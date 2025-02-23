// Copyright 2020 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package servers

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	durationpb "github.com/golang/protobuf/ptypes/duration"
	timestamppb "github.com/golang/protobuf/ptypes/timestamp"
	"github.com/opentracing/opentracing-go"
	"golang.org/x/sync/singleflight"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/drkey"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/prom"
	"github.com/scionproto/scion/go/lib/revcache"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/snet"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/pkg/daemon/colibri"
	daemon_drkey "github.com/scionproto/scion/go/pkg/daemon/drkey"
	"github.com/scionproto/scion/go/pkg/daemon/fetcher"
	sdpb "github.com/scionproto/scion/go/pkg/proto/daemon"
	dkpb "github.com/scionproto/scion/go/pkg/proto/drkey"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/scionproto/scion/go/proto"
)

type Topology interface {
	InterfaceIDs() []uint16
	UnderlayNextHop(uint16) *net.UDPAddr
	ControlServiceAddresses() []*net.UDPAddr
}

// DaemonServer handles gRPC requests to the SCION daemon.
type DaemonServer struct {
	IA          addr.IA
	MTU         uint16
	Topology    Topology
	Fetcher     fetcher.Fetcher
	RevCache    revcache.RevCache
	ASInspector trust.Inspector
	DRKeyClient daemon_drkey.ClientEngine
	ColFetcher  colibri.Fetcher
	ColClient   *colibri.DaemonClient

	Metrics Metrics

	foregroundPathDedupe singleflight.Group
	backgroundPathDedupe singleflight.Group
}

// Paths serves the paths request.
func (s *DaemonServer) Paths(ctx context.Context,
	req *sdpb.PathsRequest) (*sdpb.PathsResponse, error) {

	start := time.Now()
	dstI := addr.IA(req.DestinationIsdAs).ISD()
	response, err := s.paths(ctx, req)
	s.Metrics.PathsRequests.inc(
		pathReqLabels{Result: errToMetricResult(err), Dst: dstI},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) paths(ctx context.Context,
	req *sdpb.PathsRequest) (*sdpb.PathsResponse, error) {

	if _, ok := ctx.Deadline(); !ok {
		var cancelF context.CancelFunc
		ctx, cancelF = context.WithTimeout(ctx, 10*time.Second)
		defer cancelF()
	}
	srcIA, dstIA := addr.IA(req.SourceIsdAs), addr.IA(req.DestinationIsdAs)
	go func() {
		defer log.HandlePanic()
		s.backgroundPaths(ctx, srcIA, dstIA, req.Refresh)
	}()
	paths, err := s.fetchPaths(ctx, &s.foregroundPathDedupe, srcIA, dstIA, req.Refresh)
	if err != nil {
		log.FromCtx(ctx).Debug("Fetching paths", "err", err,
			"src", srcIA, "dst", dstIA, "refresh", req.Refresh)
		return nil, err
	}
	reply := &sdpb.PathsResponse{}
	for _, p := range paths {
		reply.Paths = append(reply.Paths, pathToPB(p))
	}
	return reply, nil
}

func (s *DaemonServer) fetchPaths(
	ctx context.Context,
	group *singleflight.Group,
	src, dst addr.IA,
	refresh bool,
) ([]snet.Path, error) {

	r, err, _ := group.Do(fmt.Sprintf("%s%s%t", src, dst, refresh),
		func() (interface{}, error) {
			return s.Fetcher.GetPaths(ctx, src, dst, refresh)
		},
	)
	// just cast to the correct type, ignore the "ok", since that can only be
	// false in case of a nil result.
	paths, _ := r.([]snet.Path)
	return paths, err
}

func pathToPB(path snet.Path) *sdpb.Path {
	meta := path.Metadata()
	interfaces := make([]*sdpb.PathInterface, len(meta.Interfaces))
	for i, intf := range meta.Interfaces {
		interfaces[i] = &sdpb.PathInterface{
			Id:    uint64(intf.ID),
			IsdAs: uint64(intf.IA),
		}
	}

	latency := make([]*durationpb.Duration, len(meta.Latency))
	for i, v := range meta.Latency {
		seconds := int64(v / time.Second)
		nanos := int32(v - time.Duration(seconds)*time.Second)
		latency[i] = &durationpb.Duration{Seconds: seconds, Nanos: nanos}
	}
	geo := make([]*sdpb.GeoCoordinates, len(meta.Geo))
	for i, v := range meta.Geo {
		geo[i] = &sdpb.GeoCoordinates{
			Latitude:  v.Latitude,
			Longitude: v.Longitude,
			Address:   v.Address,
		}
	}
	linkType := make([]sdpb.LinkType, len(meta.LinkType))
	for i, v := range meta.LinkType {
		linkType[i] = linkTypeToPB(v)
	}

	var raw []byte
	scionPath, ok := path.Dataplane().(snetpath.SCION)
	if ok {
		raw = scionPath.Raw
	}
	nextHopStr := ""
	if nextHop := path.UnderlayNextHop(); nextHop != nil {
		nextHopStr = nextHop.String()
	}
	return &sdpb.Path{
		Raw: raw,
		Interface: &sdpb.Interface{
			Address: &sdpb.Underlay{Address: nextHopStr},
		},
		Interfaces:      interfaces,
		Mtu:             uint32(meta.MTU),
		Expiration:      &timestamppb.Timestamp{Seconds: meta.Expiry.Unix()},
		Latency:         latency,
		Bandwidth:       meta.Bandwidth,
		CarbonIntensity: meta.CarbonIntensity,
		Geo:             geo,
		LinkType:        linkType,
		InternalHops:    meta.InternalHops,
		Notes:           meta.Notes,
	}

}

func linkTypeToPB(lt snet.LinkType) sdpb.LinkType {
	switch lt {
	case snet.LinkTypeDirect:
		return sdpb.LinkType_LINK_TYPE_DIRECT
	case snet.LinkTypeMultihop:
		return sdpb.LinkType_LINK_TYPE_MULTI_HOP
	case snet.LinkTypeOpennet:
		return sdpb.LinkType_LINK_TYPE_OPEN_NET
	default:
		return sdpb.LinkType_LINK_TYPE_UNSPECIFIED
	}
}

func (s *DaemonServer) backgroundPaths(origCtx context.Context, src, dst addr.IA, refresh bool) {
	backgroundTimeout := 5 * time.Second
	deadline, ok := origCtx.Deadline()
	if !ok || time.Until(deadline) > backgroundTimeout {
		// the original context is large enough no need to spin a background fetch.
		return
	}
	ctx, cancelF := context.WithTimeout(context.Background(), backgroundTimeout)
	defer cancelF()
	var spanOpts []opentracing.StartSpanOption
	if span := opentracing.SpanFromContext(origCtx); span != nil {
		spanOpts = append(spanOpts, opentracing.FollowsFrom(span.Context()))
	}
	span, ctx := opentracing.StartSpanFromContext(ctx, "fetch.paths.background", spanOpts...)
	defer span.Finish()
	if _, err := s.fetchPaths(ctx, &s.backgroundPathDedupe, src, dst, refresh); err != nil {
		log.FromCtx(ctx).Debug("Error fetching paths (background)", "err", err,
			"src", src, "dst", dst, "refresh", refresh)
	}
}

// AS serves the AS request.
func (s *DaemonServer) AS(ctx context.Context, req *sdpb.ASRequest) (*sdpb.ASResponse, error) {
	start := time.Now()
	response, err := s.as(ctx, req)
	s.Metrics.ASRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) as(ctx context.Context, req *sdpb.ASRequest) (*sdpb.ASResponse, error) {
	reqIA := addr.IA(req.IsdAs)
	if reqIA.IsZero() {
		reqIA = s.IA
	}
	mtu := uint32(0)
	if reqIA.Equal(s.IA) {
		mtu = uint32(s.MTU)
	}
	core, err := s.ASInspector.HasAttributes(ctx, reqIA, trust.Core)
	if err != nil {
		log.FromCtx(ctx).Error("Inspecting ISD-AS", "err", err, "isd_as", reqIA)
		return nil, serrors.WrapStr("inspecting ISD-AS", err, "isd_as", reqIA)
	}
	reply := &sdpb.ASResponse{
		IsdAs: uint64(reqIA),
		Core:  core,
		Mtu:   mtu,
	}
	return reply, nil
}

// Interfaces serves the interfaces request.
func (s *DaemonServer) Interfaces(ctx context.Context,
	req *sdpb.InterfacesRequest) (*sdpb.InterfacesResponse, error) {

	start := time.Now()
	response, err := s.interfaces(ctx, req)
	s.Metrics.InterfacesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) interfaces(ctx context.Context,
	_ *sdpb.InterfacesRequest) (*sdpb.InterfacesResponse, error) {

	reply := &sdpb.InterfacesResponse{
		Interfaces: make(map[uint64]*sdpb.Interface),
	}
	topo := s.Topology
	for _, ifID := range topo.InterfaceIDs() {
		nextHop := topo.UnderlayNextHop(ifID)
		if nextHop == nil {
			continue
		}
		reply.Interfaces[uint64(ifID)] = &sdpb.Interface{
			Address: &sdpb.Underlay{
				Address: nextHop.String(),
			},
		}
	}
	return reply, nil
}

// Services serves the services request.
func (s *DaemonServer) Services(ctx context.Context,
	req *sdpb.ServicesRequest) (*sdpb.ServicesResponse, error) {

	start := time.Now()
	respsonse, err := s.services(ctx, req)
	s.Metrics.ServicesRequests.inc(
		reqLabels{Result: errToMetricResult(err)},
		time.Since(start).Seconds(),
	)
	return respsonse, unwrapMetricsError(err)
}

func (s *DaemonServer) services(ctx context.Context,
	_ *sdpb.ServicesRequest) (*sdpb.ServicesResponse, error) {

	reply := &sdpb.ServicesResponse{
		Services: make(map[string]*sdpb.ListService),
	}
	list := &sdpb.ListService{}
	for _, h := range s.Topology.ControlServiceAddresses() {
		// TODO(lukedirtwalker): build actual URI after it's defined (anapapaya/scion#3587)
		list.Services = append(list.Services, &sdpb.Service{Uri: h.String()})
	}
	reply.Services[topology.Control.String()] = list
	return reply, nil
}

// NotifyInterfaceDown notifies the server about an interface that is down.
func (s *DaemonServer) NotifyInterfaceDown(ctx context.Context,
	req *sdpb.NotifyInterfaceDownRequest) (*sdpb.NotifyInterfaceDownResponse, error) {

	start := time.Now()
	response, err := s.notifyInterfaceDown(ctx, req)
	s.Metrics.InterfaceDownNotifications.inc(
		ifDownLabels{Result: errToMetricResult(err), Src: "notification"},
		time.Since(start).Seconds(),
	)
	return response, unwrapMetricsError(err)
}

func (s *DaemonServer) notifyInterfaceDown(ctx context.Context,
	req *sdpb.NotifyInterfaceDownRequest) (*sdpb.NotifyInterfaceDownResponse, error) {

	revInfo := &path_mgmt.RevInfo{
		RawIsdas:     addr.IA(req.IsdAs),
		IfID:         common.IFIDType(req.Id),
		LinkType:     proto.LinkType_core,
		RawTTL:       10,
		RawTimestamp: util.TimeToSecs(time.Now()),
	}
	_, err := s.RevCache.Insert(ctx, revInfo)
	if err != nil {
		log.FromCtx(ctx).Error("Inserting revocation", "err", err, "req", req)
		return nil, metricsError{
			err:    serrors.WrapStr("inserting revocation", err),
			result: prom.ErrDB,
		}
	}
	return &sdpb.NotifyInterfaceDownResponse{}, nil
}

func (s *DaemonServer) ASHost(ctx context.Context,
	req *dkpb.ASHostRequest) (*dkpb.ASHostResponse, error) {

	meta, err := drkey.RequestToASHostMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing protobuf ASHostReq", err)
	}

	lvl2Key, err := s.DRKeyClient.GetASHostKey(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting AS-Host from client store", err)
	}

	resp, err := drkey.KeyToASHostResp(lvl2Key)
	if err != nil {
		return nil, serrors.WrapStr("parsing to protobuf AS-Host", err)
	}
	return resp, nil
}

func (s *DaemonServer) HostAS(ctx context.Context,
	req *dkpb.HostASRequest) (*dkpb.HostASResponse, error) {

	meta, err := drkey.RequestToHostASMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing protobuf HostASReq", err)
	}

	lvl2Key, err := s.DRKeyClient.GetHostASKey(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting Host-AS from client store", err)
	}

	resp, err := drkey.KeyToHostASResp(lvl2Key)
	if err != nil {
		return nil, serrors.WrapStr("parsing to protobuf Host-AS", err)
	}
	return resp, nil
}

func (s *DaemonServer) HostHost(ctx context.Context,
	req *dkpb.HostHostRequest) (*dkpb.HostHostResponse, error) {

	meta, err := drkey.RequestToHostHostMeta(req)
	if err != nil {
		return nil, serrors.WrapStr("parsing protobuf HostHostReq", err)
	}

	lvl2Key, err := s.DRKeyClient.GetHostHostKey(ctx, meta)
	if err != nil {
		return nil, serrors.WrapStr("getting Host-AS from client store", err)
	}

	resp, err := drkey.KeyToHostHostResp(lvl2Key)
	if err != nil {
		return nil, serrors.WrapStr("parsing to protobuf Host-Host", err)
	}
	return resp, nil
}

func (s *DaemonServer) ColibriListRsvs(ctx context.Context, req *sdpb.ColibriListRsvsRequest) (
	*sdpb.ColibriListRsvsResponse, error) {

	dstIA := addr.IA(req.Base.DstIa)
	log.FromCtx(ctx).Debug("fetching reservation list", "dst", dstIA.String())
	return s.ColFetcher.ListReservations(ctx, req)
}

func (s *DaemonServer) ColibriSetupRsv(ctx context.Context, req *sdpb.ColibriSetupRsvRequest) (
	*sdpb.ColibriSetupRsvResponse, error) {

	res, err := s.ColClient.SetupReservation(ctx, req)
	if err != nil {
		return res, err
	}
	if res.Base.Success != nil {
		egress, err := strconv.Atoi(res.Base.Success.NextHop)
		if err != nil {
			return nil, serrors.WrapStr("obtaining next hop from egress", err,
				"egress", res.Base.Success.NextHop)
		}

		addr := s.Topology.UnderlayNextHop(uint16(egress))
		if addr == nil {
			return nil, serrors.New("obtaining next hop from egress id, egress not present",
				"egress", egress)
		}
		res.Base.Success.NextHop = addr.String()
	}
	return res, nil
}

func (s *DaemonServer) ColibriCleanupRsv(ctx context.Context, req *sdpb.ColibriCleanupRsvRequest) (
	*sdpb.ColibriCleanupRsvResponse, error) {

	return s.ColClient.CleanupReservation(ctx, req)
}

func (s *DaemonServer) ColibriAddAdmissionEntry(ctx context.Context,
	req *sdpb.ColibriAddAdmissionEntryRequest) (*sdpb.ColibriAddAdmissionEntryResponse, error) {

	return s.ColClient.ColibriAddAdmissionEntry(ctx, req)
}
