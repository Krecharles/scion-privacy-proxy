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

package dataplane

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/slayers"
	"github.com/scionproto/scion/go/lib/snet"
	snetpath "github.com/scionproto/scion/go/lib/snet/path"
)

const (
	// minMTU is the minmal MTU that makes sense for the gateway. The SIG header
	// must fit it as well as at least one IPv6 header plus 1 byte of content.
	minMTU    = hdrLen + 41
	udpHdrLen = 8
)

// sender handles sending traffic via one particular path.
type sender struct {
	// ring is the ring buffer containing encrypted shares to be sent
	ring               *pktRing
	conn               net.PacketConn
	address            net.Addr
	pathStatsPublisher PathStatsPublisher
	path               snet.Path
	pathFingerprint    snet.PathFingerprint
	metrics            SessionMetrics
}

func newSender(sessID uint8, conn net.PacketConn, path snet.Path,
	gatewayAddr net.UDPAddr, pathStatsPublisher PathStatsPublisher,
	metrics SessionMetrics) (*sender, error) {

	// MTU must account for the size of the SCION header.
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	addrLen := addr.IABytes*2 + len(localAddr.IP) + len(gatewayAddr.IP)
	scionPath, ok := path.Dataplane().(snetpath.SCION)
	if !ok {
		return nil, serrors.New("not a scion path", "type", common.TypeOf(path.Dataplane()))
	}
	pathLen := len(scionPath.Raw)
	mtu := int(path.Metadata().MTU) - slayers.CmnHdrLen - addrLen - pathLen - udpHdrLen
	if mtu < minMTU {
		return nil, serrors.New("insufficient MTU", "mtu", mtu, "minMTU", minMTU)
	}

	c := &sender{
		ring: newPktRing(),
		conn: conn,
		address: &snet.UDPAddr{
			IA:      path.Destination(),
			Path:    path.Dataplane(),
			NextHop: path.UnderlayNextHop(),
			Host:    &gatewayAddr,
		},
		pathStatsPublisher: pathStatsPublisher,
		path:               path,
		pathFingerprint:    snet.Fingerprint(path),
		metrics:            metrics,
	}
	go func() {
		defer log.HandlePanic()
		c.run()
	}()
	return c, nil
}

// Close closes the sender. The function returns immediately, but any buffered
// data will still be sent out.
func (c *sender) Close() {
	c.ring.Close()
}

// Write sends the packet to the remote gateway in asynchronous manner.
func (c *sender) Write(pkt []byte) {
	increaseCounterMetric(c.metrics.IPPktsSent, 1)
	increaseCounterMetric(c.metrics.IPPktBytesSent, float64(len(pkt)))

	c.ring.Write(pkt, false)
}

func (c *sender) run() {
	for {
		// Because there is only complete SIG frames written to the ring,
		// we can read the frames in blocking mode.
		frame, n := c.ring.Read(true)
		if n == -1 {
			// Sender was closed and all the buffered frames were sent.
			break
		}
		_, err := c.conn.WriteTo(frame, c.address)
		if err != nil {
			increaseCounterMetric(c.metrics.SendExternalErrors, 1)
			continue
		}
		increaseCounterMetric(c.metrics.FramesSent, 1)
		increaseCounterMetric(c.metrics.FrameBytesSent, float64(len(frame)))

		if c.pathStatsPublisher != nil {
			c.pathStatsPublisher.PublishEgressStats(c.pathFingerprint.String(),
				1, int64(len(frame)))
		}
	}
}
