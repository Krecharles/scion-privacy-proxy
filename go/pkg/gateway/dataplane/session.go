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
	"fmt"
	"hash/crc64"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/google/gopacket"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/snet"
)

var (
	crcTable = crc64.MakeTable(crc64.ECMA)
)

type PathStatsPublisher interface {
	PublishEgressStats(fingerprint string, frames int64, bytes int64)
}

// SessionMetrics report traffic and error counters for a session. They must be instantiated with
// the labels "remote_isd_as" and "policy_id".
type SessionMetrics struct {
	// IPPktsSent is the IP packets count sent.
	IPPktsSent metrics.Counter
	// IPPktBytesSent is the IP packet bytes sent.
	IPPktBytesSent metrics.Counter
	// FramesSent is the frames count sent.
	FramesSent metrics.Counter
	// FrameBytesSent is the frame bytes sent.
	FrameBytesSent metrics.Counter
	// SendExternalError is the error count when sending frames to the external network.
	SendExternalErrors metrics.Counter
}

type Session struct {
	SessionID          uint8
	GatewayAddr        net.UDPAddr
	DataPlaneConn      net.PacketConn
	PathStatsPublisher PathStatsPublisher
	Metrics            SessionMetrics

	mutex sync.Mutex
	// pathsCondition is true if there are enough paths to send securely
	pathsCond *sync.Cond
	// senders is a list of currently used senders.
	senders []*sender
	// multipath encoder
	encoder          *encoder
	redundancyFactor int
}

func NewSession(sessionId uint8, gatewayAddr net.UDPAddr,
	dataPlaneConn net.PacketConn, pathStatsPublisher PathStatsPublisher,
	metrics SessionMetrics, redundancyFactor int) *Session {
	sess := &Session{
		SessionID:          sessionId,
		GatewayAddr:        gatewayAddr,
		DataPlaneConn:      dataPlaneConn,
		PathStatsPublisher: pathStatsPublisher,
		Metrics:            metrics,
		encoder:            newEncoder(sessionId, NewStreamID(), 600),
		redundancyFactor:   redundancyFactor,
	}
	sess.pathsCond = sync.NewCond(&sess.mutex)
	go func() {
		defer log.HandlePanic()
		sess.run()
	}()
	return sess
}

// Close signals that the session should close up its internal Connections. Close returns as
// soon as forwarding goroutines are signaled to shut down (never blocks).
func (s *Session) Close() {

	fmt.Println("----[DEBUG]: Session.Close()")

	// senders will be closed in run() once encoder.Read() returns nil.
	for _, snd := range s.senders {
		snd.Close()
	}
	s.encoder.Close()
}

// Write encodes the packet and sends it to the network.
// The packet may be silently dropped.
func (s *Session) Write(packet gopacket.Packet) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	fmt.Println("----[DEBUG]: Session.Write()")
	s.encoder.Write(packet.Data())
}

func (s *Session) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	res := fmt.Sprintf("ID: %d", s.SessionID)
	for _, snd := range s.senders {
		res += fmt.Sprintf("\n    %v", snd.path)
	}
	return res
}

// SetPaths sets the paths for subsequent packets encapsulated by the session.
// Packets that were written up to this point will still be sent via the old
// path. There are two reasons for that:
//
// 1. New path may have smaller MTU causing the already buffered frame not to
// fit in.
//
// 2. Paths can have different latencies, meaning that switching to new path
// could cause packets to be delivered out of order. Using new sender with new stream
// ID causes creation of new reassemby queue on the remote side, thus avoiding the
// reordering issues.
func (s *Session) SetPaths(paths []snet.Path) error {
	// -fmt.Println("SetPaths ------")
	s.mutex.Lock()
	// -fmt.Println("SetPaths ------ 1")
	// -fmt.Println("SetPaths ------ optained locks")
	defer s.mutex.Unlock()

	created := make([]*sender, 0, len(paths))
	reused := make(map[*sender]bool, len(s.senders))
	for _, existingSender := range s.senders {
		reused[existingSender] = false
	}

	for _, path := range paths {
		// Find out whether we already have a sender for this path.
		// Keep using old senders whenever possible.
		if existingSender, ok := findSenderWithPath(s.senders, path); ok {
			reused[existingSender] = true
			continue
		}

		newSender, err := newSender(
			s.SessionID,
			s.DataPlaneConn,
			path,
			s.GatewayAddr,
			s.PathStatsPublisher,
			s.Metrics,
		)
		if err != nil {
			// Collect newly created senders to avoid go routine leak.
			for _, createdSender := range created {
				createdSender.Close()
			}
			return err
		}
		// -fmt.Println("Created new Sender")
		created = append(created, newSender)
	}

	newSenders := created
	for existingSender, reuse := range reused {
		if !reuse {
			existingSender.Close()
			continue
		}
		newSenders = append(newSenders, existingSender)
	}

	// Sort the paths to get a minimal amount of consistency,
	// at least in the case when new paths are the same as old paths.
	sort.Slice(newSenders, func(x, y int) bool {
		return strings.Compare(string(newSenders[x].pathFingerprint),
			string(newSenders[y].pathFingerprint)) == -1
	})
	s.senders = newSenders
	s.pathsCond.Broadcast()
	return nil
}

func (s *Session) run() {
	for {

		// There is a race condition issue.
		// If the paths changes after encoder.Read() returns and before the mutex is locked,
		// the value of currentMtuSum will be different to len(frame)
		// // -fmt.Println("session.run, locking")

		// ensure paths don't change while sending packets
		// s.mutex.Lock()

		N := len(s.senders)
		T := N - s.redundancyFactor
		fmt.Println("session.run(), N=", N, "T=", T)
		for T < 2 {
			// only read packets when at least 2 paths are needed to decrypt the message
			// -fmt.Println("session.run(), Waiting for more paths (T < 2)")

			// TODO check regularly if encoder has closed. If there are not enough paths,
			// but the encoder closes, it cannot signal the close operation to the session
			// is it does this by returning nil on Read().]

			// s.pathsCond.Wait()
			// N = len(s.senders)
			// T = N - s.redundancyFactor
			panic("not enough paths")
		}
		// -fmt.Println("session.run(), Got enough paths (T >= 2)")

		fmt.Println("session.run(), Calling encoder.Read()")
		shares := s.encoder.Read(N, T)
		fmt.Println("session.run(), encoder.Read() returned")

		if shares == nil {

			// Sender was closed and all the buffered frames were sent.
			fmt.Println("----[Debug]: Session.run() ---- BREAK")
			break
		}

		for pathID, sender := range s.senders {
			// copy frame and change sequence according to the pathID

			fmt.Println("Send packet to sender")
			sender.Write(shares[pathID])

		}

		// s.mutex.Unlock()

	}
	// -fmt.Println("Session.run() Thread closed down.")
}

func findSenderWithPath(senders []*sender, path snet.Path) (*sender, bool) {
	for _, s := range senders {
		if pathsEqual(path, s.path) {
			return s, true
		}
	}
	return nil, false
}

func pathsEqual(x, y snet.Path) bool {
	if x == nil && y == nil {
		return true
	}
	if x == nil || y == nil {
		return false
	}
	return snet.Fingerprint(x) == snet.Fingerprint(y) &&
		x.Metadata() != nil && y.Metadata() != nil &&
		x.Metadata().MTU == y.Metadata().MTU &&
		x.Metadata().Expiry.Equal(y.Metadata().Expiry)
}
