// Copyright 2017 ETH Zurich
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
	"bytes"
	"context"
	"fmt"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/metrics"
)

// reassemblyList is used to keep a doubly linked list of SIG frames that are
// outstanding for reassembly. The frames kept in the reassambly list sorted by
// their sequence numbers. There is always one reassembly list per epoch to
// ensure that sequence numbers are monotonically increasing.
type reassemblyList struct {
	epoch             int
	capacity          int
	numPaths          uint8
	snd               ingressSender
	markedForDeletion bool
	// a map of framebuffers with keys being their sequence numbers except for the last 8 bits
	fbgs map[uint64]*frameBufGroup
	// the sequence number of the next frame to be released, is used to check if a frame is too old
	currentGroupSeqNr uint64 // TODO don't forget
	// the current packet being built.
	buf       *bytes.Buffer
	tooOld    metrics.Counter
	duplicate metrics.Counter
	evicted   metrics.Counter
	invalid   metrics.Counter
}

// newReassemblyList returns a ReassemblyList object for the given epoch and with
// given maximum capacity.
func newReassemblyList(epoch int, capacity int, s ingressSender, numPahts uint8,
	framesDiscarded metrics.Counter) *reassemblyList {

	list := &reassemblyList{
		epoch:             epoch,
		capacity:          capacity,
		numPaths:          numPahts,
		snd:               s,
		markedForDeletion: false,
		fbgs:              make(map[uint64]*frameBufGroup),
		buf:               bytes.NewBuffer(make([]byte, 0, frameBufCap)),
		currentGroupSeqNr: 0,
	}
	if framesDiscarded != nil {
		list.tooOld = framesDiscarded.With("reason", "too_old")
		list.duplicate = framesDiscarded.With("reason", "duplicate")
		list.evicted = framesDiscarded.With("reason", "evicted")
		list.invalid = framesDiscarded.With("reason", "invalid")
	}
	return list
}

// Insert inserts a frame into the reassembly list.
// After inserting the frame at the correct position, Insert tries to reassemble packets
// that involve the newly added frame. Completely processed frames get removed from the
// list and released to the pool of frame buffers.
func (l *reassemblyList) Insert(ctx context.Context, frame *frameBuf) {

	// TODO remove this comment
	// If this is the first frame, write all complete packets to the wire and
	// add the frame to the reassembly list if it contains a fragment at the end.

	fmt.Println("Rlist.Insert ----------- 1")
	groupSeqNr := uint64(frame.seqNr >> 8)

	if groupSeqNr < l.currentGroupSeqNr {
		increaseCounterMetric(l.tooOld, 1)
		frame.Release()
		return
	}
	fbg, ok := l.fbgs[groupSeqNr]

	if !ok {
		// There is no fbg for the groupSeqNr, so create one
		fbg = NewFrameBufGroup(frame, l.numPaths)
		fmt.Println("Created a new FBG for ", groupSeqNr, frame.seqNr)
		l.fbgs[groupSeqNr] = fbg
	}

	// TODO insert checks for missing packets, duplicates and for too young packets
	// TODO check if we have capacity.

	if ok {
		fbg.Insert(frame)
	}

	l.tryReassemble(ctx)
}

// tryReassemble checks if a packet can be reassembled from the reassembly list.
func (l *reassemblyList) tryReassemble(ctx context.Context) {
	logger := log.FromCtx(ctx)

	fmt.Println("----tryReassmble() ---- 1", l.currentGroupSeqNr)

	startFbg, ok := l.fbgs[l.currentGroupSeqNr]

	if !ok {
		fmt.Println("----[ERROR]: gruopSeqNr not found in fbgs map", l.currentGroupSeqNr, "keys in map:", len(l.fbgs))
	}

	if !startFbg.TryAndCombine() {
		return
	}

	fmt.Println("----tryReassmble() ---- 2")

	startFrame := startFbg.combined
	startFrame.ProcessCompletePkts(ctx)

	fmt.Println("startFrame", startFbg.combined)

	if startFrame.frag0Start == 0 {

		startFrame.ProcessCompletePkts(ctx)

		// Should never happen.
		// logger.Error("First frame in reassembly list does not contain a packet start.",
		// 	"frame", startFrame.String())
		// fmt.Println("----[ERROR]: First frame in reassembly list does not contain a packet start.")
		// fmt.Println(startFrame, startFrame.Processed())
		// // Safest to remove all frames in the list.
		// increaseCounterMetric(l.evicted, float64(len(l.fbgs)))
		// l.removeAll()
		// return
	}

	fmt.Println("----tryReassmble() ---- 3")
	bytes := startFrame.frameLen - startFrame.frag0Start
	canReassemble := false
	framingError := false
	for seq := l.currentGroupSeqNr; true; seq++ {
		// check if seq in fbgs
		if _, ok := l.fbgs[seq]; !ok {
			break
		}
		fmt.Println("----tryReassmble() ---- 3.1")
		if !l.fbgs[seq].TryAndCombine() {
			// the next framebufgroup is not ready to be combined yet
			break
		}
		currFrame := l.fbgs[seq].combined
		// Add number of bytes contained in this frame. This potentially adds
		// too much, but we are only using it to detect whether we potentially
		// have everything we need.
		bytes += (currFrame.frameLen - sigHdrSize)
		// Check if we have found all frames.
		if bytes >= startFrame.pktLen {
			canReassemble = true
			break
		}
		fmt.Println("----tryReassmble() ---- 3.2")
		if currFrame.index != 0xffff {
			logger.Error("Framing error occurred. Not enough bytes to reassemble packet",
				"startFrame", startFrame.String(), "currFrame", currFrame.String(),
				"pktLen", startFrame.pktLen)
			framingError = true
			break
		}

	}
	fmt.Println("----tryReassmble() ---- 4")
	if canReassemble {
		l.collectAndWrite(ctx)
	} else if framingError {
		increaseCounterMetric(l.invalid, 1)
		// TODO fix line below
		// l.removeBefore(l.entries.Back())
	}
}

// collectAndWrite reassembles the packet in the reassembly list and writes it
// out to the buffer. It will also write every complete packet in the last frame.
func (l *reassemblyList) collectAndWrite(ctx context.Context) {
	fmt.Println("rlist.collectAndWrite()", l.currentGroupSeqNr)
	logger := log.FromCtx(ctx)
	startFbg := l.fbgs[l.currentGroupSeqNr]
	startFrame := startFbg.combined
	// Reset reassembly buffer.
	l.buf.Reset()
	// Collect the start of the packet.
	pktLen := startFrame.pktLen
	l.buf.Write(startFrame.raw[startFrame.frag0Start:startFrame.frameLen])
	// We cannot process the startframe any further.
	startFrame.SetProcessed()
	// Collect rest.
	var frame *frameBuf
	for seq := l.currentGroupSeqNr; true; seq++ {
		frame = l.fbgs[seq].combined
		missingBytes := pktLen - l.buf.Len()
		l.buf.Write(
			// Write all bytes excluding the SIG header. This reconstructs the IP header
			frame.raw[sigHdrSize:intMin(missingBytes+sigHdrSize, frame.frameLen)],
		)
		fmt.Println("CollectAndWrite() ------- 2")
		l.currentGroupSeqNr = seq + 1
		frame.fragNProcessed = true
		l.fbgs[seq].Release()
	}

	// Check length of the reassembled packet.
	if l.buf.Len() != pktLen {
		logger.Error("Packet len for reassembled packet does not match header",
			"expected", pktLen, "have", l.buf.Len())
	} else {
		// Write the packet to the wire.
		fmt.Println("----[Debug]:  Writing packet to wire via rlist")
		if err := l.snd.send(l.buf.Bytes()); err != nil {
			logger.Error("Unable to send reassembled packet", "err", err)
		}
	}
	// Process the complete packets in the last frame
	frame.ProcessCompletePkts(ctx)
	// Remove all processed frames from the list.
	l.removeProcessed()
}

// remove every fbg that has a groupSeqNr smaller than the lastSentGroupSeqNr
func (l *reassemblyList) removeProcessed() {

	fmt.Println("rlist.removeProcessed()")

	for groupSeqNr, fbg := range l.fbgs {

		if fbg.combined.Processed() {
			if l.currentGroupSeqNr < groupSeqNr {
				l.currentGroupSeqNr = groupSeqNr
				fmt.Println("updated currentGroupSeqNr to ", l.currentGroupSeqNr)
			}
			fbg.Release()
			delete(l.fbgs, groupSeqNr)
		}

	}

}

// Deletes all entries in fbgs
func (l *reassemblyList) removeAll() {
	for groupSeqNr, fbg := range l.fbgs {
		delete(l.fbgs, groupSeqNr)
		fbg.Release()
	}
	l.fbgs = make(map[uint64]*frameBufGroup)
}

func intMin(x, y int) int {
	if x <= y {
		return x
	}
	return y
}
