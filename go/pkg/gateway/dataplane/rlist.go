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
	"container/list"
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
	entries           *list.List
	buf               *bytes.Buffer
	tooOld            metrics.Counter
	duplicate         metrics.Counter
	evicted           metrics.Counter
	invalid           metrics.Counter
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
		entries:           list.New(),
		buf:               bytes.NewBuffer(make([]byte, 0, frameBufCap)),
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
	logger := log.FromCtx(ctx)
	// If this is the first frame, write all complete packets to the wire and
	// add the frame to the reassembly list if it contains a fragment at the end.
	if l.entries.Len() == 0 {
		l.insertNewGroup(frame)
		return
	}
	groupSeqNr := frame.seqNr >> 8
	first := l.entries.Front()
	firstFrameGroup := first.Value.(*frameBufGroup)
	// Check whether frame is too old.
	if groupSeqNr < firstFrameGroup.groupSeqNr {
		increaseCounterMetric(l.tooOld, 1)
		frame.Release()
		return
	}
	last := l.entries.Back()
	lastFrameGroup := last.Value.(*frameBufGroup)

	// If there is a gap between this frame and the last in the reassembly list,
	// remove all packets from the reassembly list and only add this frame.
	if groupSeqNr > lastFrameGroup.groupSeqNr+1 {
		logger.Debug(fmt.Sprintf("Detected dropped frameGroup(s). Discarding %d frames.",
			l.entries.Len()), "epoch", l.epoch, "groupSegNr", groupSeqNr,
			"currentNewest", lastFrameGroup.groupSeqNr)
		increaseCounterMetric(l.evicted, float64(l.entries.Len()))
		l.removeAll()
		l.insertNewGroup(frame)
		return
	}
	// Check if we have capacity.
	if l.entries.Len() == l.capacity {
		logger.Info("Reassembly list reached maximum capacity", "epoch", l.epoch, "cap", l.capacity)
		increaseCounterMetric(l.evicted, float64(l.entries.Len()))
		l.removeBefore(last)
		first = last
		firstFrameGroup = first.Value.(*frameBufGroup)
	}

	// Check if the frame belongs to old group.
	if groupSeqNr >= firstFrameGroup.groupSeqNr && groupSeqNr <= lastFrameGroup.groupSeqNr {
		// Find the frame with the same groupSeqNr
		curr := first
		for curr.Value.(*frameBufGroup).groupSeqNr < groupSeqNr {
			curr = curr.Next()
		}
		currFrameGroup := curr.Value.(*frameBufGroup)
		if currFrameGroup.groupSeqNr != groupSeqNr {
			// Should never happen.
			logger.Error("Cannot find frame group", "groupSeqNr", groupSeqNr)
			// Safest to remove all frames in the list.
			l.removeBefore(last)
			frame.Release()
			return
		}
		frameIndex := GetPathIndex(frame)
		if frameIndex >= currFrameGroup.numPaths {

			logger.Error(fmt.Sprintf("Cannot assign path index %d for %d paths.", frameIndex, currFrameGroup.numPaths))
			return
		}
		frameInserted := false
		for e := currFrameGroup.frames.Front(); e != nil; e = e.Next() {
			currFrame := e.Value.(*frameBuf)
			currFrameIndex := GetPathIndex(currFrame)
			if currFrameIndex == frameIndex {
				logger.Debug("Received duplicate frame.", "epoch", l.epoch, "seqNr", frame.seqNr)
				increaseCounterMetric(l.duplicate, 1)
				return
			}
			if currFrameIndex > frameIndex {
				frameInserted = true
				currFrameGroup.frames.InsertBefore(frame, e)
				break
			}
		}
		if !frameInserted {
			currFrameGroup.frames.PushBack(frame)
		}
		currFrameGroup.frameCnt++
	}

	// Check if the frame belongs to next group
	if groupSeqNr == lastFrameGroup.groupSeqNr+1 {
		l.insertNewGroup(frame)
	}
	l.tryReassemble(ctx)
	// l.printInfo()
}

func (l *reassemblyList) insertNewGroup(frame *frameBuf) {
	fbg := NewFrameBufGroup(frame, l.numPaths)
	if fbg != nil {
		l.entries.PushBack(fbg)
	}
}

// tryReassemble checks if a packet can be reassembled from the reassembly list.
func (l *reassemblyList) tryReassemble(ctx context.Context) {
	logger := log.FromCtx(ctx)
	start := l.entries.Front()
	startFrameGroup := start.Value.(*frameBufGroup)
	if !startFrameGroup.TryAndCombine() {
		return
	}
	startFrame := startFrameGroup.combined
	startFrame.ProcessCompletePkts(ctx)
	if startFrame.frag0Start == 0 {
		// The first frame does not contain a packet start.
		// Remove the first frame
		l.removeEntry(start)
		return
	}
	bytes := startFrame.frameLen - startFrame.frag0Start
	canReassemble := false
	framingError := false
	for e := start.Next(); e != nil; e = e.Next() {
		currFrameGroup := e.Value.(*frameBufGroup)
		if !currFrameGroup.TryAndCombine() {
			return
		}
		currFrame := currFrameGroup.combined
		// Add number of bytes contained in this frame. This potentially adds
		// too much, but we are only using it to detect whether we potentially
		// have everything we need.
		bytes += (currFrame.frameLen - sigHdrSize)
		// Check if we have found all frames.
		if bytes >= startFrame.pktLen {
			canReassemble = true
			break
		}
		if currFrame.index != 0xffff {
			logger.Error("Framing error occurred. Not enough bytes to reassemble packet",
				"startFrame", startFrame.String(), "currFrame", currFrame.String(),
				"pktLen", startFrame.pktLen)
			framingError = true
			break
		}
	}
	if canReassemble {
		l.collectAndWrite(ctx)
	} else if framingError {
		increaseCounterMetric(l.invalid, 1)
		l.removeBefore(l.entries.Back())
	}
}

// collectAndWrite reassembles the packet in the reassembly list and writes it
// out to the buffer. It will also write every complete packet in the last frame.
func (l *reassemblyList) collectAndWrite(ctx context.Context) {
	logger := log.FromCtx(ctx)
	start := l.entries.Front()
	startFrame := start.Value.(*frameBufGroup).combined
	// Reset reassembly buffer.
	l.buf.Reset()
	// Collect the start of the packet.
	pktLen := startFrame.pktLen
	l.buf.Write(startFrame.raw[startFrame.frag0Start:startFrame.frameLen])
	// We cannot process the startframe any further.
	startFrame.SetProcessed()
	// Collect rest.
	var frame *frameBuf
	for e := start.Next(); l.buf.Len() < pktLen && e != nil; e = e.Next() {
		frame = e.Value.(*frameBufGroup).combined
		missingBytes := pktLen - l.buf.Len()
		l.buf.Write(
			// Write all bytes excluding the SIG header. This reconstructs the IP header
			frame.raw[sigHdrSize:intMin(missingBytes+sigHdrSize, frame.frameLen)],
		)
		frame.fragNProcessed = true
	}
	// Check length of the reassembled packet.
	if l.buf.Len() != pktLen {
		logger.Error("Packet len for reassembled packet does not match header",
			"expected", pktLen, "have", l.buf.Len())
	} else {
		// Write the packet to the wire.
		if err := l.snd.send(l.buf.Bytes()); err != nil {
			logger.Error("Unable to send reassembled packet", "err", err)
		}
	}
	// Process the complete packets in the last frame
	frame.ProcessCompletePkts(ctx)
	// Remove all processed frames from the list.
	l.removeProcessed()
}

func (l *reassemblyList) removeEntry(e *list.Element) {
	frameGroup := e.Value.(*frameBufGroup)
	frameGroup.Release()
	l.entries.Remove(e)
}

func (l *reassemblyList) removeProcessed() {
	var next *list.Element
	for e := l.entries.Front(); e != nil; e = next {
		frame := e.Value.(*frameBufGroup)
		next = e.Next()
		if frame.combined.Processed() {
			l.removeEntry(e)
		}
	}
}

func (l *reassemblyList) removeAll() {
	l.removeBefore(nil)
}

func (l *reassemblyList) removeBefore(ele *list.Element) {
	var next *list.Element
	for e := l.entries.Front(); e != ele; e = next {
		next = e.Next()
		l.removeEntry(e)
	}
}

func (l *reassemblyList) printInfo() {
	if l.entries.Len() == 0 {
		return
	}
	first := l.entries.Front()
	firstFrameGroup := first.Value.(*frameBufGroup)
	last := l.entries.Back()
	lastFrameGroup := last.Value.(*frameBufGroup)
	fmt.Println("first seq:", firstFrameGroup.groupSeqNr, "last seq:", lastFrameGroup.groupSeqNr)
}

func intMin(x, y int) int {
	if x <= y {
		return x
	}
	return y
}
