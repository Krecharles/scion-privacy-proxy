package dataplane

import (
	"container/list"
	"fmt"

	"github.com/SSSaaS/sssa-golang"
)

type frameBufGroup struct {
	// The first 56 bits of SeqNr
	groupSeqNr uint64
	// The size of the group
	numPaths uint8
	// The number of frames we get
	frameCnt uint8
	// The frames with the same groupSeqNr
	frames *list.List
	// The combined frame
	combined *frameBuf
	// Is the group combined
	isCombined bool
}

func GetPathIndex(fb *frameBuf) uint8 {
	return uint8(fb.seqNr & 0xff)
}

func NewFrameBufGroup(fb *frameBuf, numPaths uint8) *frameBufGroup {
	groupSeqNr := fb.seqNr >> 8
	pathIndex := GetPathIndex(fb)
	if pathIndex >= numPaths {
		// Error: path index out of bound
		return nil
	}
	fbg := &frameBufGroup{
		groupSeqNr: groupSeqNr,
		numPaths:   numPaths,
		frameCnt:   1,
		frames:     list.New(),
		combined:   &frameBuf{raw: make([]byte, len(fb.raw))},
		isCombined: false,
	}
	fbg.frames.PushBack(fb)
	fbg.combined.Reset()
	return fbg
}

func (fbg *frameBufGroup) Release() {
	for e := fbg.frames.Front(); e != nil; e = e.Next() {
		e.Value.(*frameBuf).Release()
	}
}

// Tries to combine the frames. If possible, the combined frame is stoed in fbg.combined and this
// function returns true. Otherwise, it returns false and no data is changed.
func (fbg *frameBufGroup) TryAndCombine() bool {

	if fbg.isCombined {
		return true
	}
	if fbg.frameCnt < fbg.numPaths {
		return false
	}

	firstFrame := fbg.frames.Front().Value.(*frameBuf)

	// Decode shares
	shares := make([]string, fbg.numPaths)
	for e := fbg.frames.Front(); e != nil; e = e.Next() {
		fb := e.Value.(*frameBuf)
		shares[GetPathIndex(fb)] = string(fb.raw[hdrLen:fb.frameLen])
	}
	output, err := sssa.Combine(shares)
	if err != nil {
		fmt.Println("Error combining shares:", err)
		return false
	}

	// build frame
	fbg.combined.index = firstFrame.index
	fbg.combined.seqNr = firstFrame.seqNr
	fbg.combined.snd = firstFrame.snd
	copy(fbg.combined.raw[:hdrLen], firstFrame.raw[:hdrLen])
	copy(fbg.combined.raw[hdrLen:], []byte(output))
	fbg.combined.frameLen = len(output) + hdrLen
	fbg.combined.raw = fbg.combined.raw[:fbg.combined.frameLen]

	fbg.isCombined = true
	return true
}
