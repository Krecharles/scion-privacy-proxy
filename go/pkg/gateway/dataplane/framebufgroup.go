package dataplane

import (
	"container/list"
	"fmt"
)

type frameBufGroup struct {
	// The first 56 bits of SeqNr
	groupSeqNr uint64
	// The number of paths needed for decryption. Also called T
	numPaths uint8
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
	if pathIndex >= 255 {
		// Error: path index out of bound
		fmt.Println("----[WARNING]: framebufgroup.NewFrameBufGroup: path index out of bound")
		return nil
	}
	fbg := &frameBufGroup{
		groupSeqNr: groupSeqNr,
		numPaths:   numPaths,
		frames:     list.New(),
		combined:   &frameBuf{raw: make([]byte, len(fb.raw))},
		isCombined: false,
	}
	fbg.Insert(fb)
	fbg.combined.Reset()
	return fbg
}

func (fbg *frameBufGroup) Release() {
	for e := fbg.frames.Front(); e != nil; e = e.Next() {
		e.Value.(*frameBuf).Release()
	}
}

func (fbg *frameBufGroup) Insert(fb *frameBuf) {
	fmt.Println("----[Debug]: Inserted frame with seq", fb.seqNr)
	fbg.frames.PushBack(fb)
}

// Tries to combine the frames. If this group has numPaths many frames, the combined frame is stored
// in fbg.combined and this function returns true. Otherwise, it returns false and no data is
// changed.
func (fbg *frameBufGroup) TryAndCombine() bool {

	fmt.Println("Trying to reassemble")

	if fbg.isCombined {
		return true
	}
	if uint8(fbg.frames.Len()) < fbg.numPaths {
		fmt.Println("Not enough shares", "frameCnt", fbg.frames.Len(), "numPaths", fbg.numPaths, "seq", fbg.groupSeqNr)
		return false
	}

	firstFrame := fbg.frames.Front().Value.(*frameBuf)

	// Decode shares
	shares := make([][]byte, fbg.numPaths)
	for i, e := 0, fbg.frames.Front(); e != nil; i, e = i+1, e.Next() {
		fb := e.Value.(*frameBuf)
		shares[i] = fb.raw[hdrLen:fb.frameLen]
	}
	fmt.Println("Attempting combination using ", len(shares))
	output, err := Combine(shares)
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

	fmt.Println("framebufgroup.TryAndCombine() was successful. ", "frameLen", fbg.combined.frameLen, "index", fbg.combined.index, "seqNr", fbg.combined.seqNr)
	fmt.Println("combined packet: ", fbg.combined.raw)
	fbg.isCombined = true
	return true
}
