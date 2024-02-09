package dataplane

import (
	"container/list"
	"fmt"

	"github.com/scionproto/scion/go/lib/ringbuf"
)

type shareBufGroup struct {
	// The first 56 bits of SeqNr
	groupSeqNr uint64
	// The number of paths needed for decryption. Also called T
	numPaths uint8
	// The frames with the same groupSeqNr
	frames *list.List
	// Is the group combined
	isCombined bool
}

func GetPathIndex(fb *shareBuf) uint8 {
	return uint8(fb.seqNr & 0xff)
}

func NewShareBufGroup(fb *shareBuf, numPaths uint8) *shareBufGroup {
	groupSeqNr := fb.seqNr >> 8
	pathIndex := GetPathIndex(fb)
	if pathIndex >= 255 {
		// Error: path index out of bound
		fmt.Println("----[WARNING]: framebufgroup.NewShareBufGroup: path index out of bound")
		return nil
	}
	fbg := &shareBufGroup{
		groupSeqNr: groupSeqNr,
		numPaths:   numPaths,
		frames:     list.New(),
		isCombined: false,
	}
	fbg.Insert(fb)
	return fbg
}

func (fbg *shareBufGroup) Release() {
	for e := fbg.frames.Front(); e != nil; e = e.Next() {
		e.Value.(*shareBuf).Release()
	}
}

func (fbg *shareBufGroup) Insert(fb *shareBuf) {
	// fmt.Println("----[Debug]: Inserted frame with seq", fb.seqNr)
	fbg.frames.PushBack(fb)
}

// Tries to combine the frames. If this group has numPaths many frames, the combined frame is stored
// in fbg.combined and this function returns true. Otherwise, it returns false and no data is
// changed.
func (fbg *shareBufGroup) TryAndCombine() *frameBuf {

	if uint8(fbg.frames.Len()) < fbg.numPaths {
		// fmt.Println("----[Debug]: Not enough share for combination. ", "frameCnt", fbg.frames.Len(), "numPaths", fbg.numPaths, "seq", fbg.groupSeqNr)
		return nil
	}

	firstFrame := fbg.frames.Front().Value.(*shareBuf)

	// Decode shares
	shares := make([][]byte, fbg.numPaths)
	for i, e := 0, fbg.frames.Front(); e != nil && i < int(fbg.numPaths); i, e = i+1, e.Next() {
		fb := e.Value.(*shareBuf)
		shares[i] = fb.raw[hdrLen:fb.frameLen]
	}
	output, err := Combine(shares)
	if err != nil {
		for i := 0; i < len(shares); i++ {
			fmt.Println("Share", i+1, "length:", len(shares[i]), "seq", fbg.groupSeqNr)
		}
		fmt.Println("----[Error]: Error combining shares:", err)
		return nil
	}

	readEntries := make(ringbuf.EntryList, 1)
	n := newFrameBufs(readEntries)

	if n != 1 {
		fmt.Println("----[Error]: ring.Read should return 0")
		return nil
	}

	combinedFrame := readEntries[0].(*frameBuf)
	copy(combinedFrame.raw[:hdrLen], firstFrame.raw[:hdrLen])
	copy(combinedFrame.raw[hdrLen:], []byte(output))

	combinedFrame.seqNr = firstFrame.seqNr >> 8
	combinedFrame.frameLen = len(output) + hdrLen
	combinedFrame.fragNProcessed = combinedFrame.index == 0
	combinedFrame.completePktsProcessed = combinedFrame.index == 0xffff

	fbg.isCombined = true
	fbg.Release()

	return combinedFrame
}
