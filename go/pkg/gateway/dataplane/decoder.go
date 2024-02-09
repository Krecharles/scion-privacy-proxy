package dataplane

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/ringbuf"
)

const (
	// shareBufCap is the size of a preallocated frame buffer.
	shareBufCap = 65535
	// freeFramesCap is the number of preallocated Framebuf objects.
	freeSharesCap = 1024
)

var (
	// Cache of the frame buffers free to be used.
	freeShares *ringbuf.Ring
)

func newShareBufs(encryptedframes ringbuf.EntryList) int {
	if freeShares == nil {
		initFreeShares()
	}
	n, _ := freeShares.Read(encryptedframes, true)
	return n
}

func initFreeShares() {
	freeShares = ringbuf.New(freeSharesCap, func() interface{} {
		return newShareBuf()
	}, "ingress_freeEncrypted")
}

// shareBuf is a struct used to reassemble shares into a SIG frame. shareBufs
// are managed by the decoder. Once enough shares
type shareBuf struct {
	// Session Id of the frame.
	sessId uint8
	// Sequence number of the frame.
	seqNr uint64
	// Total length of the frame (including 16-byte header).
	frameLen int
	// The raw bytes buffer for the frame.
	raw []byte
	// The sender object for the frame.
	snd ingressSender
}

func newShareBuf() *shareBuf {
	buf := &shareBuf{raw: make([]byte, shareBufCap)}
	buf.Reset()
	return buf
}

func (fb *shareBuf) Reset() {
	fb.sessId = 0
	fb.seqNr = 0
	fb.frameLen = 0
	fb.snd = nil
}

func (fb *shareBuf) Release() {
	fb.Reset()
	if freeShares == nil {
		initFreeShares()
	}
	freeShares.Write(ringbuf.EntryList{fb}, true)
}

type decoder struct {
	requiredSharesForDecode int
	fbgs                    map[uint64]*shareBufGroup
	aesKey                  string
}

func newDecoder(requiredSharesForDecode int, aesKey string) *decoder {
	return &decoder{
		requiredSharesForDecode: requiredSharesForDecode,
		fbgs:                    make(map[uint64]*shareBufGroup),
		aesKey:                  aesKey,
	}
}

func (d *decoder) Insert(frame *shareBuf) *frameBuf {
	groupSeqNr := uint64(frame.seqNr >> 8)

	// check if groupSeqNr contained in d.fbgs
	fbg, ok := d.fbgs[groupSeqNr]

	// check if groupSeqNr already combined
	if ok && fbg.isCombined {
		frame.Release()
		// fmt.Println("----[Debug]: Frame too late, fbg already combined. groupSeqNr=", groupSeqNr)
		return nil
	}

	if !ok {
		// There is no fbg for the groupSeqNr, so create one
		fbg = NewShareBufGroup(frame, uint8(d.requiredSharesForDecode))
		d.fbgs[groupSeqNr] = fbg
	} else {
		fbg.Insert(frame)
	}

	combinedFrame := fbg.TryAndCombine()
	if combinedFrame == nil {
		// Combination was unsuccessful.
		return nil
	}

	// fmt.Println("----[Debug]: Combined frame. frame seq=", combinedFrame.seqNr, "groupSeqNr=", groupSeqNr)

	temp := combinedFrame.raw[hdrLen:combinedFrame.frameLen]
	decryptedFrame, err := Decrypt(temp, d.aesKey)
	if err != nil {
		fmt.Println("----[ERROR]: Failed to decrypt frame. err=", err)
		return nil
	}
	n := copy(combinedFrame.raw[hdrLen:], decryptedFrame)
	combinedFrame.frameLen = hdrLen + n
	return combinedFrame
}
