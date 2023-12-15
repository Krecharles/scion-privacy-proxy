package dataplane

import (
	"fmt"
)

type decoder struct {
	requiredSharesForDecode int
	fbgs                    map[uint64]*frameBufGroup
	aesKey                  string
}

func newDecoder(requiredSharesForDecode int, aesKey string) *decoder {
	return &decoder{
		requiredSharesForDecode: requiredSharesForDecode,
		fbgs:                    make(map[uint64]*frameBufGroup),
		aesKey:                  aesKey,
	}
}

func (d *decoder) Insert(frame *frameBuf) *frameBuf {
	groupSeqNr := uint64(frame.seqNr >> 8)
	// fmt.Println("----[Debug]: Inserting new frame seq=", frame.seqNr, "groupSeqNr=", groupSeqNr, "len=", frame.frameLen)
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
		fbg = NewFrameBufGroup(frame, uint8(d.requiredSharesForDecode))
		d.fbgs[groupSeqNr] = fbg
	} else {
		fbg.Insert(frame)
	}

	if fbg.TryAndCombine() {
		// Combination was successful, we can delete the group and return the combined frame
		// delete(d.fbgs, groupSeqNr)
		// fmt.Println("----[Debug]: Combined frame. frame seq=", fbg.combined.seqNr, "groupSeqNr=", groupSeqNr)
		temp := fbg.combined.raw[hdrLen:fbg.combined.frameLen]
		decryptedFrame, err := Decrypt(temp, d.aesKey)
		if err != nil {
			fmt.Println("----[ERROR]: Failed to decrypt frame. err=", err)
		}
		n := copy(fbg.combined.raw[hdrLen:], decryptedFrame)
		fbg.combined.frameLen = hdrLen + n
		return fbg.combined
	}
	return nil
}
