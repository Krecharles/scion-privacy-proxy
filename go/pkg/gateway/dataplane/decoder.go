package dataplane

import (
	"context"
)

type Decoder struct {
	// requiredSharesForDecode is equal to T in a (T,N) secret sharing scheme
	requiredSharesForDecode int
	// shareBufGroupMap is a map of shareBufGroups for each groupSeqNr
	shareBufGroupMap map[uint64]*shareBufGroup
	// aesKey is the AES key used to decrypt the frames after combining the shares
	// The key is currently provided in the config .toml file
	aesKey string
}

func newDecoder(requiredSharesForDecode int, aesKey string) *Decoder {
	return &Decoder{
		requiredSharesForDecode: requiredSharesForDecode,
		shareBufGroupMap:        make(map[uint64]*shareBufGroup),
		aesKey:                  aesKey,
	}
}

func (d *Decoder) Insert(ctx context.Context, share *shareBuf) *frameBuf {
	groupSeqNr := uint64(share.seqNr >> 8)

	sbg, ok := d.shareBufGroupMap[groupSeqNr]

	// Check if groupSeqNr is already combined
	if ok && sbg.isCombined {
		share.Release()
		return nil
	}

	if !ok {
		// There is no sbg for the groupSeqNr, so create one
		sbg = NewShareBufGroup(share, uint8(d.requiredSharesForDecode))
		d.shareBufGroupMap[groupSeqNr] = sbg
	} else {
		sbg.Insert(share)
	}

	combinedFrame := sbg.TryAndCombine(ctx)
	if combinedFrame == nil {
		// Combination was unsuccessful.
		return nil
	}

	// AES-Decrypt the combined frame
	decryptedFrame, err := Decrypt(combinedFrame.raw[hdrLen:combinedFrame.frameLen], d.aesKey)
	if err != nil {
		return nil
	}
	n := copy(combinedFrame.raw[hdrLen:], decryptedFrame)
	combinedFrame.frameLen = hdrLen + n
	return combinedFrame
}
