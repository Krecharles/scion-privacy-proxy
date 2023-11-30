package dataplane

type decoder struct {
	requiredSharesForDecode int
	fbgs                    map[uint64]*frameBufGroup
}

func newDecoder(requiredSharesForDecode int) *decoder {
	return &decoder{
		requiredSharesForDecode: requiredSharesForDecode,
		fbgs:                    make(map[uint64]*frameBufGroup),
	}
}

func (d *decoder) Insert(frame *frameBuf) *frameBuf {
	groupSeqNr := uint64(frame.seqNr >> 8)
	// fmt.Println("----[Debug]: Inserting new frame seq=", frame.seqNr, "groupSeqNr=", groupSeqNr)
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
		return fbg.combined
	}
	return nil
}
