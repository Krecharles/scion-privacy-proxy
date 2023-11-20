package dataplane

type decoder struct {
	requiredSharesForDecode int
	fbgs                    map[uint64]*frameBufGroup
	nextGroupSeqNr          uint64
}

func newDecoder(requiredSharesForDecode int) *decoder {
	return &decoder{
		requiredSharesForDecode: requiredSharesForDecode,
		nextGroupSeqNr:          0,
		fbgs:                    make(map[uint64]*frameBufGroup),
	}
}

func (d *decoder) Insert(frame *frameBuf) *frameBuf {
	// fmt.Println("----[Debug]: Inserting new frame seq=", frame.seqNr)
	groupSeqNr := uint64(frame.seqNr >> 8)

	if groupSeqNr < d.nextGroupSeqNr {

		frame.Release()
		// fmt.Println("----[Debug]: Frame too late, fbg already combined. groupSeqNr=", groupSeqNr)
		return nil
	}

	fbg, ok := d.fbgs[groupSeqNr]

	if !ok {
		// There is no fbg for the groupSeqNr, so create one
		fbg = NewFrameBufGroup(frame, uint8(d.requiredSharesForDecode))
		d.fbgs[groupSeqNr] = fbg
	} else {
		fbg.Insert(frame)
	}

	if fbg.TryAndCombine() {
		// Combination was successful, we can delete the group and return the combined frame
		// TODO this is probably a memory leak
		d.nextGroupSeqNr++
		delete(d.fbgs, groupSeqNr)
		return fbg.combined
	}
	return nil

	// l.tryReassemble(ctx)
}
