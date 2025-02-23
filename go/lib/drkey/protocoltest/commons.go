package protocoltest

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/drkey"
)

func GetLvl1(t *testing.T, protoID drkey.Protocol, epoch drkey.Epoch,
	srcIA, dstIA addr.IA) drkey.Lvl1Key {
	asSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7}
	sv, err := drkey.DeriveSV(protoID, epoch, asSecret)
	require.NoError(t, err)

	lvl1Meta := drkey.Lvl1Meta{
		SrcIA:   srcIA,
		DstIA:   dstIA,
		ProtoId: sv.ProtoId,
	}
	key, err := (&drkey.SpecificDeriver{}).DeriveLvl1(lvl1Meta, sv.Key)
	require.NoError(t, err)
	return drkey.Lvl1Key{
		Epoch:   sv.Epoch,
		SrcIA:   srcIA,
		DstIA:   dstIA,
		ProtoId: sv.ProtoId,
		Key:     key,
	}
}

func DeriveASHostGeneric(meta drkey.ASHostMeta, lvl1key drkey.Lvl1Key) (drkey.ASHostKey, error) {

	derivedKey, err := (&drkey.GenericDeriver{}).DeriveASHost(meta, lvl1key.Key)
	if err != nil {
		return drkey.ASHostKey{}, err
	}

	return drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   lvl1key.Epoch,
		SrcIA:   lvl1key.SrcIA,
		DstIA:   lvl1key.DstIA,
		DstHost: meta.DstHost,
		Key:     derivedKey,
	}, nil
}

func DeriveHostASGeneric(meta drkey.HostASMeta, lvl1key drkey.Lvl1Key) (drkey.HostASKey, error) {
	derivedKey, err := (&drkey.GenericDeriver{}).DeriveHostAS(meta, lvl1key.Key)
	if err != nil {
		return drkey.HostASKey{}, err
	}

	return drkey.HostASKey{
		ProtoId: meta.ProtoId,
		Epoch:   lvl1key.Epoch,
		SrcIA:   lvl1key.SrcIA,
		DstIA:   lvl1key.DstIA,
		SrcHost: meta.SrcHost,
		Key:     derivedKey,
	}, nil
}

func DeriveHostHostGeneric(meta drkey.HostHostMeta,
	lvl1key drkey.Lvl1Key) (drkey.HostHostKey, error) {

	hostASMeta := drkey.HostASMeta{
		Lvl2Meta: meta.Lvl2Meta,
		SrcHost:  meta.SrcHost,
	}
	hostASKey, err := (&drkey.GenericDeriver{}).DeriveHostAS(hostASMeta, lvl1key.Key)
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	h2hKey, err := (&drkey.GenericDeriver{}).DeriveHostToHost(meta.DstHost, hostASKey)
	if err != nil {
		return drkey.HostHostKey{}, err
	}

	return drkey.HostHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   lvl1key.Epoch,
		SrcIA:   lvl1key.SrcIA,
		DstIA:   lvl1key.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
		Key:     h2hKey,
	}, nil
}

func DeriveASHostSpecific(meta drkey.ASHostMeta, lvl1key drkey.Lvl1Key) (drkey.ASHostKey, error) {

	derivedKey, err := (&drkey.SpecificDeriver{}).DeriveASHost(meta, lvl1key.Key)
	if err != nil {
		return drkey.ASHostKey{}, err
	}

	return drkey.ASHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   lvl1key.Epoch,
		SrcIA:   lvl1key.SrcIA,
		DstIA:   lvl1key.DstIA,
		DstHost: meta.DstHost,
		Key:     derivedKey,
	}, nil
}

func DeriveHostASSpecific(meta drkey.HostASMeta, lvl1key drkey.Lvl1Key) (drkey.HostASKey, error) {

	derivedKey, err := (&drkey.SpecificDeriver{}).DeriveHostAS(meta, lvl1key.Key)
	if err != nil {
		return drkey.HostASKey{}, err
	}

	return drkey.HostASKey{
		ProtoId: meta.ProtoId,
		Epoch:   lvl1key.Epoch,
		SrcIA:   lvl1key.SrcIA,
		DstIA:   lvl1key.DstIA,
		SrcHost: meta.SrcHost,
		Key:     derivedKey,
	}, nil
}

func DeriveHostHostSpecific(meta drkey.HostHostMeta,
	lvl1key drkey.Lvl1Key) (drkey.HostHostKey, error) {

	hostASMeta := drkey.HostASMeta{
		Lvl2Meta: meta.Lvl2Meta,
		SrcHost:  meta.SrcHost,
	}

	hostASKey, err := (&drkey.SpecificDeriver{}).DeriveHostAS(hostASMeta, lvl1key.Key)
	if err != nil {
		return drkey.HostHostKey{}, err
	}
	h2hKey, err := (&drkey.SpecificDeriver{}).DeriveHostToHost(meta.DstHost, hostASKey)
	if err != nil {
		return drkey.HostHostKey{}, err
	}

	return drkey.HostHostKey{
		ProtoId: meta.ProtoId,
		Epoch:   lvl1key.Epoch,
		SrcIA:   lvl1key.SrcIA,
		DstIA:   lvl1key.DstIA,
		SrcHost: meta.SrcHost,
		DstHost: meta.DstHost,
		Key:     h2hKey,
	}, nil
}
