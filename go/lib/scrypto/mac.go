// Copyright 2016 ETH Zurich
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

package scrypto

import (
	"crypto/aes"
	"crypto/sha256"
	"hash"

	"github.com/dchest/cmac"
	"golang.org/x/crypto/pbkdf2"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

const (
	ErrCipherFailure common.ErrMsg = "Unable to initialize AES cipher"
	ErrMacFailure    common.ErrMsg = "Unable to initialize Mac"
)

var (
	hfMacSalt   = []byte("Derive OF Key")
	colibriSalt = []byte("Derive Colibri Key")
)

func InitMac(key []byte) (hash.Hash, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serrors.Wrap(ErrCipherFailure, err)
	}
	mac, err := cmac.New(block)
	if err != nil {
		return nil, serrors.Wrap(ErrMacFailure, err)
	}
	return mac, nil
}

func HFMacFactory(key []byte) (func() hash.Hash, error) {
	hfGenKey := DeriveHFMacKey(key)

	// First check for MAC creation errors.
	if _, err := InitMac(hfGenKey); err != nil {
		return nil, err
	}
	f := func() hash.Hash {
		mac, _ := InitMac(hfGenKey)
		return mac
	}
	return f, nil
}

// DeriveHFMacKey generates the hop field mac key.
// This uses 16B keys with 1000 hash iterations, which is the same as the
// defaults used by pycrypto.
func DeriveHFMacKey(key []byte) []byte {
	return pbkdf2.Key(key, hfMacSalt, 1000, 16, sha256.New)
}

// DeriveColibriMacKey derives the private Colibri key from the given key.
func DeriveColibriMacKey(key []byte) []byte {
	// This uses 16B keys with 1000 hash iterations, which is the same as the
	// defaults used by pycrypto.
	return pbkdf2.Key(key, colibriSalt, 1000, 16, sha256.New)
}
