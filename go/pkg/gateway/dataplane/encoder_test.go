// Copyright 2020 Anapaya Systems
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

package dataplane

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testAESKey = "12345678901234567890123456789012"

func RandomPayload(length int) []byte {
	payload := make([]byte, length)
	rand.Read(payload)
	return payload
}

func reassembleFramesSimple(frames [][]byte) []byte {
	// remove the 16byte header from each frame
	framePayloads := make([][]byte, len(frames))
	for i, frame := range frames {
		framePayloads[i] = frame[16:]
	}
	out, err := Combine(framePayloads)
	if err != nil {
		fmt.Println("----[Warning]: Failed to combine frames", "err", err)
		return nil
	}
	return out
}

func TestEncoder(t *testing.T) {
	fmt.Println("[Running Test]: encoder_test.go->TestEncoder")

	// t.Run("closed ringbuf", func(t *testing.T) {
	// 	e := newEncoder(1, 2)
	// 	e.Close()
	// 	f := e.ReadEncryptedSIGFrame(1500)
	// 	assert.Nil(t, f)
	// })

	t.Run("simple IPv4 packet", func(t *testing.T) {
		e := newEncoder(1, 2, testAESKey)
		ipv4Packet := []byte{
			// IPv4 header.
			0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			// Payload.
			1, 2, 3,
		}
		e.Write(ipv4Packet)
		e.Close()
		frame := e.ReadEncryptedSIGFrame(1500)

		assert.EqualValues(t, []byte{
			// SIG frame header.
			0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
		}, frame[:hdrLen])

		decrypted, err := Decrypt(frame[hdrLen:], testAESKey)
		assert.NoError(t, err)

		assert.EqualValues(t, decrypted, ipv4Packet)

		frame = e.ReadEncryptedSIGFrame(1500)
		assert.Nil(t, frame)
	})

	// t.Run("simple IPv6 packet", func(t *testing.T) {
	// 	e := newEncoder(1, 2, 1500)
	// 	e.Write([]byte{
	// 		// IPv6 header.
	// 		0x60, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// Payload.
	// 		1, 2, 3,
	// 	})
	// 	e.Close()
	// 	f := e.Read()
	// 	assert.EqualValues(t, []byte{
	// 		// SIG frame header.
	// 		0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// IPv6 header.
	// 		0x60, 0, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// Payload.
	// 		1, 2, 3,
	// 	}, f)
	// 	f = e.Read()
	// 	assert.Nil(t, f)
	// })

	// t.Run("two packets in a single frame", func(t *testing.T) {
	// 	e := newEncoder(1, 2, 1500)
	// 	e.Write([]byte{
	// 		// IPv4 header.
	// 		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// Payload.
	// 		4, 5, 6,
	// 	})
	// 	e.Write([]byte{
	// 		// IPv4 header.
	// 		0x40, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// Payload.
	// 		7, 8,
	// 	})
	// 	e.Close()
	// 	f := e.Read()
	// 	assert.EqualValues(t, []byte{
	// 		// SIG frame header.
	// 		0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// IPv4 header.
	// 		0x40, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// Payload.
	// 		4, 5, 6,
	// 		// IPv4 header.
	// 		0x40, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// Payload.
	// 		7, 8,
	// 	}, f)
	// 	f = e.Read()
	// 	assert.Nil(t, f)
	// })

	// t.Run("single packet split into two frames", func(t *testing.T) {
	// 	e := newEncoder(1, 2, 56)
	// 	e.Write([]byte{
	// 		// IPv4 header.
	// 		0x40, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// Payload.
	// 		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
	// 	})
	// 	e.Close()
	// 	f := e.Read()
	// 	assert.EqualValues(t, []byte{
	// 		// SIG frame header.
	// 		0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// IPv4 header.
	// 		0x40, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	// 		// Payload.
	// 		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
	// 	}, f)
	// 	f = e.Read()
	// 	assert.EqualValues(t, []byte{
	// 		// SIG frame header.
	// 		0, 1, 255, 255, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1,
	// 		// Trailing part of the payload.
	// 		21, 22,
	// 	}, f)
	// 	f = e.Read()
	// 	assert.Nil(t, f)
	// })

	//	t.Run("second packet starting at non-zero position in the second frame", func(t *testing.T) {
	//		e := newEncoder(1, 2, 58)
	//		e.Write([]byte{
	//			// IPv4 header.
	//			0x40, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	//			// Payload.
	//			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
	//		})
	//		e.Write([]byte{
	//			// IPv4 header.
	//			0x40, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	//			// Payload.
	//			25, 26,
	//		})
	//		e.Close()
	//		f := e.Read()
	//		assert.EqualValues(t, []byte{
	//			// SIG frame header.
	//			0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0,
	//			// IPv4 header.
	//			0x40, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	//			// Payload.
	//			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
	//		}, f)
	//		f = e.Read()
	//		assert.EqualValues(t, []byte{
	//			// SIG frame header.
	//			0, 1, 0, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1,
	//			// Trailing part of the payload.
	//			23, 24,
	//			// IPv4 header.
	//			0x40, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	//			// Payload.
	//			25, 26,
	//		}, f)
	//		f = e.Read()
	//		assert.Nil(t, f)
	//	})
}
