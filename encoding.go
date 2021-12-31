// Copyright 2009 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"hash/adler32"
	"io"

	"golang.org/x/crypto/md4"
)

const (
	varintHasFurtherMask = 0x80
	varintMask           = 0x7F
)

// writeUint32 encodes an unsigned 32-bit integer using the minimal number
// of bytes possible and writes the bytes to the writer.
//
// This approach is based on protocol buffer's varints.
// https://developers.google.com/protocol-buffers/docs/encoding#varints
func writeUint32(v uint32, w io.Writer) error {
	out := make([]byte, 1)
	for {
		r := v >> 7
		if r > 0 {
			out[0] = byte(v&varintMask) | varintHasFurtherMask
		} else {
			out[0] = byte(v)
		}
		if _, err := w.Write(out); err != nil {
			return err
		}
		v = r
		if v == 0 {
			break
		}
	}
	return nil
}

// readUint32 decodes an unsigned 32-bit integer from the given reader
// that was encoded using Base 128 varints.
//
// This approach is based on protocol buffer's varints.
// https://developers.google.com/protocol-buffers/docs/encoding#varints
func readUint32(r io.Reader) (uint32, error) {
	out := uint32(0)
	p := make([]byte, 1)
	i := 0
	for {
		if _, err := r.Read(p); err != nil {
			return 0, err
		}
		out = uint32(p[0]&varintMask)<<i | out
		i += 7
		if p[0]&varintHasFurtherMask == 0 {
			return out, nil
		}
	}
}

func getAdler32(block []byte) uint32 {
	h := adler32.New()
	h.Write(block)
	return h.Sum32()
}

func getMD4Checksum(block []byte) []byte {
	h := md4.New()
	h.Write(block)
	return h.Sum(nil)
}
