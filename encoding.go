// Copyright 2009 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
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

// writeBytes writes a sequence of bytes to the writer.
func writeBytes(b []byte, w io.Writer) error {
	if err := writeUint32(uint32(len(b)), w); err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	return nil
}

// readBytes reads a sequence of bytes from the reader.
func readBytes(r io.Reader) ([]byte, error) {
	l, err := readUint32(r)
	if err != nil {
		return make([]byte, 0), err
	}
	b := make([]byte, l)
	if _, err := r.Read(b); err != nil {
		return make([]byte, 0), err
	}
	return b, nil
}

const adler32mod = 65521

func getAdler32Sums(block []byte) (s1 uint32, s2 uint32) {
	s1 = 1
	for _, b := range block {
		s1 = (s1 + uint32(b)) % adler32mod
		s2 = (s2 + s1) % adler32mod
	}
	return s1, s2
}

func getAdler32(block []byte) uint32 {
	s1, s2 := getAdler32Sums(block)
	return s2<<16 | s1
}

func getNextAdler32(s1, s2, sz uint32, removed, added byte) uint32 {
	s1 = (s1 + uint32(added) - uint32(removed)) % adler32mod
	s2 = (s2 + s1 - (uint32(removed) * sz) - 1) % adler32mod
	return s2<<16 | s1
}

func getMD4Checksum(block []byte) []byte {
	h := md4.New()
	h.Write(block)
	return h.Sum(nil)
}
