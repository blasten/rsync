// Copyright 2021 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"io"

	"golang.org/x/crypto/md4"
)

type (
	wireType    = uint32
	fieldNumber = uint32
)

const (
	varintHasFurtherMask = 1 << 7
	varintMask           = varintHasFurtherMask - 1
	fieldTypeMask        = (1 << 3) - 1
	adler32mod           = 65521 // The largest prime number that is less than 2^16.
)

const (
	typeVarint wireType = iota
	typeLengthDelimeted
)

// getValueMeta provides the field number and field type of the
// varint next in the byte buffer.
// An error occurs if the varint cannot be read.
// This metadata is based on the protocol buffer encoding.
// https://developers.google.com/protocol-buffers/docs/encoding#structure
func getValueMeta(r io.Reader) (fieldNumber, wireType, error) {
	v, err := readVarint(r)
	if err != nil {
		return 0, 0, err
	}
	fieldNum := v >> 3
	fieldType := v & fieldTypeMask
	return fieldNum, fieldType, nil
}

// wrapVarint wraps a varint in an envelope that contains metadata such
// as a fieldNum and writes it to the provided writer.
// The metadata can then be read by using getValueMeta.
func wrapVarint(v uint32, fieldNum fieldNumber, w io.Writer) error {
	writeVarint(fieldNum<<3|typeVarint, w)
	return writeVarint(v, w)
}

// writeUint32 encodes an unsigned 32-bit integer using the minimal number
// of bytes possible and writes the bytes to the writer.
//
// This approach is based on protocol buffer's varints.
// https://developers.google.com/protocol-buffers/docs/encoding#varints
func writeVarint(v uint32, w io.Writer) error {
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

// readVarint decodes an unsigned 32-bit integer from the given reader
// that was encoded using Base 128 varints.
//
// This approach is based on protocol buffer's varints.
// https://developers.google.com/protocol-buffers/docs/encoding#varints
func readVarint(r io.Reader) (uint32, error) {
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

// wrapVarint wraps a data stream in an envelope that contains metadata such
// as a fieldNum and writes it to the provided writer.
// The metadata can then be read by using getValueMeta.
func wrapBytes(b []byte, fieldNumber uint32, w io.Writer) error {
	writeVarint(fieldNumber<<3|typeLengthDelimeted, w)
	return writeBytes(b, w)
}

// writeBytes writes a data stream to the writer.
func writeBytes(b []byte, w io.Writer) error {
	if err := writeVarint(uint32(len(b)), w); err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	return nil
}

// readBytes reads a data stream from the reader.
func readBytes(r io.Reader) ([]byte, error) {
	l, err := readVarint(r)
	if err != nil {
		return make([]byte, 0), err
	}
	b := make([]byte, l)
	if _, err := r.Read(b); err != nil {
		return make([]byte, 0), err
	}
	return b, nil
}

// getAdler32Sums returns the sums (s1, s2) that form the adler-32 checksum
// for a given data stream.
// The final checksum is computed as follows: s2 << 16 | s1.
// In this case, the individual sums are necessary to compute the next sums
// very cheaply as described in the original rsync paper.
// https://www.andrew.cmu.edu/course/15-749/READINGS/required/cas/tridgell96.pdf
func getAdler32Sums(block []byte) (uint32, uint32) {
	s1 := uint32(1)
	s2 := uint32(0)
	for _, b := range block {
		s1 = (s1 + uint32(b)) % adler32mod
		s2 = (s2 + s1) % adler32mod
	}
	return s1, s2
}

// getNextAdler32 gets the next adler-32 sums given the sums of
// returned from getAdler32Sums for a given data stream, where a
// delta of one byte removed, and one added is applied to the data stream.
//
// This is explained in the original rsync paper under "rolling checksum".
// https://www.andrew.cmu.edu/course/15-749/READINGS/required/cas/tridgell96.pdf
func getNextAdler32(s1, s2, sz uint32, removed, added byte) (uint32, uint32) {
	s1 = (s1 + uint32(added) - uint32(removed)) % adler32mod
	s2 = (s2 + s1 - (uint32(removed) * sz) - 1) % adler32mod
	return s1, s2
}

// getMD4Checksum gets the MD4 hash for the given data stream.
func getMD4Checksum(block []byte) []byte {
	h := md4.New()
	h.Write(block)
	return h.Sum(nil)
}
