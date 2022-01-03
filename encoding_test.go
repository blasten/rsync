// Copyright 2009 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"bytes"
	"math"
	"testing"
)

func TestWriteVarint(t *testing.T) {
	b := bytes.NewBuffer([]byte{})
	if err := writeVarint(10, b); err != nil {
		t.Error(err)
	}
	got := b.Bytes()
	wanted := []byte{10}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	b.Reset()
	if err := writeVarint(300, b); err != nil {
		t.Error(err)
	}
	got = b.Bytes()
	wanted = []byte{172, 2}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	b.Reset()
	if err := writeVarint(math.MaxUint32, b); err != nil {
		t.Error(err)
	}
	got = b.Bytes()
	wanted = []byte{255, 255, 255, 255, 15}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	b.Reset()
	if err := writeVarint(0, b); err != nil {
		t.Error(err)
	}
	got = b.Bytes()
	wanted = []byte{0}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestWrapVarint(t *testing.T) {
	b := bytes.NewBuffer([]byte{})
	if err := wrapVarint(10, 1, b); err != nil {
		t.Error(err)
	}
	got := b.Bytes()
	wanted := []byte{8, 10}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestGetValueVarint(t *testing.T) {
	wantedFieldNum := uint32(17)
	b := bytes.NewBuffer([]byte{})
	if err := wrapVarint(10, wantedFieldNum, b); err != nil {
		t.Error(err)
	}

	fieldNum, fieldType, err := getValueMeta(b)
	if err != nil {
		t.Error(err)
	}

	if got, wanted := fieldNum, wantedFieldNum; got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if got, wanted := fieldType, uint32(typeVarint); got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestGetValueBytes(t *testing.T) {
	wantedFieldNum := uint32(17)
	b := bytes.NewBuffer([]byte{})
	if err := wrapBytes([]byte{}, wantedFieldNum, b); err != nil {
		t.Error(err)
	}

	fieldNum, fieldType, err := getValueMeta(b)
	if err != nil {
		t.Error(err)
	}

	if got, wanted := fieldNum, wantedFieldNum; got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if got, wanted := fieldType, uint32(typeLengthDelimeted); got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestReadVarintUint32(t *testing.T) {
	got, _ := readVarint(bytes.NewBuffer([]byte{10}))
	wanted := uint32(10)
	if got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
	got, _ = readVarint(bytes.NewBuffer([]byte{172, 2}))
	wanted = uint32(300)
	if got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
	got, _ = readVarint(bytes.NewBuffer([]byte{172, 2, 10}))
	wanted = uint32(300)
	if got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
	got, _ = readVarint(bytes.NewBuffer([]byte{255, 255, 255, 255, 15}))
	wanted = uint32(math.MaxUint32)
	if got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
	got, _ = readVarint(bytes.NewBuffer([]byte{0}))
	wanted = uint32(0)
	if got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestWriteBytes(t *testing.T) {
	b := bytes.NewBuffer([]byte{})
	if err := writeBytes([]byte("hello world"), b); err != nil {
		t.Error(err)
	}
	got := b.Bytes()
	wanted := []byte{11, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestWrapBytes(t *testing.T) {
	b := bytes.NewBuffer([]byte{})
	if err := wrapBytes([]byte("hello world"), 1, b); err != nil {
		t.Error(err)
	}
	got := b.Bytes()
	wanted := []byte{9, 11, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestReadBytes(t *testing.T) {
	got, err := readBytes(bytes.NewBuffer([]byte{11, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100}))
	if err != nil {
		t.Error(err)
	}
	wanted := []byte("hello world")
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestGetAdler32Sums(t *testing.T) {
	s1, s2 := getAdler32Sums([]byte("test"))

	if got, wanted := s1, uint32(449); got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
	if got, wanted := s2, uint32(1117); got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestGetNextAdler32(t *testing.T) {
	block := []byte("test")
	s1, s2 := getAdler32Sums(block)
	removed, added := byte('t'), byte('!')
	nextS1, nextS2 := getNextAdler32(s1, s2, uint32(len(block)), removed, added)
	wantedS1, wantedS2 := getAdler32Sums([]byte("est!"))
	if nextS1 != wantedS1 {
		t.Errorf("got %v, wanted %v", nextS1, wantedS1)
	}
	if nextS2 != wantedS2 {
		t.Errorf("got %v, wanted %v", nextS1, wantedS1)
	}
}

func TestGetMD4Checksum(t *testing.T) {
	checksum := getMD4Checksum([]byte("test"))
	wanted := []byte{219, 52, 109, 105, 29, 122, 204, 77, 194, 98, 93, 177, 159, 158, 63, 82}
	if !bytes.Equal(checksum, wanted) {
		t.Errorf("got %v, wanted %v", checksum, wanted)
	}
}
