// Copyright 2009 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"bytes"
	"math"
	"testing"
)

func TestWriteVarintUint32(t *testing.T) {
	b := bytes.NewBuffer([]byte{})
	if err := writeUint32(10, b); err != nil {
		t.Error(err)
	}
	got := b.Bytes()
	wanted := []byte{10}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	b.Reset()
	if err := writeUint32(300, b); err != nil {
		t.Error(err)
	}
	got = b.Bytes()
	wanted = []byte{172, 2}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	b.Reset()
	if err := writeUint32(math.MaxUint32, b); err != nil {
		t.Error(err)
	}
	got = b.Bytes()
	wanted = []byte{255, 255, 255, 255, 15}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	b.Reset()
	if err := writeUint32(0, b); err != nil {
		t.Error(err)
	}
	got = b.Bytes()
	wanted = []byte{0}
	if !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestReadVarintUint32(t *testing.T) {
	got, _ := readUint32(bytes.NewBuffer([]byte{10}))
	wanted := uint32(10)
	if got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
	got, _ = readUint32(bytes.NewBuffer([]byte{172, 2}))
	wanted = uint32(300)
	if got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
	got, _ = readUint32(bytes.NewBuffer([]byte{172, 2, 10}))
	wanted = uint32(300)
	if got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
	got, _ = readUint32(bytes.NewBuffer([]byte{255, 255, 255, 255, 15}))
	wanted = uint32(math.MaxUint32)
	if got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
	got, _ = readUint32(bytes.NewBuffer([]byte{0}))
	wanted = uint32(0)
	if got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestGetAdler32(t *testing.T) {
	checksum := getAdler32([]byte("test"))
	wanted := uint32(73204161)
	if checksum != wanted {
		t.Errorf("got %v, wanted %v", checksum, wanted)
	}
}

func TestGetMD4Checksum(t *testing.T) {
	checksum := getMD4Checksum([]byte("test"))
	wanted := []byte{219, 52, 109, 105, 29, 122, 204, 77, 194, 98, 93, 177, 159, 158, 63, 82}
	if !bytes.Equal(checksum, wanted) {
		t.Errorf("got %v, wanted %v", checksum, wanted)
	}
}
