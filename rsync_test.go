// Copyright 2009 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"testing"
)

func CompareSlice[T comparable](a, b []T) error {
	if len(a) != len(b) {
		return fmt.Errorf("slices don't have the same size:\nA=%v\nB=%v", a, b)
	}
	s := make(map[T]struct{}, len(a))
	for _, v := range a {
		s[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := s[v]; !ok {
			return fmt.Errorf("slice A doesn't contain %v found in slice B.\nA=%v", v, a)
		}
	}
	return nil
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

func TestFileChecksums(t *testing.T) {
	checksums := getFileChecksums([]byte{219, 52, 109, 105}, 2)

	if got, wanted := len(checksums.adler32), 2; got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if got, wanted := checksums.adler32[0], uint32(32243984); got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if got, wanted := checksums.adler32[1], uint32(21299415); got != wanted {
		t.Errorf("got adler32 checksum %v, wanted %v", got, wanted)
	}

	if got, wanted := len(checksums.md4), 2; got != wanted {
		t.Errorf("got  adler32 checksum %v, wanted %v", got, wanted)
	}

	wanted := []byte{248, 29, 157, 75, 5, 102, 74, 32, 31, 166, 181, 202, 233, 47, 255, 95}
	if got := []byte(checksums.md4[0]); !bytes.Equal(got, wanted) {
		t.Errorf("got md4 checksum %v, wanted %v", got, wanted)
	}

	wanted = []byte{167, 238, 255, 206, 211, 199, 81, 166, 165, 5, 104, 35, 130, 142, 20, 119}
	if got := []byte(checksums.md4[1]); !bytes.Equal(got, wanted) {
		t.Errorf("got md4 checksum %v, wanted %v", got, wanted)
	}
}

func TestRecurseDir(t *testing.T) {
	dir, err := os.MkdirTemp(os.TempDir(), "test")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir)

	if _, err := os.Create(path.Join(dir, "file1")); err != nil {
		t.Error(err)
	}

	if _, err := os.Create(path.Join(dir, "file2")); err != nil {
		t.Error(err)
	}

	if err := os.Mkdir(path.Join(dir, "dir1"), 0700); err != nil {
		t.Error(err)
	}

	if err := os.Mkdir(path.Join(dir, "dir1", "dir2"), 0700); err != nil {
		t.Error(err)
	}

	if _, err := os.Create(path.Join(dir, "dir1", "file3")); err != nil {
		t.Error(err)
	}

	if _, err := os.Create(path.Join(dir, "dir1", "dir2", "file4")); err != nil {
		t.Error(err)
	}

	files := []string{}
	err = recurseDir(dir, func(file string, entry os.DirEntry) error {
		files = append(files, file)
		return nil
	})
	if err != nil {
		t.Error(err)
	}

	wanted := []string{
		path.Join(dir, "file1"),
		path.Join(dir, "file2"),
		path.Join(dir, "dir1", "file3"),
		path.Join(dir, "dir1", "dir2", "file4"),
	}
	if err := CompareSlice(files, wanted); err != nil {
		t.Error(err)
	}
}

func TestGetFilesChecksums(t *testing.T) {
	dir, err := os.MkdirTemp(os.TempDir(), "test")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir)

	{
		f, err := os.Create(path.Join(dir, "file1"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("content of file 1")
	}

	{
		f, err := os.Create(path.Join(dir, "file2"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("content of file 2")
	}

	fChecksums, err := getFilesChecksums([]string{
		path.Join(dir, "file1"),
		path.Join(dir, "file2"),
	}, 50)

	if err != nil {
		t.Error(err)
	}

	if got, wanted := len(fChecksums.checksums), 2; got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if got, wanted := fChecksums.checksumsCount, 2; got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if err := CompareSlice(fChecksums.checksums[0].adler32, []uint32{983238146}); err != nil {
		t.Error(err)
	}

	if err := CompareSlice(fChecksums.checksums[1].adler32, []uint32{983303683}); err != nil {
		t.Error(err)
	}

	md41 := []byte{230, 31, 121, 104, 154, 113, 88, 28, 63, 182, 52, 55, 149, 233, 146, 150}
	if !bytes.Equal(fChecksums.checksums[0].md4[0], md41) {
		t.Error(err)
	}

	md42 := []byte{42, 82, 130, 153, 200, 59, 194, 84, 26, 55, 216, 201, 124, 246, 8, 236}
	if !bytes.Equal(fChecksums.checksums[1].md4[0], md42) {
		t.Error(err)
	}
}

func TestPush(t *testing.T) {
	dir, err := os.MkdirTemp(os.TempDir(), "test")
	if err != nil {
		t.Error(err)
	}
	defer os.RemoveAll(dir)

	{
		f, err := os.Create(path.Join(dir, "file1"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("content of file 1")
	}

	buf := bytes.NewBuffer([]byte{})

	err = push(buf, dir, 10)
	if err != nil {
		t.Error(err)
	}

	actual := buf.Bytes()
	expected := []byte{
		protocolVersion,
		/*blockSize = 10*/ 10, 0, 0, 0,
		/*hashes = 2*/ 2, 0, 0, 0,
		/*adler32[0]=*/ 241, 3, 99, 22,
		/*md4[0]=*/ 19, 46, 229, 154, 113, 4, 208, 200, 104, 44, 103, 9, 182, 16, 78, 108,
		/*adler32[1]=*/ 18, 2, 168, 8,
		/*md4[1]=*/ 133, 192, 106, 241, 146, 178, 238, 48, 118, 201, 228, 92, 172, 165, 224, 133,
	}
	if !bytes.Equal(actual, expected) {
		t.Errorf("unexpected bytes. expected: %v actual: %v", expected, actual)
	}
}
