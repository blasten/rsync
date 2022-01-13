// Copyright 2021 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"testing"
)

func TestGetFileHashes(t *testing.T) {
	dir := t.TempDir()

	f, err := os.Create(path.Join(dir, "file1"))
	if err != nil {
		t.Error(err)
	}
	f.Write([]byte{219, 52, 109, 105})
	f.Close()

	hashes := getFileHashes(dir, "file1", 2)

	if got, wanted := len(hashes), 2; got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if got, wanted := hashes[0].weak, uint32(32243984); got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if got, wanted := hashes[1].weak, uint32(21299415); got != wanted {
		t.Errorf("got adler32 checksum %v, wanted %v", got, wanted)
	}

	wanted := []byte{248, 29, 157, 75, 5, 102, 74, 32, 31, 166, 181, 202, 233, 47, 255, 95}
	if got := []byte(hashes[0].strong); !bytes.Equal(got, wanted) {
		t.Errorf("got md4 checksum %v, wanted %v", got, wanted)
	}

	wanted = []byte{167, 238, 255, 206, 211, 199, 81, 166, 165, 5, 104, 35, 130, 142, 20, 119}
	if got := []byte(hashes[1].strong); !bytes.Equal(got, wanted) {
		t.Errorf("got md4 checksum %v, wanted %v", got, wanted)
	}
}

func TestRecurseDir(t *testing.T) {
	dir := t.TempDir()

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
	err := recurseDir(dir, "", func(file string, entry os.DirEntry) error {
		files = append(files, file)
		return nil
	})
	if err != nil {
		t.Error(err)
	}

	wanted := []string{
		path.Join("file1"),
		path.Join("file2"),
		path.Join("dir1", "file3"),
		path.Join("dir1", "dir2", "file4"),
	}
	if err := CompareSlice(files, wanted); err != nil {
		t.Error(err)
	}
}

func TestGetFilesChecksums(t *testing.T) {
	dir := t.TempDir()

	{
		f, err := os.Create(path.Join(dir, "file1"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("content of file 1")
		f.Close()
	}

	{
		f, err := os.Create(path.Join(dir, "file2"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("content of file 2")
		f.Close()
	}

	fsBlocks, err := getBlocks(dir,
		[]string{
			path.Join("file1"),
			path.Join("file2"),
		}, 50)

	if err != nil {
		t.Error(err)
	}

	if got, wanted := len(fsBlocks.blocks), 2; got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if _, has := fsBlocks.files["file1"]; !has {
		t.Error("expected file1")
	}

	if _, has := fsBlocks.files["file2"]; !has {
		t.Error("expected file2")
	}

	if got, wanted := fsBlocks.files["file1"], [2]uint32{0, 1}; got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if got, wanted := fsBlocks.files["file2"], [2]uint32{1, 1}; got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if got, wanted := fsBlocks.blocks[0].weak, uint32(983238146); got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	if got, wanted := fsBlocks.blocks[1].weak, uint32(983303683); got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}

	md41 := []byte{230, 31, 121, 104, 154, 113, 88, 28, 63, 182, 52, 55, 149, 233, 146, 150}
	if !bytes.Equal(fsBlocks.blocks[0].strong, md41) {
		t.Error(err)
	}

	md42 := []byte{42, 82, 130, 153, 200, 59, 194, 84, 26, 55, 216, 201, 124, 246, 8, 236}
	if !bytes.Equal(fsBlocks.blocks[1].strong, md42) {
		t.Error(err)
	}
}

func TestWriteChecksumsBlockMiss(t *testing.T) {
	dir := t.TempDir()

	{
		f, err := os.Create(path.Join(dir, "file1"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("content of file 1")
		f.Close()
	}

	{
		f, err := os.Create(path.Join(dir, "file2"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("content of file 2")
		f.Close()
	}

	db := make(blockDB)
	blockSize := uint32(10)
	w := bytes.NewBuffer([]byte{})
	writeChecksums(dir, []string{"file1", "file2"}, db, blockSize, w)

	ew := bytes.NewBuffer([]byte{})
	wrapBytes([]byte("file1"), fieldNumberFileName, ew)
	wrapBytes([]byte("content of file 1"), fieldNumberFileContent, ew)

	wrapBytes([]byte("file2"), fieldNumberFileName, ew)
	wrapBytes([]byte("content of file 2"), fieldNumberFileContent, ew)
	wrapVarint(successSig, fieldDonePushing, ew)

	if got, wanted := w.Bytes(), ew.Bytes(); !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestWriteChecksumsBlockHit(t *testing.T) {
	dir := t.TempDir()

	{
		f, err := os.Create(path.Join(dir, "file1"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("file 1 has content 1")
		f.Close()
	}

	{
		f, err := os.Create(path.Join(dir, "file2"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("file 2 has content 2")
		f.Close()
	}

	db := make(blockDB)

	// Write blocks.
	blockSize := uint32(10)
	{
		fcontent := []byte("file 1 has")
		if len(fcontent) != int(blockSize) {
			t.Errorf("expected block of size %v", blockSize)
		}

		s1, s2 := getAdler32Sums(fcontent)
		db[s2] = []*block{
			{
				idx: 0,
				hashes: &blockHashes{
					weak:   s2<<16 | s1,
					strong: getMD4Checksum(fcontent),
				},
			},
		}
	}

	{
		fcontent := []byte(" content 1")
		if len(fcontent) != int(blockSize) {
			t.Errorf("expected block of size %v", blockSize)
		}

		s1, s2 := getAdler32Sums(fcontent)
		db[s2] = []*block{
			{
				idx: 1,
				hashes: &blockHashes{
					weak:   s2<<16 | s1,
					strong: getMD4Checksum(fcontent),
				},
			},
		}
	}

	{
		fcontent := []byte("file 2 has")
		if len(fcontent) != int(blockSize) {
			t.Errorf("expected block of size %v", blockSize)
		}

		s1, s2 := getAdler32Sums(fcontent)
		db[s2] = []*block{
			{
				idx: 2,
				hashes: &blockHashes{
					weak:   s2<<16 | s1,
					strong: getMD4Checksum(fcontent),
				},
			},
		}
	}

	{
		fcontent := []byte(" content 2")
		if len(fcontent) != int(blockSize) {
			t.Errorf("expected block of size %v", blockSize)
		}

		s1, s2 := getAdler32Sums(fcontent)
		db[s2] = []*block{
			{
				idx: 3,
				hashes: &blockHashes{
					weak:   s2<<16 | s1,
					strong: getMD4Checksum(fcontent),
				},
			},
		}
	}

	w := bytes.NewBuffer([]byte{})
	writeChecksums(dir, []string{"file1", "file2"}, db, blockSize, w)

	ew := bytes.NewBuffer([]byte{})
	wrapBytes([]byte("file1"), fieldNumberFileName, ew)
	wrapVarint(0, fieldNumberHash, ew)
	wrapVarint(1, fieldNumberHash, ew)

	wrapBytes([]byte("file2"), fieldNumberFileName, ew)
	wrapVarint(2, fieldNumberHash, ew)
	wrapVarint(3, fieldNumberHash, ew)
	wrapVarint(successSig, fieldDonePushing, ew)

	if got, wanted := w.Bytes(), ew.Bytes(); !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestWriteChecksumsBlockHitWithAlignedDelta(t *testing.T) {
	dir := t.TempDir()

	{
		f, err := os.Create(path.Join(dir, "file1"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("file 1 has[was added content 1")
		f.Close()
	}

	db := make(blockDB)

	// Write blocks.
	blockSize := uint32(10)
	{
		fcontent := []byte("file 1 has")
		if len(fcontent) != int(blockSize) {
			t.Errorf("expected block of size %v", blockSize)
		}

		s1, s2 := getAdler32Sums(fcontent)
		db[s2] = []*block{
			{
				idx: 0,
				hashes: &blockHashes{
					weak:   s2<<16 | s1,
					strong: getMD4Checksum(fcontent),
				},
			},
		}
	}

	{
		fcontent := []byte(" content 1")
		if len(fcontent) != int(blockSize) {
			t.Errorf("expected block of size %v", blockSize)
		}

		s1, s2 := getAdler32Sums(fcontent)
		db[s2] = []*block{
			{
				idx: 1,
				hashes: &blockHashes{
					weak:   s2<<16 | s1,
					strong: getMD4Checksum(fcontent),
				},
			},
		}
	}

	w := bytes.NewBuffer([]byte{})
	writeChecksums(dir, []string{"file1"}, db, blockSize, w)

	ew := bytes.NewBuffer([]byte{})
	wrapBytes([]byte("file1"), fieldNumberFileName, ew)
	wrapVarint(0, fieldNumberHash, ew)
	wrapBytes([]byte("[was added"), fieldNumberFileContent, ew) // added delta
	wrapVarint(1, fieldNumberHash, ew)
	wrapVarint(successSig, fieldDonePushing, ew)

	if got, wanted := w.Bytes(), ew.Bytes(); !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestWriteChecksumsBlockHitWithUnalignedDelta(t *testing.T) {
	dir := t.TempDir()

	{
		f, err := os.Create(path.Join(dir, "file1"))
		if err != nil {
			t.Error(err)
		}
		f.WriteString("file 1 has[was content 1 for examp")
		f.Close()
	}

	db := make(blockDB)

	// Write blocks.
	blockSize := uint32(10)
	{
		fcontent := []byte("file 1 has")
		if len(fcontent) != int(blockSize) {
			t.Errorf("expected block of size %v", blockSize)
		}

		s1, s2 := getAdler32Sums(fcontent)
		db[s2] = []*block{
			{
				idx: 0,
				hashes: &blockHashes{
					weak:   s2<<16 | s1,
					strong: getMD4Checksum(fcontent),
				},
			},
		}
	}

	{
		fcontent := []byte(" content 1")
		if len(fcontent) != int(blockSize) {
			t.Errorf("expected block of size %v", blockSize)
		}

		s1, s2 := getAdler32Sums(fcontent)
		db[s2] = []*block{
			{
				idx: 1,
				hashes: &blockHashes{
					weak:   s2<<16 | s1,
					strong: getMD4Checksum(fcontent),
				},
			},
		}
	}

	{
		fcontent := []byte(" for examp")
		if len(fcontent) != int(blockSize) {
			t.Errorf("expected block of size %v", blockSize)
		}

		s1, s2 := getAdler32Sums(fcontent)
		db[s2] = append(
			db[s2], &block{
				idx: 2,
				hashes: &blockHashes{
					weak:   s2<<16 | s1,
					strong: getMD4Checksum(fcontent),
				},
			},
		)
	}

	w := bytes.NewBuffer([]byte{})
	writeChecksums(dir, []string{"file1"}, db, blockSize, w)

	ew := bytes.NewBuffer([]byte{})
	wrapBytes([]byte("file1"), fieldNumberFileName, ew)
	wrapVarint(0, fieldNumberHash, ew)
	wrapBytes([]byte("[was"), fieldNumberFileContent, ew) // added delta
	wrapVarint(1, fieldNumberHash, ew)
	wrapVarint(2, fieldNumberHash, ew)
	wrapVarint(successSig, fieldDonePushing, ew)

	if got, wanted := w.Bytes(), ew.Bytes(); !bytes.Equal(got, wanted) {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestPushPull(t *testing.T) {
	src, err := os.MkdirTemp(t.TempDir(), "src")
	if err != nil {
		t.Error(err)
	}

	f, err := os.Create(path.Join(src, "file1"))
	if err != nil {
		t.Error(err)
	}
	f.WriteString("content of file 1")
	f.Close()

	dest, err := os.MkdirTemp(t.TempDir(), "dest")
	if err != nil {
		t.Error(err)
	}

	peer1r, peer1w := io.Pipe()
	peer2r, peer2w := io.Pipe()

	errCh := make(chan error, 1)
	doneCh := make(chan struct{}, 1)
	var wg = sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := push(peer2r, peer1w, src); err != nil {
			errCh <- fmt.Errorf("push failed: %v", err.Error())
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := pull(peer1r, peer2w, dest, 10); err != nil {
			errCh <- fmt.Errorf("pull failed: %v", err.Error())
		}
	}()

	go func() {
		wg.Wait()
		doneCh <- struct{}{}
	}()

	select {
	case err := <-errCh:
		t.Error(err)
	case <-doneCh:
	}

	b, err := os.ReadFile(path.Join(dest, "file1"))
	if err != nil {
		t.Error(err)
	}
	if got, wanted := string(b), "content of file 1"; got != wanted {
		t.Errorf("got %v, wanted %v", got, wanted)
	}
}

func TestPushPullDelete(t *testing.T) {
	src, err := os.MkdirTemp(t.TempDir(), "src")
	if err != nil {
		t.Error(err)
	}

	dest, err := os.MkdirTemp(t.TempDir(), "dest")
	if err != nil {
		t.Error(err)
	}

	f, err := os.Create(path.Join(dest, "file1"))
	if err != nil {
		t.Error(err)
	}
	f.WriteString("content of file 1")

	peer1r, peer1w := io.Pipe()
	peer2r, peer2w := io.Pipe()

	var wg = sync.WaitGroup{}
	errCh := make(chan error, 1)
	doneCh := make(chan struct{}, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := push(peer2r, peer1w, src); err != nil {
			errCh <- fmt.Errorf("push failed: %v", err.Error())
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := pull(peer1r, peer2w, dest, 10); err != nil {
			errCh <- fmt.Errorf("pull failed: %v", err.Error())
		}
	}()

	go func() {
		wg.Wait()
		doneCh <- struct{}{}
	}()

	select {
	case err := <-errCh:
		t.Error(err)
	case <-doneCh:
	}

	_, err = os.Stat(path.Join(dest, "file1"))
	if err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Error("file expected to be deleted was found")
	}
}

func TestRsync(t *testing.T) {
	testDataDir := "test_data"
	entries, err := os.ReadDir(testDataDir)
	if err != nil {
		t.Error(err)
	}
	for _, entry := range entries {
		t.Run("TestData"+entry.Name(), func(t *testing.T) {
			srcDir := path.Join(testDataDir, entry.Name(), "src")
			currDir := path.Join(testDataDir, entry.Name(), "dest")
			destDir, err := os.MkdirTemp(t.TempDir(), "dest")
			if err != nil {
				t.Error(err)
			}
			if err := copyFiles(currDir, destDir); err != nil {
				t.Error(err)
			}
			compareDir(srcDir, destDir /*blockSize=*/, 10, t)
		})
	}
}

// TODO: use type parameters once go1.18 is stable.
// GitHub actions doesn't support it yet.
func CompareSlice(a, b []string) error {
	if len(a) != len(b) {
		return fmt.Errorf("slices don't have the same size:\nA=%v\nB=%v", a, b)
	}
	s := make(map[string]struct{}, len(a))
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

func copyFiles(src, dest string) error {
	return recurseDir(src, "", func(file string, entry os.DirEntry) error {
		srcFile := path.Join(src, file)
		srcPath := path.Dir(srcFile)

		b, err := os.ReadFile(srcFile)
		if err != nil {
			return fmt.Errorf("could not read file: %s", err.Error())
		}
		finfo, err := os.Stat(srcFile)
		if err != nil {
			return fmt.Errorf("could not get file info: %s", err.Error())
		}
		destFile := path.Join(dest, file)
		destPath := path.Dir(destFile)

		dinfo, err := os.Stat(srcPath)
		if err != nil {
			return fmt.Errorf("could not get path info: %s", err.Error())
		}
		if err := os.MkdirAll(destPath, dinfo.Mode()); err != nil {
			return fmt.Errorf("could not create dir: %s", err.Error())
		}
		return os.WriteFile(destFile, b, finfo.Mode())
	})
}

func compareDir(src, dest string, blockSize uint32, t *testing.T) {
	wanted := make(map[string][]byte)
	recurseDir(src, "", func(file string, entry os.DirEntry) error {
		filepath := path.Join(src, file)
		b, err := os.ReadFile(filepath)
		if err != nil {
			return err
		}
		wanted[file] = b
		return nil
	})

	peer1r, peer1w := io.Pipe()
	peer2r, peer2w := io.Pipe()

	var wg = sync.WaitGroup{}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := push(peer2r, peer1w, src); err != nil {
			t.Errorf("push failed: %v", err.Error())
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := pull(peer1r, peer2w, dest, blockSize); err != nil {
			t.Errorf("pull failed: %v", err.Error())
		}
	}()

	wg.Wait()

	got := make(map[string][]byte)
	recurseDir(dest, "", func(file string, entry os.DirEntry) error {
		filepath := path.Join(dest, file)
		b, err := os.ReadFile(filepath)
		if err != nil {
			return err
		}
		got[file] = b
		return nil
	})

	for name := range wanted {
		t.Logf("wanted file '%s'", name)
		if _, ok := got[name]; !ok {
			t.Errorf("expected file '%s', but it was not found.", name)
		}
	}
	for name := range got {
		t.Logf("got file '%s'", name)
		if _, ok := wanted[name]; !ok {
			t.Errorf("unexpected file '%s'.", name)
		}
	}

	for name, b1 := range got {
		b2 := wanted[name]
		if !bytes.Equal(b1, b2) {
			t.Errorf("file '%s' doesn't identical content in the dest dir."+
				"\ngot\n\n'%s'\n\nwanted:\n\n'%s'", name, b1, b2)
		}
	}
}
