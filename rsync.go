// Copyright 2009 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"fmt"
	"io"
	"math"
	"os"
	"path"
)

// Push sends to the remote peer the weak "rolling" 32-bit checksum
// of a file's blocks contained in src directory.
//
// These checksums are then used by the remote peer to determine what
// file blocks must be sent by the current peer in order to syncronize
// the src directory.
//
// Finally, the current peer transfers the requested blocks to the remote
// peer.
func Push(rw io.ReadWriter, src string) error {
	return push(rw, rw, src)
}

// Pull retrieves the weak "rolling" 32-bit checksum of the file's blocks
// contained in the remote peer's src directory.
//
// It then scans the dest directory, and finds the minimal set of file blocks
// that must be sent by the remote peer in order to syncronize the src
// directory in the current peer.
//
// Finally, the current peer writes the blocks to disk.
func Pull(rw io.ReadWriter, dest string) error {
	return pull(rw, rw, dest, blockSize)
}

// A block represents a non-overlapping fixed-sized sequence of S bytes
// in a file.
// S is the block size.
type block struct {
	// The index of the block relative to the other blocks in the list
	// resulted from scanning the dest directory.
	idx uint32

	// The hashes used to identify this block.
	hashes *blockHashes
}

type blockHashes struct {
	// The weak rolling checksum that uses adler-32.
	weak uint32

	// The strong checksum that uses MD4.
	strong []byte
}

type fsBlocks struct {
	blocks []*blockHashes
	files  map[filename]blockRange
}

type onFileCb = func(string, os.DirEntry) error
type filename string
type blockRange [2]int
type OpCode byte
type blockDB map[uint16][]*block

const (
	blockSize       uint32 = 1000
	protocolVersion byte   = 1
)

const (
	syncOp OpCode = iota
)

func getFileHashes(file string, blockSize int) []*blockHashes {
	f, err := os.Open(file)
	if err != nil {
		return make([]*blockHashes, 0)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return make([]*blockHashes, 0)
	}

	flen := info.Size()
	maxBlocks := int(math.Ceil(float64(flen) / float64(blockSize)))
	blocks := make([]*blockHashes, maxBlocks)

	blockIdx := int(0)
	b := make([]byte, blockSize)

	for {
		n, err := f.Read(b)
		if err != nil && err != io.EOF {
			return make([]*blockHashes, 0)
		}
		if n == 0 {
			return blocks
		}
		blocks[blockIdx] = &blockHashes{
			weak:   getAdler32(b[:n]),
			strong: getMD4Checksum(b[:n]),
		}
		if err == io.EOF {
			return blocks
		}
		blockIdx++
	}
}

func recurseDir(base string, relDir string, onFile onFileCb) error {
	f, err := os.Open(path.Join(base, relDir))
	if err != nil {
		return err
	}
	defer f.Close()

	entries, err := f.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, file := range entries {
		nextRelDir := path.Join(relDir, file.Name())
		if file.IsDir() {
			if err := recurseDir(base, nextRelDir, onFile); err != nil {
				return err
			}
		} else if err := onFile(nextRelDir, file); err != nil {
			return err
		}
	}
	return nil
}

func getBlocks(basedir string, files []string, blockSize int) (*fsBlocks, error) {
	allBlocks := fsBlocks{
		blocks: []*blockHashes{},
		files:  make(map[filename]blockRange),
	}
	for _, relfile := range files {
		fullFile := path.Join(basedir, relfile)
		fileHashes := getFileHashes(fullFile, blockSize)
		allBlocks.files[filename(relfile)] = blockRange{
			len(allBlocks.blocks),
			len(fileHashes),
		}
		allBlocks.blocks = append(allBlocks.blocks, fileHashes...)
	}
	return &allBlocks, nil
}

func searchChecksum(base string, filenames []string, db *blockDB, blockSize uint32, w io.Writer) error {
	for _, filename := range filenames {
		processFile(path.Join(base, filename), db, blockSize, w)
	}
	return nil
}

func processFile(file string, db *blockDB, blockSize uint32, w io.Writer) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	// if err := writeBytes([]byte(file), w); err != nil {
	// 	return err
	// }
	b := make([]byte, blockSize)
	n, err := f.Read(b)
	if n == 0 || err == io.EOF {
		return nil
	}
	singleByte := make([]byte, 1)
	for {
		n, err := f.Read(singleByte)
		if n == 0 || err == io.EOF {
			return nil
		}
	}
}

func push(r io.Reader, w io.Writer, src string) error {
	if _, err := w.Write([]byte{byte(syncOp)}); err != nil {
		return fmt.Errorf("could not send sync operation: %v", err.Error())
	}
	rHeader := make([]byte, 1)
	if _, err := r.Read(rHeader); err != nil {
		return fmt.Errorf("could not read header: %v", err.Error())
	}
	if rVersion := rHeader[0]; rVersion != protocolVersion {
		return fmt.Errorf(
			"remote uses a different version: %d, the local version is: %d",
			rVersion,
			protocolVersion,
		)
	}
	rBlockSize, err := readUint32(r)
	if err != nil {
		return fmt.Errorf("could not get block size from remote: %v", err.Error())
	}
	if rBlockSize == 0 {
		return fmt.Errorf("remote cannot use block size of zero bytes")
	}
	blockCount, err := readUint32(r)
	if err != nil {
		return fmt.Errorf("could not get checksum count from remote: %v", err.Error())
	}

	blocks := make(blockDB, blockCount)
	for idx := uint32(0); idx < blockCount; idx++ {
		rollingChecksum, err := readUint32(r)
		if err != nil {
			return fmt.Errorf("could not read rolling checksum: %v, for index: %d", err.Error(), idx)
		}
		strongChecksum := make([]byte, 16)
		if _, err := r.Read(strongChecksum); err != nil {
			return fmt.Errorf("could not read strong checksum: %v, for index: %d", err.Error(), idx)
		}
		// Use the 16-bit hash of the 32-bit rolling checksum as the key of the map.
		// The 16-bit hash is cheaper to compute than the 32-bit hash.
		blockKey := uint16(rollingChecksum >> 16)
		if _, has := blocks[blockKey]; !has {
			blocks[blockKey] = []*block{}
		}
		blocks[blockKey] = append(
			blocks[blockKey],
			&block{
				idx: idx,
				hashes: &blockHashes{
					weak:   rollingChecksum,
					strong: strongChecksum,
				},
			})
	}
	lFiles := []string{}
	err = recurseDir(src, "", func(file string, entry os.DirEntry) error {
		lFiles = append(lFiles, file)
		return nil
	})
	if err != nil {
		return fmt.Errorf("could not scan directory: %v", err.Error())
	}
	err = searchChecksum(src, lFiles, &blocks, rBlockSize, w)
	if err != nil {
		return fmt.Errorf("could not determine checksums: %v", err.Error())
	}
	return nil
}

func pull(r io.Reader, w io.Writer, src string, lBlockSize uint32) error {
	rHeader := make([]byte, 1)
	if _, err := r.Read(rHeader); err != nil {
		return fmt.Errorf("could not read remote headers: %v", err.Error())
	}
	if rHeader[0] != byte(syncOp) {
		return fmt.Errorf("unexpected operation: %v", rHeader[0])
	}
	lFiles := []string{}
	err := recurseDir(src, "", func(file string, entry os.DirEntry) error {
		lFiles = append(lFiles, file)
		return nil
	})
	if err != nil {
		return fmt.Errorf("could not scan directory: %v", err.Error())
	}
	fsBlocks, err := getBlocks(src, lFiles, int(lBlockSize))
	if err != nil {
		return fmt.Errorf("could not get file metas: %v", err.Error())
	}
	if _, err := w.Write([]byte{protocolVersion}); err != nil {
		return fmt.Errorf("could not write protocol version: %v", err.Error())
	}
	if err := writeUint32(lBlockSize, w); err != nil {
		return fmt.Errorf("could not write block size: %v", err.Error())
	}
	if err := writeUint32(uint32(len(fsBlocks.blocks)), w); err != nil {
		return fmt.Errorf("could not write number of files: %v", err.Error())
	}
	for _, block := range fsBlocks.blocks {
		if err := writeUint32(block.weak, w); err != nil {
			return fmt.Errorf("could not write weak checksum: %v", err.Error())
		}
		if _, err := w.Write(block.strong); err != nil {
			return fmt.Errorf("could not write hash: %v", err.Error())
		}
	}
	return nil
}
