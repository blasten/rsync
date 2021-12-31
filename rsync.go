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
	// weak rolling checksum that uses adler-32.
	weak uint32
	// strong checksum that uses MD4.
	strong []byte
}

func getFileBlocks(filename string, fcontent []byte, blockSize int) []*block {
	flen := len(fcontent)
	maxBlocks := int(math.Ceil(float64(flen) / float64(blockSize)))
	blocks := make([]*block, maxBlocks)
	for blockIdx := 0; blockIdx < maxBlocks; blockIdx++ {
		start := blockIdx * blockSize
		end := (blockIdx + 1) * blockSize
		if end > flen {
			end = flen
		}
		blocks[blockIdx] = &block{
			weak:   getAdler32(fcontent[start:end]),
			strong: getMD4Checksum(fcontent[start:end]),
		}
	}
	return blocks
}

type onFileCb = func(string, os.DirEntry) error

func recurseDir(base string, onFile onFileCb) error {
	return recurseDirWithRelDir(base, "", onFile)
}

func recurseDirWithRelDir(base string, relDir string, onFile onFileCb) error {
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
			if err := recurseDirWithRelDir(base, nextRelDir, onFile); err != nil {
				return err
			}
		} else if err := onFile(nextRelDir, file); err != nil {
			return err
		}
	}
	return nil
}

type filename string
type blockRange [2]int

type fsBlocks struct {
	blocks []*block
	files  map[filename]blockRange
}

func getBlocks(basedir string, files []string, blockSize int) (*fsBlocks, error) {
	allBlocks := fsBlocks{
		blocks: []*block{},
		files:  make(map[filename]blockRange),
	}
	for _, relfile := range files {
		file := path.Join(basedir, relfile)
		c, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		fileBlocks := getFileBlocks(relfile, c, blockSize)
		allBlocks.files[filename(relfile)] = blockRange{
			len(allBlocks.blocks),
			len(fileBlocks),
		}
		allBlocks.blocks = append(allBlocks.blocks, fileBlocks...)
	}
	return &allBlocks, nil
}

const (
	blockSize       uint32 = 1000
	protocolVersion byte   = 1
)

type OpCode byte

const (
	syncOp OpCode = iota
)

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

	blocks := make(map[uint16][]*block)

	for i := uint32(0); i < blockCount; i++ {
		rollingChecksum, err := readUint32(r)
		if err != nil {
			return fmt.Errorf("could not read rolling checksum: %v, for index: %d", err.Error(), i)
		}
		strongChecksum := make([]byte, 16)
		if _, err := r.Read(strongChecksum); err != nil {
			return fmt.Errorf("could not read strong checksum: %v, for index: %d", err.Error(), i)
		}
		// Use the 16-bit hash of the 32-bit rolling checksum.
		blockKey := uint16(rollingChecksum >> 16)
		if _, has := blocks[blockKey]; !has {
			blocks[blockKey] = []*block{}
		}
		blocks[blockKey] = append(
			blocks[blockKey],
			&block{
				weak:   rollingChecksum,
				strong: strongChecksum,
			})
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
	err := recurseDir(src, func(file string, entry os.DirEntry) error {
		lFiles = append(lFiles, file)
		return nil
	})
	if err != nil {
		return fmt.Errorf("could not recurse directory: %v", err.Error())
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
