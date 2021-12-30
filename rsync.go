// Copyright 2009 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"
	"math"
	"os"
	"path"

	"golang.org/x/crypto/md4"
)

type message struct {
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

type fileChecksums struct {
	adler32 []uint32
	md4     [][]byte
}

func getFileChecksums(fcontent []byte, blockSize int) *fileChecksums {
	flen := len(fcontent)
	maxBlocks := int(math.Ceil(float64(flen) / float64(blockSize)))
	checksums := &fileChecksums{
		make([]uint32, maxBlocks),
		make([][]byte, maxBlocks),
	}
	for blockIdx := 0; blockIdx < maxBlocks; blockIdx++ {
		start := blockIdx * blockSize
		end := (blockIdx + 1) * blockSize
		if end > flen {
			end = flen
		}
		checksums.adler32[blockIdx] = getAdler32(fcontent[start:end])
		checksums.md4[blockIdx] = getMD4Checksum(fcontent[start:end])
	}
	return checksums
}

type onFileCb = func(string, os.DirEntry) error

func recurseDir(dir string, onFile onFileCb) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()

	entries, err := f.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, file := range entries {
		childFile := path.Join(dir, file.Name())
		if file.IsDir() {
			if err := recurseDir(childFile, onFile); err != nil {
				return err
			}
		} else if err := onFile(childFile, file); err != nil {
			return err
		}
	}
	return nil
}

func getFilesChecksums(files []string, blockSize int) ([]*fileChecksums, error) {
	checksums := make([]*fileChecksums, len(files))
	for i, file := range files {
		c, err := os.ReadFile(file)
		if err != nil {
			return checksums, err
		}
		checksums[i] = getFileChecksums(c, blockSize)
	}
	return checksums, nil
}

const (
	blockSize       uint32 = 100
	protocolVersion byte   = 1
)

type sqType byte

const (
	version sqType = iota
	hash
	blockContent
)

func decodeUint32(bytes []byte) uint32 {
	return binary.LittleEndian.Uint32(bytes)
}

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
	files := []string{}
	err := recurseDir(src, func(file string, entry os.DirEntry) error {
		files = append(files, file)
		return nil
	})
	if err != nil {
		return fmt.Errorf("could not recurse directory: %v", err.Error())
	}
	checksums, err := getFilesChecksums(files, int(blockSize))
	if err != nil {
		return fmt.Errorf("could not get checksums for files: %v", err.Error())
	}

	header := make([]byte, 6)
	header[0] = byte(version)
	header[1] = protocolVersion
	binary.LittleEndian.PutUint32(header[2:], blockSize)

	if _, err := rw.Write(header); err != nil {
		return fmt.Errorf("could not write header: %v", err.Error())
	}

	bytes := make([]byte, 21)
	for _, checksums := range checksums {
		for idx := range checksums.md4 {
			bytes[0] = byte(hash)
			binary.LittleEndian.PutUint32(bytes[1:5], checksums.adler32[idx])
			copy(bytes[5:], checksums.md4[idx])
			if _, err := rw.Write(bytes); err != nil {
				return fmt.Errorf("could not write hash: %v", err.Error())
			}
		}
	}
	return nil
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
	return nil
}
