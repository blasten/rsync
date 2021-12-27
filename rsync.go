// Copyright 2009 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"encoding/gob"
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

func getMD4Checksum(block []byte) string {
	h := md4.New()
	h.Write(block)
	return string(h.Sum(nil))
}

type fileChecksums struct {
	adler32 []uint32
	md4     []string
}

func getFileChecksums(fcontent []byte, blockSize int) *fileChecksums {
	flen := len(fcontent)
	maxBlocks := int(math.Ceil(float64(flen) / float64(blockSize)))
	checksums := &fileChecksums{
		make([]uint32, maxBlocks),
		make([]string, maxBlocks),
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
	dec := gob.NewDecoder(rw)

	var msg message
	err := dec.Decode(&msg)
	if err != nil {
		return fmt.Errorf("could not decode message: %s", err.Error())
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
