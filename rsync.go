// Copyright 2009 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
)

type message struct {
}

type fileChecksums struct {
	weak   []uint32
	strong [][]byte
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
		checksums.weak[blockIdx] = getAdler32(fcontent[start:end])
		checksums.strong[blockIdx] = getMD4Checksum(fcontent[start:end])
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

type filesChecksums struct {
	checksums      []*fileChecksums
	checksumsCount int
}

func getFilesChecksums(files []string, blockSize int) (*filesChecksums, error) {
	checksums := make([]*fileChecksums, len(files))
	checksumsCount := 0

	for i, file := range files {
		c, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		checksums[i] = getFileChecksums(c, blockSize)
		if len(checksums[i].weak) != len(checksums[i].strong) {
			return nil, errors.New("invalid state: expected same number of checksums")
		}
		checksumsCount += len(checksums[i].weak)
	}
	return &filesChecksums{
		checksums:      checksums,
		checksumsCount: checksumsCount,
	}, nil
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
	checksumsCount, err := readUint32(r)
	if err != nil {
		return fmt.Errorf("could not get checksum count from remote: %v", err.Error())
	}
	strongChecksum := make([]byte, 16)
	for i := uint32(0); i < checksumsCount; i++ {
		_, err := readUint32(r)
		if err != nil {
			return fmt.Errorf("could not read weak checksum: %v, for index: %d", err.Error(), i)
		}
		if _, err := r.Read(strongChecksum); err != nil {
			return fmt.Errorf("could not read strong checksum: %v, for index: %d", err.Error(), i)
		}
	}
	return nil
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
	return push(rw, rw, src)
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
	lChecksums, err := getFilesChecksums(lFiles, int(lBlockSize))
	if err != nil {
		return fmt.Errorf("could not get checksums for files: %v", err.Error())
	}
	if _, err := w.Write([]byte{protocolVersion}); err != nil {
		return fmt.Errorf("could not write protocol version: %v", err.Error())
	}
	if err := writeUint32(lBlockSize, w); err != nil {
		return fmt.Errorf("could not write block size: %v", err.Error())
	}
	if err := writeUint32(uint32(lChecksums.checksumsCount), w); err != nil {
		return fmt.Errorf("could not write checksum count: %v", err.Error())
	}
	for _, checksums := range lChecksums.checksums {
		for idx := range checksums.strong {
			if err := writeUint32(checksums.weak[idx], w); err != nil {
				return fmt.Errorf("could not write weak checksum: %v", err.Error())
			}
			if _, err := w.Write(checksums.strong[idx]); err != nil {
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
	return pull(rw, rw, dest, blockSize)
}
