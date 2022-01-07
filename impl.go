// Copyright 2021 Emmanuel Garcia. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsync

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
)

const (
	fieldNumberFileName fieldNumber = iota
	fieldNumberHash
	fieldNumberFileContent
	fieldDonePushing
)

const (
	blockSize       uint32 = 1000
	protocolVersion uint32 = 1

	successSig = 1
)

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

	// The file that contains these hashes relative
	// to a base directory.
	relfile string
}

type fsBlocks struct {
	blocks []*blockHashes
	files  map[fname]blockRange
}

type onFileCb = func(string, os.DirEntry) error
type fname string
type blockRange [2]uint32
type OpCode byte
type blockDB map[uint32][]*block
type found = struct{}

func getFileHashes(basedir, relfile string, blockSize int) []*blockHashes {
	f, err := os.Open(path.Join(basedir, relfile))
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
		s1, s2 := getAdler32Sums(b[:n])
		blocks[blockIdx] = &blockHashes{
			weak:    s2<<16 | s1,
			strong:  getMD4Checksum(b[:n]),
			relfile: relfile,
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
		files:  make(map[fname]blockRange),
	}
	for _, relfile := range files {
		fileHashes := getFileHashes(basedir, relfile, blockSize)
		allBlocks.files[fname(relfile)] = blockRange{
			uint32(len(allBlocks.blocks)),
			uint32(len(fileHashes)),
		}
		allBlocks.blocks = append(allBlocks.blocks, fileHashes...)
	}
	return &allBlocks, nil
}

func writeChecksums(base string, filenames []string, db blockDB, blockSize uint32, w io.Writer) error {
	for _, filename := range filenames {
		if err := wrapBytes([]byte(filename), fieldNumberFileName, w); err != nil {
			return err
		}
		if err := processFile(path.Join(base, filename), db, blockSize, w); err != nil {
			return err
		}
	}
	// Notify success to the peer.
	return wrapVarint(successSig, fieldDonePushing, w)
}

func processFile(file string, db blockDB, blockSize uint32, w io.Writer) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	sb := make([]byte, 1)
	b := make([]byte, blockSize)
	off := -1
	lastOff := -1

	var s1, s2 uint32
	for {
		n, _ := f.Read(b)
		if n == 0 {
			break
		}
		currOff := off
		off += n
		s1, s2 = getAdler32Sums(b[:n])

		if entries, ok := db[s2]; ok {
			idx, err := getHashIndex(s1, s2, entries, b[:n])
			if err != nil {
				continue
			}
			if lastOff > -1 && lastOff < currOff {
				return errors.New("unexpected state")
			}
			if err := wrapVarint(idx, fieldNumberHash, w); err != nil {
				return err
			}
			lastOff = off
			continue
		}
		for {
			n, err := f.Read(sb)
			if n == 0 || err == io.EOF {
				break
			}

			currOff += n
			off += n
			added, removed := sb[0], b[0]
			b = append(b[1:], sb...)
			s1, s2 = getNextAdler32(s1, s2, blockSize, removed, added)
			entries, ok := db[s2]
			if !ok {
				continue
			}
			idx, err := getHashIndex(s1, s2, entries, b)
			if err != nil {
				continue
			}
			if lastOff < currOff {
				fcontent := make([]byte, currOff-lastOff)
				n, err := f.ReadAt(fcontent, int64(lastOff+1))
				if err != nil {
					return err
				}
				if err := wrapBytes(fcontent[:n], fieldNumberFileContent, w); err != nil {
					return err
				}
			}
			if err := wrapVarint(idx, fieldNumberHash, w); err != nil {
				return err
			}
			lastOff = off
			break
		}
	}
	if lastOff >= off {
		return nil
	}
	fcontent := make([]byte, off-lastOff)
	n, err := f.ReadAt(fcontent, int64(lastOff+1))
	if err != nil {
		return err
	}
	return wrapBytes(fcontent[:n], fieldNumberFileContent, w)
}

func getHashIndex(s1, s2 uint32, entries []*block, b []byte) (uint32, error) {
	weak := s2<<16 | s1
	for _, entry := range entries {
		if entry.hashes.weak == weak && bytes.Equal(getMD4Checksum(b), entry.hashes.strong) {
			return entry.idx, nil
		}
	}
	return 0, fmt.Errorf("index not found")
}

func push(r io.Reader, w io.Writer, src string) error {
	version, err := readVarint(r)
	if err != nil {
		return fmt.Errorf("could not read version: %v", err.Error())
	}
	if version != protocolVersion {
		return fmt.Errorf(
			"remote uses a different version: %d, the local version is: %d",
			version,
			protocolVersion,
		)
	}
	rBlockSize, err := readVarint(r)
	if err != nil {
		return fmt.Errorf("could not get block size from remote: %v", err.Error())
	}
	if rBlockSize == 0 {
		return fmt.Errorf("remote cannot use block size of zero bytes")
	}
	blockCount, err := readVarint(r)
	if err != nil {
		return fmt.Errorf("could not get checksum count from remote: %v", err.Error())
	}

	blocks := make(blockDB, blockCount)
	for idx := uint32(0); idx < blockCount; idx++ {
		rollingChecksum, err := readVarint(r)
		if err != nil {
			return fmt.Errorf("could not read rolling checksum: %v, for index: %d", err.Error(), idx)
		}
		strongChecksum := make([]byte, 16)
		if _, err := r.Read(strongChecksum); err != nil {
			return fmt.Errorf("could not read strong checksum: %v, for index: %d", err.Error(), idx)
		}
		// Use the 16-bit hash of the 32-bit rolling checksum as the key of the map.
		// The 16-bit hash is cheaper to compute than the 32-bit hash.
		blockKey := rollingChecksum >> 16
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
	err = writeChecksums(src, lFiles, blocks, rBlockSize, w)
	if err != nil {
		return fmt.Errorf("could not determine checksums: %v", err.Error())
	}
	fieldNum, fieldType, err := getValueMeta(r)
	if err != nil {
		return fmt.Errorf("expected success check: %s", err.Error())
	}
	if fieldNum != fieldDonePushing || fieldType != typeVarint {
		return fmt.Errorf("expected success check: %d, %d", fieldNum, fieldType)
	}
	success, err := readVarint(r)
	if err != nil {
		return fmt.Errorf("expected success check: %s", err.Error())
	}
	if success != successSig {
		return fmt.Errorf("success check expected %v, but got: %v", successSig, success)
	}
	return nil
}

func pull(r io.Reader, w io.Writer, src string, lBlockSize uint32) error {
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
	if err := writeVarint(protocolVersion, w); err != nil {
		return fmt.Errorf("could not write protocol version: %v", err.Error())
	}
	if err := writeVarint(lBlockSize, w); err != nil {
		return fmt.Errorf("could not write block size: %v", err.Error())
	}
	if err := writeVarint(uint32(len(fsBlocks.blocks)), w); err != nil {
		return fmt.Errorf("could not write number of files: %v", err.Error())
	}
	for _, block := range fsBlocks.blocks {
		if err := writeVarint(block.weak, w); err != nil {
			return fmt.Errorf("could not write weak checksum: %v", err.Error())
		}
		if _, err := w.Write(block.strong); err != nil {
			return fmt.Errorf("could not write hash: %v", err.Error())
		}
	}

	// Read response from peer.
	var currFile *os.File
	var blockIdx uint32
	var filename string
	b := make([]byte, blockSize)
	fSent := make(map[fname]found)
	for {
		fieldNum, fieldType, err := getValueMeta(r)
		if err != nil {
			return fmt.Errorf("could not read value metadata: %v", err.Error())
		}
		switch fieldNum {
		case fieldNumberFileName:
			if fieldType != typeLengthDelimeted {
				return fmt.Errorf("expected type: %v, but got: %v", typeLengthDelimeted, fieldType)
			}
			if currFile != nil {
				currFile.Close()
				currFile = nil
			}
			name, err := readBytes(r)
			if err != nil {
				return fmt.Errorf("could not read bytes: %v", err)
			}
			filename = string(name)
			if _, ok := fSent[fname(filename)]; ok {
				return fmt.Errorf("file already sent: %s", filename)
			}
			fSent[fname(filename)] = found{}
			filepath := path.Join(src, string(filename))
			blockIdx = 0
			if _, err := os.Stat(filepath); errors.Is(err, os.ErrNotExist) {
				currFile, err = os.OpenFile(filepath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
				if err != nil {
					return fmt.Errorf("could not create file %s: %v", filepath, err)
				}
			} else {
				currFile, err = os.Open(filepath)
				if err != nil {
					return fmt.Errorf("could not open file %s: %v", filepath, err)
				}
			}
		case fieldNumberHash:
			if fieldType != typeVarint {
				return fmt.Errorf("expected type: %v, but got: %v", typeVarint, fieldType)
			}
			if currFile == nil || len(filename) == 0 {
				return errors.New("expected file and filename")
			}
			rblockIdx, err := readVarint(r)
			if rblockIdx >= uint32(len(fsBlocks.blocks)) {
				return fmt.Errorf(
					"unexpected block index %d, the max number of local blocks is %d",
					rblockIdx,
					len(fsBlocks.blocks),
				)
			}
			if rg, ok := fsBlocks.files[fname(filename)]; ok {
				startBlockIdx, endBlockIdx := rg[0], rg[1]
				if startBlockIdx+blockIdx == rblockIdx && rblockIdx < endBlockIdx {
					// Ok. block found at the expected offset.
					continue
				} else {
					// A block was found, but the block at the current offset doesn't match.
					// This can happen if file content is moved around.
					remaining := make([]byte, (endBlockIdx-startBlockIdx)*lBlockSize)
					n1, err := currFile.ReadAt(remaining, (int64(blockIdx)+1)*int64(lBlockSize))
					if err != io.EOF && err != nil {
						return fmt.Errorf("could not read file %s: %s", filename, err.Error())
					}
					err = currFile.Truncate(int64(blockIdx) * int64(lBlockSize))
					if err != nil {
						return fmt.Errorf("could not truncate file %s: %s", filename, err.Error())
					}
					relfile := fsBlocks.blocks[rblockIdx].relfile
					f, err := os.Open(path.Join(src, relfile))
					if err != nil {
						return fmt.Errorf("could not open file %s in %s: %s", relfile, src, err.Error())
					}
					rg := fsBlocks.files[fname(relfile)]
					off := (int64(rblockIdx) - int64(rg[0])) * int64(lBlockSize)
					n2, err := f.ReadAt(b, off)
					f.Close()
					if err != io.EOF && err != nil {
						return fmt.Errorf("could not read file %s in %s: %s", relfile, src, err.Error())
					}
					currFile.Write(b[:n2])
					currFile.Write(remaining[:n1])
				}
			} else {
				// The file was not present locally, but a block was found.
				// This can happen when a file is moved.
				// In this case, the block is copied from file A to file B.
				relfile := fsBlocks.blocks[rblockIdx].relfile
				f, err := os.Open(path.Join(src, relfile))
				if err != nil {
					return fmt.Errorf("could not open file %s in %s: %s", relfile, src, err.Error())
				}
				rg := fsBlocks.files[fname(relfile)]
				off := (int64(rblockIdx) - int64(rg[0])) * int64(lBlockSize)
				n, err := f.ReadAt(b, off)
				f.Close()
				if err != io.EOF && err != nil {
					return fmt.Errorf("could not read file %s in %s: %s", relfile, src, err.Error())
				}
				_, err = currFile.WriteAt(b[:n], int64(blockIdx)*int64(lBlockSize))
				if err != nil {
					return fmt.Errorf("could not write file %s: %s", filename, err.Error())
				}
			}
			blockIdx++
			if err != nil {
				return fmt.Errorf("could not read varint: %v", err.Error())
			}
		case fieldNumberFileContent:
			if fieldType != typeLengthDelimeted {
				return fmt.Errorf("expected type: %v, but got: %v", typeLengthDelimeted, fieldType)
			}
			if currFile == nil || len(filename) == 0 {
				return errors.New("expected file and filename")
			}
			fcontent, err := readBytes(r)
			if err != nil {
				return fmt.Errorf("could not read bytes: %v", err.Error())
			}
			// Write the file content in the expected offset.
			_, err = currFile.WriteAt(fcontent, int64(blockIdx)*int64(lBlockSize))
			if err != io.EOF && err != nil {
				return fmt.Errorf("could not write file content %s: %s", filename, err.Error())
			}
		case fieldDonePushing:
			if currFile != nil {
				currFile.Close()
				currFile = nil
			}
			// Delete files that are present locally, but were not sent by the peer.
			for filename := range fsBlocks.files {
				if _, ok := fSent[filename]; !ok {
					err := os.Remove(path.Join(src, string(filename)))
					if err != nil {
						return fmt.Errorf("could not delete file %s: %s", filename, err.Error())
					}
				}
			}
			success, _ := readVarint(r)
			if success != successSig {
				return fmt.Errorf("success check expected %v, but got: %v", successSig, success)
			}
			// Notify success to the peer.
			return wrapVarint(successSig, fieldDonePushing, w)
		default:
			return fmt.Errorf("invalid field number: %v", fieldNum)
		}
	}
}
