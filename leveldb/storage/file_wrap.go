package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"os"
	"crypto/rand"
)

type fileWrap struct {
	*os.File
	fs     *fileStorage
	fd     FileDesc
	closed bool
}

func (fw *fileWrap) Sync() error {
	if err := fw.File.Sync(); err != nil {
		return err
	}
	if fw.fd.Type == TypeManifest {
		// Also sync parent directory if file type is manifest.
		// See: https://code.google.com/p/leveldb/issues/detail?id=190.
		if err := syncDir(fw.fs.path); err != nil {
			fw.fs.log(fmt.Sprintf("syncDir: %v", err))
			return err
		}
	}
	return nil
}

func (fw *fileWrap) Close() error {
	fw.fs.mu.Lock()
	defer fw.fs.mu.Unlock()
	if fw.closed {
		return ErrClosed
	}
	fw.closed = true
	fw.fs.open--
	err := fw.File.Close()
	if err != nil {
		fw.fs.log(fmt.Sprintf("close %s: %v", fw.fd, err))
	}
	return err
}

type aesFileWrap struct {
	*os.File

	// handle data which not fit into chunk size
	nRem uint64
	rem  []byte

	// for encryption
	// FIXME: update cipher block iv per page?
	//        seems should be do the cipher with FileWrapper, do it in container
	aesCipherBlock cipher.Block
	encryMode      cipher.BlockMode
	decryMode  cipher.BlockMode

	fs     *fileStorage
	fd     FileDesc
	closed bool
}

func InitAesFileWrap(of *os.File, fs *fileStorage, fd FileDesc, key []byte) (*aesFileWrap, error) {
	flen, err := of.Seek(0, os.SEEK_END)
	if err != nil {
		return nil, err
	}
	if (flen-8)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid file len: %d", flen)
	}

	fw := &aesFileWrap{
		File: of,
		fs:   fs,
		fd:   fd,
	}

	tmpBlock := make([]byte, aes.BlockSize)
	if flen > aes.BlockSize {
		of.Seek(0, os.SEEK_SET)
		of.Read(tmpBlock)
	} else {
		if _, err := rand.Reader.Read(tmpBlock); err != nil {
			return nil, fmt.Errorf("failed to init cipher block")
		}
		of.Write(tmpBlock)
	}
	fw.aesCipherBlock, err = aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to init cipher")
	}
	fw.encryMode = cipher.NewCBCEncrypter(fw.aesCipherBlock, tmpBlock)
	fw.decryMode = cipher.NewCBCEncrypter(fw.aesCipherBlock, tmpBlock)
	stm := cipher.NewCTR(fw.aesCipherBlock, tmpBlock)
	stm.XORKeyStream(tmpBlock, tmpBlock)

	lenBytes := make([]byte, 8)
	of.Seek(-8, os.SEEK_END)
	if _, err := of.Read(lenBytes); err != nil {
		return nil, fmt.Errorf("read file len failed: %s", err)
	}


	dataLen := binary.LittleEndian.Uint64(lenBytes)
	rem := make([]byte, aes.BlockSize)
	nRem := dataLen % aes.BlockSize
	if nRem > 0 {
		of.Seek(-8-aes.BlockSize, os.SEEK_END)
		of.Read(rem)
		fw.encryMode.CryptBlocks(rem, rem)
		fw.nRem = nRem
		fw.rem = rem
	}

	return fw, nil
}

func (fw *aesFileWrap) Write(data []byte) (nw int, err error) {
	if len(data) <= 0 {
		return 0, nil
	}

	// set pos back to end of last full block
	remBytesInFile := 8
	if fw.nRem > 0 {
		remBytesInFile += aes.BlockSize
	}
	fw.File.Seek(int64(-remBytesInFile), os.SEEK_END)

	roundSize := ((uint64(len(data)) + fw.nRem) / aes.BlockSize) * aes.BlockSize
	nbw := Max(roundSize-fw.nRem, 0)
	if roundSize > 0 {
		buf := make([]byte, roundSize)
		copy(buf, fw.rem[0:fw.nRem])
		copy(buf[fw.nRem:], data[0:nbw])
		fw.nRem = 0
		fw.encryMode.CryptBlocks(buf, buf)
		if n, err := fw.File.Write(buf); err != nil {
			return n, err
		}
	}

	// get file len
	flen, err := fw.File.Seek(0, os.SEEK_END)
	if err != nil {
		return int(nbw), err
	}

	if fw.nRem > 0 {
		// write rem
		if err := fw.writeRems(); err != nil {
			return int(nbw), err
		}
	} else {
		// write file length
		lenBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(lenBytes, uint64(flen))
		fw.File.Write(lenBytes)
	}

	// set file position to end
	fw.File.Seek(0, os.SEEK_END)

	copy(fw.rem[fw.nRem:], data[nbw:])
	fw.nRem += (uint64(len(data)) - nbw)
	return len(data), nil
}

func (fw *aesFileWrap) writeRems() error {
	if fw.nRem <= 0 {
		return nil
	}

	// get file len
	flen, err := fw.File.Seek(0, os.SEEK_END)
	if err != nil {
		return err
	}

	// write rem
	buf := make([]byte, aes.BlockSize)
	copy(buf, fw.rem[0:fw.nRem])
	fw.encryMode.CryptBlocks(buf, buf)
	if _, err := fw.File.Write(buf); err != nil {
		return err
	}

	// write file length
	lenBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(lenBytes, uint64(flen))
	fw.File.Write(lenBytes)

	return nil
}

func (fw *aesFileWrap) Sync() error {
	if fw.nRem > 0 {
		if err := fw.writeRems(); err != nil {
			return err
		}
	}

	if err := fw.File.Sync(); err != nil {
		return err
	}
	if fw.fd.Type == TypeManifest {
		// Also sync parent directory if file type is manifest.
		// See: https://code.google.com/p/leveldb/issues/detail?id=190.
		if err := syncDir(fw.fs.path); err != nil {
			fw.fs.log(fmt.Sprintf("syncDir: %v", err))
			return err
		}
	}

	return nil
}

func Max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func Min(a, b uint64) uint64 {
	if a > b {
		return b
	}
	return a
}
