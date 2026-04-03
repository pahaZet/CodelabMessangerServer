package media

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

var encryptedMediaMagic = []byte("TINODE_MEDIA_V1\x00")

const defaultEncryptedChunkSize = 64 * 1024

// FileCryptoConfig carries optional at-rest encryption settings for media handlers.
type FileCryptoConfig struct {
	Cipher    cipher.AEAD
	AADPrefix string
	ChunkSize int
}

// FileCryptoProvider is an optional adapter interface for media encryption.
type FileCryptoProvider interface {
	GetFileCryptoConfig() *FileCryptoConfig
}

type tempReadSeekCloser struct {
	*os.File
	path string
}

func (trsc *tempReadSeekCloser) Close() error {
	err := trsc.File.Close()
	if rmErr := os.Remove(trsc.path); err == nil && rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		err = rmErr
	}
	return err
}

func (fcc *FileCryptoConfig) chunkSize() int {
	if fcc == nil || fcc.ChunkSize <= 0 {
		return defaultEncryptedChunkSize
	}
	return fcc.ChunkSize
}

func (fcc *FileCryptoConfig) aad(fileID string) []byte {
	if fcc == nil || fcc.AADPrefix == "" {
		return nil
	}
	return []byte(fcc.AADPrefix + fileID)
}

func (fcc *FileCryptoConfig) noncePrefixSize() (int, error) {
	if fcc == nil || fcc.Cipher == nil {
		return 0, nil
	}

	prefixSize := fcc.Cipher.NonceSize() - 8
	if prefixSize <= 0 {
		return 0, fmt.Errorf("media encryption: unsupported nonce size %d", fcc.Cipher.NonceSize())
	}

	return prefixSize, nil
}

func (fcc *FileCryptoConfig) nonce(prefix []byte, chunkID uint64) []byte {
	nonce := make([]byte, len(prefix)+8)
	copy(nonce, prefix)
	binary.BigEndian.PutUint64(nonce[len(prefix):], chunkID)
	return nonce
}

// EncryptStream encrypts media content in chunks before writing it to dst.
// If cfg is nil, the content is copied as-is.
func EncryptStream(dst io.Writer, src io.Reader, cfg *FileCryptoConfig, fileID string) (int64, error) {
	if cfg == nil || cfg.Cipher == nil {
		return io.Copy(dst, src)
	}

	prefixSize, err := cfg.noncePrefixSize()
	if err != nil {
		return 0, err
	}

	header := make([]byte, len(encryptedMediaMagic)+prefixSize)
	copy(header, encryptedMediaMagic)
	if _, err = io.ReadFull(rand.Reader, header[len(encryptedMediaMagic):]); err != nil {
		return 0, fmt.Errorf("media encryption: failed to generate nonce prefix: %w", err)
	}
	if _, err = dst.Write(header); err != nil {
		return 0, err
	}

	prefix := header[len(encryptedMediaMagic):]
	plaintext := make([]byte, cfg.chunkSize())
	aad := cfg.aad(fileID)

	var total int64
	for chunkID := uint64(0); ; chunkID++ {
		n, readErr := io.ReadFull(src, plaintext)
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return total, readErr
		}
		if n == 0 {
			return total, nil
		}

		ciphertext := cfg.Cipher.Seal(nil, cfg.nonce(prefix, chunkID), plaintext[:n], aad)
		if _, err = dst.Write(ciphertext); err != nil {
			return total, err
		}
		total += int64(n)

		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			return total, nil
		}
	}
}

// WrapEncryptedReadSeekCloser returns a read-seek-closer that transparently decrypts encrypted files.
// Plaintext files are returned unchanged to preserve backward compatibility.
func WrapEncryptedReadSeekCloser(file *os.File, cfg *FileCryptoConfig, fileID string) (ReadSeekCloser, error) {
	magic := make([]byte, len(encryptedMediaMagic))
	n, err := io.ReadFull(file, magic)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
			file.Close()
			return nil, seekErr
		}
		return file, nil
	}
	if err != nil {
		file.Close()
		return nil, err
	}
	if n != len(encryptedMediaMagic) || !bytes.Equal(magic, encryptedMediaMagic) {
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			file.Close()
			return nil, err
		}
		return file, nil
	}

	if cfg == nil || cfg.Cipher == nil {
		file.Close()
		return nil, errors.New("media encryption key is not configured")
	}

	prefixSize, err := cfg.noncePrefixSize()
	if err != nil {
		file.Close()
		return nil, err
	}

	prefix := make([]byte, prefixSize)
	if _, err = io.ReadFull(file, prefix); err != nil {
		file.Close()
		return nil, fmt.Errorf("media encryption: failed to read file header: %w", err)
	}

	tmp, err := os.CreateTemp("", "tinode-media-*")
	if err != nil {
		file.Close()
		return nil, err
	}

	cleanup := func(inErr error) (ReadSeekCloser, error) {
		file.Close()
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, inErr
	}

	aad := cfg.aad(fileID)
	encryptedChunk := make([]byte, cfg.chunkSize()+cfg.Cipher.Overhead())

	for chunkID := uint64(0); ; chunkID++ {
		n, readErr := io.ReadFull(file, encryptedChunk)
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return cleanup(readErr)
		}
		if n == 0 {
			break
		}
		if n < cfg.Cipher.Overhead() {
			return cleanup(errors.New("media encryption: encrypted chunk is too short"))
		}

		plaintext, err := cfg.Cipher.Open(nil, cfg.nonce(prefix, chunkID), encryptedChunk[:n], aad)
		if err != nil {
			return cleanup(fmt.Errorf("media encryption: failed to decrypt chunk: %w", err))
		}
		if _, err = tmp.Write(plaintext); err != nil {
			return cleanup(err)
		}

		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			break
		}
	}

	if _, err = tmp.Seek(0, io.SeekStart); err != nil {
		return cleanup(err)
	}
	if err = file.Close(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}

	return &tempReadSeekCloser{File: tmp, path: tmp.Name()}, nil
}
