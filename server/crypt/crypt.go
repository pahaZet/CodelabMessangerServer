package crypt

import (
	"io"
	"os"
)

// Handler initializes a pluggable encryption backend.
type Handler interface {
	Init(jsconf string) error
}

// MessageHandler encrypts and decrypts stored message payloads.
type MessageHandler interface {
	EncryptMessage(field string, raw []byte) ([]byte, error)
	DecryptMessage(field string, raw []byte) ([]byte, bool, error)
}

// ReadSeekCloser is used for decrypted file content.
type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
}

// FileHandler encrypts and decrypts uploaded file content.
type FileHandler interface {
	EncryptFile(dst io.Writer, src io.Reader, fileID string) (int64, error)
	DecryptFile(file *os.File, fileID string) (ReadSeekCloser, bool, error)
}
