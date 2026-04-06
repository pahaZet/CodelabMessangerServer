package vaulttransit

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	srvcrypt "github.com/tinode/chat/server/crypt"
	"github.com/tinode/chat/server/store"
)

const (
	handlerName             = "vaulttransit"
	defaultTransitMount     = "transit"
	defaultTimeoutSeconds   = 10
	defaultFileChunkSize    = 64 * 1024
	transitMessageVersion   = 1
	transitFileVersion      = 1
	vaultTransitMediaMagic  = "TINODE_MEDIA_VAULT_V1\x00"
	transitEnvelopeJSONKey  = "__tinode_vault_transit_message_enc"
)

type configType struct {
	Address       string `json:"address"`
	Token         string `json:"token"`
	Namespace     string `json:"namespace"`
	TransitMount  string `json:"transit_mount"`
	MessageKey    string `json:"message_key"`
	FileKey       string `json:"file_key"`
	Timeout       int    `json:"timeout"`
	ChunkSize     int    `json:"chunk_size"`
	TLSSkipVerify bool   `json:"tls_skip_verify"`
	TLSCAFile     string `json:"tls_ca_file"`
}

type handler struct {
	conf       configType
	client     *http.Client
	baseURL    string
	mediaMagic []byte
}

type transitEncryptRequest struct {
	Plaintext string `json:"plaintext"`
}

type transitDecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
}

type transitEncryptResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

type transitDecryptResponse struct {
	Data struct {
		Plaintext string `json:"plaintext"`
	} `json:"data"`
	Errors []string `json:"errors"`
}

type storedMessageEnvelope struct {
	Payload *storedMessagePayload `json:"__tinode_vault_transit_message_enc,omitempty"`
}

type storedMessagePayload struct {
	Version    int    `json:"v"`
	Field      string `json:"f"`
	Ciphertext string `json:"c"`
}

type transitMessagePlaintext struct {
	Version int    `json:"v"`
	Field   string `json:"f"`
	Data    string `json:"d"`
}

type transitFileChunkPlaintext struct {
	Version int    `json:"v"`
	FileID  string `json:"f"`
	ChunkID uint64 `json:"i"`
	Data    string `json:"d"`
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

func (h *handler) Init(jsconf string) error {
	h.conf = configType{}
	if err := json.Unmarshal([]byte(jsconf), &h.conf); err != nil {
		return errors.New("failed to parse config: " + err.Error())
	}

	h.conf.Address = strings.TrimSpace(h.conf.Address)
	if h.conf.Address == "" {
		return errors.New("missing address")
	}
	if h.conf.Token == "" {
		return errors.New("missing token")
	}
	if h.conf.MessageKey == "" {
		return errors.New("missing message_key")
	}
	if h.conf.FileKey == "" {
		return errors.New("missing file_key")
	}
	if h.conf.TransitMount == "" {
		h.conf.TransitMount = defaultTransitMount
	}
	if h.conf.Timeout <= 0 {
		h.conf.Timeout = defaultTimeoutSeconds
	}
	if h.conf.ChunkSize <= 0 {
		h.conf.ChunkSize = defaultFileChunkSize
	}

	parsed, err := url.Parse(h.conf.Address)
	if err != nil {
		return fmt.Errorf("invalid address: %w", err)
	}
	h.baseURL = strings.TrimRight(parsed.String(), "/")
	h.mediaMagic = []byte(vaultTransitMediaMagic)

	transport := &http.Transport{}
	if h.conf.TLSSkipVerify || h.conf.TLSCAFile != "" {
		tlsConfig := &tls.Config{InsecureSkipVerify: h.conf.TLSSkipVerify}
		if h.conf.TLSCAFile != "" {
			caPem, err := os.ReadFile(h.conf.TLSCAFile)
			if err != nil {
				return fmt.Errorf("failed to read tls_ca_file: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(caPem) {
				return errors.New("failed to parse tls_ca_file")
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}

	h.client = &http.Client{
		Timeout:   time.Duration(h.conf.Timeout) * time.Second,
		Transport: transport,
	}
	return nil
}

func (h *handler) EncryptMessage(field string, raw []byte) ([]byte, error) {
	if raw == nil {
		return nil, nil
	}

	plaintext, err := json.Marshal(&transitMessagePlaintext{
		Version: transitMessageVersion,
		Field:   field,
		Data:    base64.StdEncoding.EncodeToString(raw),
	})
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: failed to encode %s plaintext: %w", field, err)
	}

	ciphertext, err := h.encrypt(h.conf.MessageKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: failed to encrypt %s: %w", field, err)
	}

	envelope, err := json.Marshal(&storedMessageEnvelope{
		Payload: &storedMessagePayload{
			Version:    transitMessageVersion,
			Field:      field,
			Ciphertext: ciphertext,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: failed to marshal %s envelope: %w", field, err)
	}

	return envelope, nil
}

func (h *handler) DecryptMessage(field string, raw []byte) ([]byte, bool, error) {
	envelope, handled, err := parseStoredMessageEnvelope(raw)
	if err != nil || !handled {
		return nil, handled, err
	}

	if envelope.Field != "" && envelope.Field != field {
		return nil, true, fmt.Errorf("vaulttransit: encrypted message field mismatch: got %q, want %q", envelope.Field, field)
	}

	plaintext, err := h.decrypt(h.conf.MessageKey, envelope.Ciphertext)
	if err != nil {
		return nil, true, fmt.Errorf("vaulttransit: failed to decrypt %s: %w", field, err)
	}

	var decoded transitMessagePlaintext
	if err = json.Unmarshal(plaintext, &decoded); err != nil {
		return nil, true, fmt.Errorf("vaulttransit: failed to decode %s plaintext: %w", field, err)
	}
	if decoded.Version != transitMessageVersion {
		return nil, true, fmt.Errorf("vaulttransit: unsupported %s version %d", field, decoded.Version)
	}
	if decoded.Field != field {
		return nil, true, fmt.Errorf("vaulttransit: decrypted message field mismatch: got %q, want %q", decoded.Field, field)
	}

	plainRaw, err := base64.StdEncoding.DecodeString(decoded.Data)
	if err != nil {
		return nil, true, fmt.Errorf("vaulttransit: invalid %s payload encoding: %w", field, err)
	}

	return plainRaw, true, nil
}

func (h *handler) EncryptFile(dst io.Writer, src io.Reader, fileID string) (int64, error) {
	if _, err := dst.Write(h.mediaMagic); err != nil {
		return 0, err
	}

	buf := make([]byte, h.conf.ChunkSize)
	var total int64
	for chunkID := uint64(0); ; chunkID++ {
		n, readErr := io.ReadFull(src, buf)
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return total, readErr
		}
		if n == 0 {
			return total, nil
		}

		plaintext, err := json.Marshal(&transitFileChunkPlaintext{
			Version: transitFileVersion,
			FileID:  fileID,
			ChunkID: chunkID,
			Data:    base64.StdEncoding.EncodeToString(buf[:n]),
		})
		if err != nil {
			return total, fmt.Errorf("vaulttransit: failed to encode file chunk: %w", err)
		}

		ciphertext, err := h.encrypt(h.conf.FileKey, plaintext)
		if err != nil {
			return total, fmt.Errorf("vaulttransit: failed to encrypt file chunk: %w", err)
		}

		if len(ciphertext) > int(^uint32(0)) {
			return total, errors.New("vaulttransit: encrypted file chunk is too large")
		}

		var sizeBuf [4]byte
		binary.BigEndian.PutUint32(sizeBuf[:], uint32(len(ciphertext)))
		if _, err = dst.Write(sizeBuf[:]); err != nil {
			return total, err
		}
		if _, err = io.WriteString(dst, ciphertext); err != nil {
			return total, err
		}
		total += int64(n)

		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			return total, nil
		}
	}
}

func (h *handler) DecryptFile(file *os.File, fileID string) (srvcrypt.ReadSeekCloser, bool, error) {
	header := make([]byte, len(h.mediaMagic))
	n, err := io.ReadFull(file, header)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		if _, seekErr := file.Seek(0, io.SeekStart); seekErr != nil {
			file.Close()
			return nil, false, seekErr
		}
		return file, false, nil
	}
	if err != nil {
		file.Close()
		return nil, true, err
	}

	if n != len(h.mediaMagic) || !bytes.Equal(header, h.mediaMagic) {
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			file.Close()
			return nil, false, err
		}
		return file, false, nil
	}

	tmp, err := os.CreateTemp("", "tinode-vault-media-*")
	if err != nil {
		file.Close()
		return nil, true, err
	}

	cleanup := func(inErr error) (srvcrypt.ReadSeekCloser, bool, error) {
		file.Close()
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, true, inErr
	}

	var chunkLenBuf [4]byte
	for chunkID := uint64(0); ; chunkID++ {
		_, err = io.ReadFull(file, chunkLenBuf[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return cleanup(err)
		}

		chunkLen := binary.BigEndian.Uint32(chunkLenBuf[:])
		if chunkLen == 0 {
			return cleanup(errors.New("vaulttransit: encrypted file chunk length is zero"))
		}

		ciphertext := make([]byte, chunkLen)
		if _, err = io.ReadFull(file, ciphertext); err != nil {
			return cleanup(err)
		}

		plaintext, err := h.decrypt(h.conf.FileKey, string(ciphertext))
		if err != nil {
			return cleanup(fmt.Errorf("vaulttransit: failed to decrypt file chunk: %w", err))
		}

		var decoded transitFileChunkPlaintext
		if err = json.Unmarshal(plaintext, &decoded); err != nil {
			return cleanup(fmt.Errorf("vaulttransit: failed to decode file chunk: %w", err))
		}
		if decoded.Version != transitFileVersion {
			return cleanup(fmt.Errorf("vaulttransit: unsupported file chunk version %d", decoded.Version))
		}
		if decoded.FileID != fileID {
			return cleanup(fmt.Errorf("vaulttransit: decrypted file id mismatch: got %q, want %q", decoded.FileID, fileID))
		}
		if decoded.ChunkID != chunkID {
			return cleanup(fmt.Errorf("vaulttransit: decrypted file chunk mismatch: got %d, want %d", decoded.ChunkID, chunkID))
		}

		chunkPlaintext, err := base64.StdEncoding.DecodeString(decoded.Data)
		if err != nil {
			return cleanup(fmt.Errorf("vaulttransit: invalid file chunk encoding: %w", err))
		}
		if _, err = tmp.Write(chunkPlaintext); err != nil {
			return cleanup(err)
		}
	}

	if _, err = tmp.Seek(0, io.SeekStart); err != nil {
		return cleanup(err)
	}
	if err = file.Close(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, true, err
	}

	return &tempReadSeekCloser{File: tmp, path: tmp.Name()}, true, nil
}

func (h *handler) encrypt(key string, plaintext []byte) (string, error) {
	reqBody, err := json.Marshal(&transitEncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	})
	if err != nil {
		return "", err
	}

	respBody, err := h.doRequest("encrypt", key, reqBody)
	if err != nil {
		return "", err
	}

	var resp transitEncryptResponse
	if err = json.Unmarshal(respBody, &resp); err != nil {
		return "", err
	}
	if len(resp.Errors) > 0 {
		return "", errors.New(strings.Join(resp.Errors, "; "))
	}
	if resp.Data.Ciphertext == "" {
		return "", errors.New("empty ciphertext returned by vault transit")
	}

	return resp.Data.Ciphertext, nil
}

func (h *handler) decrypt(key, ciphertext string) ([]byte, error) {
	reqBody, err := json.Marshal(&transitDecryptRequest{Ciphertext: ciphertext})
	if err != nil {
		return nil, err
	}

	respBody, err := h.doRequest("decrypt", key, reqBody)
	if err != nil {
		return nil, err
	}

	var resp transitDecryptResponse
	if err = json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	if len(resp.Errors) > 0 {
		return nil, errors.New(strings.Join(resp.Errors, "; "))
	}
	if resp.Data.Plaintext == "" {
		return nil, errors.New("empty plaintext returned by vault transit")
	}

	return base64.StdEncoding.DecodeString(resp.Data.Plaintext)
}

func (h *handler) doRequest(operation, key string, body []byte) ([]byte, error) {
	endpoint := h.baseURL + path.Join("/v1", strings.Trim(h.conf.TransitMount, "/"), operation, url.PathEscape(key))
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", h.conf.Token)
	if h.conf.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", h.conf.Namespace)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		if len(respBody) == 0 {
			return nil, fmt.Errorf("vaulttransit: request failed with status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("vaulttransit: request failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	return respBody, nil
}

func parseStoredMessageEnvelope(raw []byte) (*storedMessagePayload, bool, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, false, nil
	}

	var envelope storedMessageEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, false, nil
	}
	if envelope.Payload == nil {
		return nil, false, nil
	}
	return envelope.Payload, true, nil
}

func init() {
	store.RegisterCryptoHandler(handlerName, &handler{})
}
