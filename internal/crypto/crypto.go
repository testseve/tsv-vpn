package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

const KeySize = 32

var ErrCiphertext = errors.New("ciphertext is malformed")

type Cipher struct {
	aead cipher.AEAD
}

func New(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("master key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// The key file is 64 hex characters ("openssl rand -hex 32") or 32 raw bytes.
func LoadKey(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == hex.EncodedLen(KeySize) {
		key, err := hex.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("master key file %s: %w", path, err)
		}
		return key, nil
	}
	if len(raw) == KeySize {
		return raw, nil
	}
	return nil, fmt.Errorf("master key file %s: want %d hex characters or %d raw bytes", path, hex.EncodedLen(KeySize), KeySize)
}

func NewKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

func (c *Cipher) Encrypt(plaintext string) ([]byte, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return c.aead.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

func (c *Cipher) Decrypt(ciphertext []byte) (string, error) {
	if len(ciphertext) < c.aead.NonceSize() {
		return "", ErrCiphertext
	}
	nonce, sealed := ciphertext[:c.aead.NonceSize()], ciphertext[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return "", ErrCiphertext
	}
	return string(plaintext), nil
}
