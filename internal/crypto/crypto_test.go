package crypto

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRoundTrip(t *testing.T) {
	c := testCipher(t)
	for _, plaintext := range []string{"", "hunter2", "a much longer preshared key with spaces"} {
		ciphertext, err := c.Encrypt(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(ciphertext, []byte(plaintext)) && plaintext != "" {
			t.Fatalf("ciphertext contains plaintext %q", plaintext)
		}
		got, err := c.Decrypt(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		if got != plaintext {
			t.Fatalf("got %q, want %q", got, plaintext)
		}
	}
}

func TestEncryptIsRandomized(t *testing.T) {
	c := testCipher(t)
	first, err := c.Encrypt("same")
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.Encrypt("same")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two encryptions of the same plaintext are identical")
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	c := testCipher(t)
	ciphertext, err := c.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext[len(ciphertext)-1] ^= 0xff
	if _, err := c.Decrypt(ciphertext); err != ErrCiphertext {
		t.Fatalf("got %v, want %v", err, ErrCiphertext)
	}
	if _, err := c.Decrypt([]byte{1, 2, 3}); err != ErrCiphertext {
		t.Fatalf("short ciphertext: got %v, want %v", err, ErrCiphertext)
	}
}

func TestDecryptRejectsOtherKey(t *testing.T) {
	ciphertext, err := testCipher(t).Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testCipher(t).Decrypt(ciphertext); err != ErrCiphertext {
		t.Fatalf("got %v, want %v", err, ErrCiphertext)
	}
}

func TestNewRejectsWrongKeySize(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("want error for 16-byte key")
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	want := make([]byte, KeySize)
	for i := range want {
		want[i] = byte(i)
	}

	hexPath := filepath.Join(dir, "hex")
	if err := os.WriteFile(hexPath, []byte(hex.EncodeToString(want)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rawPath := filepath.Join(dir, "raw")
	if err := os.WriteFile(rawPath, want, 0o600); err != nil {
		t.Fatal(err)
	}
	shortPath := filepath.Join(dir, "short")
	if err := os.WriteFile(shortPath, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{hexPath, rawPath} {
		got, err := LoadKey(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s: got %x, want %x", path, got, want)
		}
	}
	if _, err := LoadKey(shortPath); err == nil {
		t.Fatal("want error for undersized key file")
	}
}
