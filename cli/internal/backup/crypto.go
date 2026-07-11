// Package backup creates, verifies, encrypts, and restores Vulna backups. It
// adds a versioned manifest, authenticated encryption, and safety checks on top
// of the checksummed archive produced by deploy/backup/backup.sh.
//
// Encryption is AES-256-GCM with a key derived from a user-controlled recovery
// passphrase via PBKDF2-HMAC-SHA256 (implemented from the standard library so the
// CLI stays dependency-free). The passphrase and derived key are never written to
// the manifest, logs, or the bundle.
package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// EncAlgo/KDF identify the scheme recorded in the manifest (no secrets).
	EncAlgo = "aes-256-gcm"
	KDF     = "pbkdf2-hmac-sha256"
	// Iterations for PBKDF2. High enough to be costly to brute-force a passphrase.
	Iterations = 200_000

	saltLen  = 16
	nonceLen = 12
	keyLen   = 32
)

// Encrypt seals plaintext with a key derived from passphrase. The output is
// salt || nonce || ciphertext+tag, self-describing for Decrypt.
func Encrypt(plaintext, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("a recovery passphrase is required to encrypt a backup")
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	gcm, err := newGCM(passphrase, salt)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, saltLen+nonceLen+len(ct))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// Decrypt opens a bundle produced by Encrypt. A wrong passphrase or any tampering
// fails authentication and returns an error (never partial plaintext).
func Decrypt(data, passphrase []byte) ([]byte, error) {
	if len(data) < saltLen+nonceLen {
		return nil, fmt.Errorf("encrypted bundle is truncated")
	}
	salt := data[:saltLen]
	nonce := data[saltLen : saltLen+nonceLen]
	ct := data[saltLen+nonceLen:]
	gcm, err := newGCM(passphrase, salt)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: wrong passphrase or corrupted backup")
	}
	return pt, nil
}

func newGCM(passphrase, salt []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(pbkdf2SHA256(passphrase, salt, Iterations, keyLen))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// pbkdf2SHA256 is a standard-library PBKDF2-HMAC-SHA256 (RFC 2898) so the CLI
// needs no third-party dependency.
func pbkdf2SHA256(password, salt []byte, iter, keyLength int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLength + hashLen - 1) / hashLen
	var dk []byte
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Write(buf)
		u := prf.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for x := range t {
				t[x] ^= u[x]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLength]
}
