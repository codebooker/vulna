// Package secrets generates cryptographically strong values for the generated
// deployment configuration. Secrets are never logged and are written only to
// restrictive (0600) files by the caller.
package secrets

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// Token returns a URL-safe, base64 secret with at least nBytes of entropy.
func Token(nBytes int) (string, error) {
	if nBytes < 16 {
		nBytes = 16
	}
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Password returns a strong password suitable for an initial admin or database
// account (32 bytes of entropy, ~43 URL-safe characters).
func Password() (string, error) {
	return Token(32)
}

// SessionKey returns a 48-byte signing secret for JWT/session tokens.
func SessionKey() (string, error) {
	return Token(48)
}
