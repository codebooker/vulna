package policy

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
)

const signatureField = "signature"

// ErrUnsigned indicates a document had no signature field.
var ErrUnsigned = errors.New("document has no signature")

// ErrBadSignature indicates signature verification failed.
var ErrBadSignature = errors.New("signature verification failed")

// ParsePublicKey decodes a base64 raw 32-byte Ed25519 public key.
func ParsePublicKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}

// VerifyDocument verifies the Ed25519 signature embedded in a signed document
// and returns the parsed document (numbers as json.Number). The signature
// covers the canonical form of the document with the signature field removed.
func VerifyDocument(raw []byte, pub ed25519.PublicKey) (map[string]any, error) {
	doc, err := decodeDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("parse document: %w", err)
	}
	sigVal, ok := doc[signatureField].(string)
	if !ok || sigVal == "" {
		return nil, ErrUnsigned
	}
	sig, err := base64.StdEncoding.DecodeString(sigVal)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	payload := make(map[string]any, len(doc))
	for k, v := range doc {
		if k != signatureField {
			payload[k] = v
		}
	}
	msg, err := canonicalBytes(payload)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, msg, sig) {
		return nil, ErrBadSignature
	}
	return doc, nil
}
