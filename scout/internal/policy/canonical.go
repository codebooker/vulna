// Package policy verifies Ed25519-signed local policy (and job) documents from
// the orchestrator and enforces the probe's approved scope independently.
package policy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// canonicalBytes returns the canonical JSON encoding of v, byte-for-byte
// identical to the orchestrator's Python canonicalization:
//
//   - object keys sorted (recursively) — Go's encoder sorts string map keys;
//   - compact separators, no insignificant whitespace;
//   - HTML escaping disabled (so <, >, & are literal);
//   - integer fidelity — callers must decode numbers with json.Number;
//   - no trailing newline.
//
// The input must be built from map[string]any / []any / json.Number / string /
// bool (i.e. decoded with a json.Decoder using UseNumber), so every object is a
// map and therefore key-sorted.
func canonicalBytes(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// decodeDocument parses raw JSON into a generic map using json.Number so integer
// values keep their exact textual form for canonicalization.
func decodeDocument(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// DocumentHash returns the SHA-256 hex of a signed document's canonical payload
// (excluding the signature field), matching the orchestrator's document hash.
func DocumentHash(raw []byte) (string, error) {
	doc, err := decodeDocument(raw)
	if err != nil {
		return "", err
	}
	payload := make(map[string]any, len(doc))
	for k, v := range doc {
		if k != signatureField {
			payload[k] = v
		}
	}
	b, err := canonicalBytes(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
