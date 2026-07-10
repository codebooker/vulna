package secrets

import (
	"encoding/base64"
	"testing"
)

func TestTokenEntropyAndEncoding(t *testing.T) {
	tok, err := Token(32)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("token is not valid base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("expected 32 bytes of entropy, got %d", len(raw))
	}
}

func TestTokenMinimum(t *testing.T) {
	tok, err := Token(1) // below floor
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	if len(raw) < 16 {
		t.Fatalf("token below 16-byte floor: %d", len(raw))
	}
}

func TestUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		p, err := Password()
		if err != nil {
			t.Fatal(err)
		}
		if seen[p] {
			t.Fatal("duplicate secret generated")
		}
		seen[p] = true
	}
}
