package policy

import "testing"

// pythonPolicyHash is document_hash(policy_payload) computed by the orchestrator
// (dash/backend/app/services/signing.py) for jobVectorPolicy's payload. Matching
// it proves the Go and Python document hashes agree.
const pythonPolicyHash = "3c6ab1a703ee46847890461dc2c8cf6f62a398e239159aabaa7bf6a120cdff45"

func TestDocumentHashMatchesPython(t *testing.T) {
	got, err := DocumentHash([]byte(jobVectorPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if got != pythonPolicyHash {
		t.Errorf("DocumentHash = %s, want %s (cross-language mismatch)", got, pythonPolicyHash)
	}
}
