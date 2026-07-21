package policy

import "testing"

// pythonPolicyHash is document_hash(policy_payload) computed by the orchestrator
// (dash/backend/app/services/signing.py) for jobVectorPolicy's payload. Matching
// it proves the Go and Python document hashes agree.
const pythonPolicyHash = "5fe8f51ef2cf1606b54f8bfc413b44e421df006bd470a0413625d20ef940c6f1"

func TestDocumentHashMatchesPython(t *testing.T) {
	got, err := DocumentHash([]byte(jobVectorPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if got != pythonPolicyHash {
		t.Errorf("DocumentHash = %s, want %s (cross-language mismatch)", got, pythonPolicyHash)
	}
}
