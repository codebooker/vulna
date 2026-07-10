package policy

import (
	"strings"
	"testing"
	"time"
)

// Cross-language vectors: one Python key signs both a policy and a job whose
// target is within the policy's scope (see dash/backend/app/services/signing.py).
const (
	jobVectorPub    = "blvaFuR83ZFZ+AxnSh49WCQWagd2LnnMKaIdZldONJ0="
	jobVectorPolicy = `{"policy_version": 4, "probe_id": "p1", "site_id": "s1", "approved_cidrs": ["10.20.0.0/24"], "denied_cidrs": [], "allow_public_addresses": false, "allowed_modes": ["vulnerability_assessment"], "allowed_plugins": ["nmap"], "limits": {"max_hosts": 256, "max_parallel_hosts": 8, "max_packets_per_second": 1000, "max_duration_seconds": 10800}, "signature": "Roi9CK9tIdbT2emeUi1S7HQu+/j1Vxh6mjCbZciPlgsCgefulC1RXCH2LNKb0yZHZDOoh2tRlLjFANaqfVhLAA=="}`
	jobVectorJob    = `{"job_id": "job-123", "probe_id": "p1", "site_id": "s1", "mode": "vulnerability_assessment", "policy_version": 4, "not_before": "2020-01-01T00:00:00+00:00", "expires_at": "2030-01-01T00:00:00+00:00", "targets": ["10.20.0.5/32"], "workflow": [{"stage": "discovery", "plugin": "nmap", "config": {}}], "limits": {"max_hosts": 256, "max_parallel_hosts": 8, "max_packets_per_second": 1000, "max_duration_seconds": 10800}, "signature": "XXQ96+bIc576ZxinQFEpmstjEUF7DKTKPsKphVjVwfJj05xOyV0Ze+977nTS7noPHUVHXM3x2/RzNfDIdO6NAQ=="}`
)

var withinWindow = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

func jobVectorPolicyParsed(t *testing.T) *Policy {
	t.Helper()
	pub, err := ParsePublicKey(jobVectorPub)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse([]byte(jobVectorPolicy), pub)
	if err != nil {
		t.Fatalf("policy vector failed: %v", err)
	}
	return p
}

func TestVerifyJobAcceptsValid(t *testing.T) {
	pub, _ := ParsePublicKey(jobVectorPub)
	job, err := VerifyJob([]byte(jobVectorJob), pub, jobVectorPolicyParsed(t), withinWindow)
	if err != nil {
		t.Fatalf("valid job rejected: %v", err)
	}
	if job.JobID != "job-123" || job.Mode != "vulnerability_assessment" {
		t.Errorf("unexpected job: %+v", job)
	}
}

func TestVerifyJobRejectsAltered(t *testing.T) {
	pub, _ := ParsePublicKey(jobVectorPub)
	// Tamper with the target after signing.
	altered := strings.Replace(jobVectorJob, "10.20.0.5/32", "10.99.0.5/32", 1)
	if _, err := VerifyJob([]byte(altered), pub, jobVectorPolicyParsed(t), withinWindow); err == nil {
		t.Fatal("expected altered job to be rejected")
	}
}

func TestVerifyJobRejectsExpired(t *testing.T) {
	pub, _ := ParsePublicKey(jobVectorPub)
	afterExpiry := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := VerifyJob([]byte(jobVectorJob), pub, jobVectorPolicyParsed(t), afterExpiry)
	if err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestVerifyJobRejectsNotYetValid(t *testing.T) {
	pub, _ := ParsePublicKey(jobVectorPub)
	beforeStart := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	_, err := VerifyJob([]byte(jobVectorJob), pub, jobVectorPolicyParsed(t), beforeStart)
	if err != ErrNotYetValid {
		t.Fatalf("expected ErrNotYetValid, got %v", err)
	}
}

func TestVerifyJobRejectsOutOfScopeTarget(t *testing.T) {
	// A policy that does not cover the job's target.
	pub, _ := ParsePublicKey(jobVectorPub)
	narrow := jobVectorPolicyParsed(t)
	narrow.approved = narrow.approved[:0] // empty approved scope
	if _, err := VerifyJob([]byte(jobVectorJob), pub, narrow, withinWindow); err == nil {
		t.Fatal("expected out-of-scope target to be rejected")
	}
}

func TestVerifyJobRejectsWrongKey(t *testing.T) {
	// A different (valid) key must not verify this job.
	otherPub, err := ParsePublicKey(vectorPubKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyJob([]byte(jobVectorJob), otherPub, jobVectorPolicyParsed(t), withinWindow); err == nil {
		t.Fatal("expected verification failure with the wrong key")
	}
}
