package winrm_inventory

import (
	"context"
	"strings"
	"testing"

	"github.com/codebooker/vulna/scout/internal/policy"
)

type fakeTransport struct {
	calls      int
	credential policy.Credential
}

func (f *fakeTransport) Collect(
	_ context.Context, _ string, credential policy.Credential,
) ([]byte, error) {
	f.calls++
	f.credential = credential
	return []byte(`{"operating_system":{"name":"Windows Server 2022","version":"10.0"},"packages":[{"name":"Vulna Agent","package_key":"vulna agent","version":"1.0","architecture":"x64","product_key":"vulna agent"}]}`), nil
}

func TestWorkerNormalizesInventoryWithoutLeakingCredential(t *testing.T) {
	transport := &fakeTransport{}
	job := &policy.Job{
		Targets: []string{"192.0.2.20"},
		Credentials: []policy.Credential{{
			Protocol: "winrm", AuthType: "password", Username: "administrator", Secret: "do-not-return",
		}},
	}
	result, err := NewWorkerWithTransport(transport).Run(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if transport.calls != 1 || transport.credential.Secret != "do-not-return" {
		t.Fatal("worker did not pass the in-memory credential exactly once")
	}
	if strings.Contains(string(result), "do-not-return") || strings.Contains(string(result), "administrator") {
		t.Fatal("collector output leaked credentials")
	}
	if !strings.Contains(string(result), "Windows Server 2022") || !strings.Contains(string(result), "Vulna Agent") {
		t.Fatalf("unexpected normalized payload: %s", result)
	}
}

func TestWorkerRejectsRangeAndUnsupportedAuthentication(t *testing.T) {
	transport := &fakeTransport{}
	rangeJob := &policy.Job{
		Targets: []string{"192.0.2.0/24"},
		Credentials: []policy.Credential{{
			Protocol: "winrm", AuthType: "password", Username: "user", Secret: "secret",
		}},
	}
	if _, err := NewWorkerWithTransport(transport).Run(context.Background(), rangeJob); err == nil {
		t.Fatal("network range was accepted")
	}
	wrongAuth := &policy.Job{
		Targets: []string{"192.0.2.20"},
		Credentials: []policy.Credential{{
			Protocol: "winrm", AuthType: "ssh_private_key", Username: "user", Secret: "secret",
		}},
	}
	if _, err := NewWorkerWithTransport(transport).Run(context.Background(), wrongAuth); err == nil {
		t.Fatal("unsupported WinRM authentication was accepted")
	}
	if transport.calls != 0 {
		t.Fatal("transport ran for a rejected job")
	}
}
