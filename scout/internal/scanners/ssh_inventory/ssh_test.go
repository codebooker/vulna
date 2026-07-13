package ssh_inventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/codebooker/vulna/scout/internal/policy"
)

type fakeTransport struct {
	commands    []string
	credentials []policy.Credential
}

func (f *fakeTransport) Run(
	_ context.Context, _ string, credential policy.Credential, command string,
) ([]byte, error) {
	f.commands = append(f.commands, command)
	f.credentials = append(f.credentials, credential)
	if len(f.commands) == 1 {
		return []byte("PRETTY_NAME=Ubuntu 24.04 LTS\nVERSION_ID=24.04\n"), nil
	}
	return []byte("openssl\t3.0.13\tamd64\nignored\n"), nil
}

func TestWorkerUsesFixedCommandsAndNormalizesInventory(t *testing.T) {
	transport := &fakeTransport{}
	worker := NewWorkerWithTransport(transport)
	job := &policy.Job{
		Targets: []string{"192.0.2.10/32"},
		Credentials: []policy.Credential{{
			Protocol: "ssh", AuthType: "password", Username: "inventory", Secret: "do-not-return",
		}},
	}

	result, err := worker.Run(context.Background(), job)
	if err != nil {
		t.Fatal(err)
	}
	if len(transport.commands) != len(fixedCommands) {
		t.Fatalf("commands = %d, want %d", len(transport.commands), len(fixedCommands))
	}
	for index, command := range transport.commands {
		if command != fixedCommands[index] {
			t.Fatalf("command %d was not the fixed allowlist value", index)
		}
	}
	if strings.Contains(string(result), "do-not-return") || strings.Contains(string(result), "inventory") {
		t.Fatal("collector output leaked credentials")
	}
	var payload struct {
		OperatingSystem map[string]string   `json:"operating_system"`
		Packages        []map[string]string `json:"packages"`
	}
	if err := json.Unmarshal(result, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.OperatingSystem["version"] != "24.04" || len(payload.Packages) != 1 {
		t.Fatalf("unexpected normalized payload: %+v", payload)
	}
}

func TestWorkerRejectsRangesBeforeTransport(t *testing.T) {
	transport := &fakeTransport{}
	job := &policy.Job{
		Targets: []string{"192.0.2.0/24"},
		Credentials: []policy.Credential{{
			Protocol: "ssh", Username: "inventory", Secret: "secret",
		}},
	}
	if _, err := NewWorkerWithTransport(transport).Run(context.Background(), job); err == nil {
		t.Fatal("network range was accepted")
	}
	if len(transport.commands) != 0 {
		t.Fatal("transport ran for a rejected target")
	}
}
