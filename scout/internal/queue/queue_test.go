package queue

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func item(job, stage, scanner, raw string) Item {
	return Item{JobID: job, Stage: stage, Scanner: scanner, Raw: []byte(raw)}
}

func TestEnqueueDedupesByContent(t *testing.T) {
	q, err := Open(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	it := item("j1", "discovery", "nmap", "<xml/>")
	if err := q.Enqueue(it); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(it); err != nil { // same content -> no-op
		t.Fatal(err)
	}
	count, _, err := q.Backlog()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 item after duplicate enqueue, got %d", count)
	}
}

func TestDrainUploadsOncePerItemAndResumes(t *testing.T) {
	dir := t.TempDir()
	q, _ := Open(dir, 0)
	_ = q.Enqueue(item("j1", "discovery", "nmap", "a"))
	_ = q.Enqueue(item("j1", "vuln", "nuclei", "b"))

	// First drain: the link is "down" -> upload fails immediately.
	calls := 0
	_, err := q.Drain(context.Background(), func(_ context.Context, _ Item) error {
		calls++
		return errors.New("offline")
	})
	if err == nil {
		t.Fatal("expected drain to surface the upload error")
	}
	if calls != 1 {
		t.Fatalf("drain should stop at the first failure, got %d calls", calls)
	}
	// Nothing was removed; the work is preserved.
	if n, _, _ := q.Backlog(); n != 2 {
		t.Fatalf("expected 2 items preserved after failed drain, got %d", n)
	}

	// Reconnect: a fresh Queue over the same dir drains everything, once each.
	q2, _ := Open(dir, 0)
	seen := map[string]int{}
	uploaded, err := q2.Drain(context.Background(), func(_ context.Context, it Item) error {
		seen[it.Key]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if uploaded != 2 {
		t.Fatalf("expected 2 uploaded after reconnect, got %d", uploaded)
	}
	for k, c := range seen {
		if c != 1 {
			t.Fatalf("item %s uploaded %d times, want exactly once", k, c)
		}
	}
	if n, _, _ := q2.Backlog(); n != 0 {
		t.Fatalf("expected empty queue after successful drain, got %d", n)
	}
}

func TestBacklogBytesAndCapProvidesBackpressure(t *testing.T) {
	q, _ := Open(t.TempDir(), 8) // 8-byte cap
	if err := q.Enqueue(item("j1", "s", "nmap", "12345")); err != nil {
		t.Fatal(err)
	}
	_, bytes, _ := q.Backlog()
	if bytes != 5 {
		t.Fatalf("expected 5 backlog bytes, got %d", bytes)
	}
	// Next item would exceed the cap -> ErrFull (backpressure, not a crash).
	if err := q.Enqueue(item("j1", "s2", "nmap", "6789")); !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}
}

func TestKeyIsStableAndContentAddressed(t *testing.T) {
	a := Key("j1", "discovery", "nmap", []byte("x"))
	b := Key("j1", "discovery", "nmap", []byte("x"))
	c := Key("j1", "discovery", "nmap", []byte("y"))
	if a != b {
		t.Fatal("key should be stable for identical content")
	}
	if a == c {
		t.Fatal("key should differ for different content")
	}
}

func TestKeyMatchesVersionedUploadContract(t *testing.T) {
	jobID := "00000000-0000-0000-0000-000000000001"
	if got := Key(jobID, "discovery", "nmap", []byte("<nmaprun/>")); got != "7925f9328a62d64b5240bf5f03dc567a49605b7cef1f0f27e8f9456158fb9bee" {
		t.Fatalf("queue result key drifted: %s", got)
	}
}

func TestEnqueueKeepsDistinctFencedAttempts(t *testing.T) {
	q, _ := Open(t.TempDir(), 0)
	first := item("j1", "discovery", "nmap", "same")
	first.AttemptID, first.LeaseID, first.FencingToken = "a1", "l1", 1
	second := first
	second.AttemptID, second.LeaseID, second.FencingToken = "a2", "l2", 2
	if err := q.Enqueue(first); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(second); err != nil {
		t.Fatal(err)
	}
	if count, _, err := q.Backlog(); err != nil || count != 2 {
		t.Fatalf("expected both fenced attempts in durable queue, count=%d err=%v", count, err)
	}
}

func TestCompletionDrainsAfterEarlierResultBatches(t *testing.T) {
	q, _ := Open(t.TempDir(), 0)
	complete := item("j1", "vuln", "nuclei", "")
	complete.Complete = true
	complete.CreatedAtUnixNano = 20
	result := item("j1", "vuln", "nuclei", "finding")
	result.CreatedAtUnixNano = 10
	// Enqueue in the opposite order to prove persisted timestamps, not content
	// hashes or directory enumeration, define delivery order.
	_ = q.Enqueue(complete)
	_ = q.Enqueue(result)
	var order []bool
	_, err := q.Drain(context.Background(), func(_ context.Context, it Item) error {
		order = append(order, it.Complete)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] || !order[1] {
		t.Fatalf("completion was not delivered last: %v", order)
	}
}

func TestEnqueueOrderRemainsMonotonicAcrossRestartAndClockRollback(t *testing.T) {
	dir := t.TempDir()
	q, _ := Open(dir, 0)
	future := time.Now().Add(24 * time.Hour).UnixNano()
	first := item("j1", "vuln", "nuclei", "finding")
	first.CreatedAtUnixNano = future
	if err := q.Enqueue(first); err != nil {
		t.Fatal(err)
	}

	q, err := Open(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	completion := item("j1", "vuln", "nuclei", "")
	completion.Complete = true
	if err := q.Enqueue(completion); err != nil {
		t.Fatal(err)
	}
	items, err := q.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Complete || !items[1].Complete {
		t.Fatalf("restart reordered completion before its result: %+v", items)
	}
	if items[1].CreatedAtUnixNano <= items[0].CreatedAtUnixNano {
		t.Fatalf("timestamps are not strictly monotonic: %+v", items)
	}
}

func TestOpenRejectsCorruptEntryInsteadOfSkippingToCompletion(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, 0); err == nil {
		t.Fatal("corrupt queued evidence was silently skipped")
	}
}
