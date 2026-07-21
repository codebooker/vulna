// Package queue is VulnaScout's durable, on-disk queue of finished result
// batches waiting to be uploaded. On an intermittent WAN link a Scout keeps
// accepted work locally and drains it when connectivity returns; each item
// carries a stable idempotency key so a resend after a lost acknowledgement
// never produces a duplicate observation on the dashboard.
//
// The queue is a directory of one JSON file per item (owner-only), named by the
// item's key so enqueuing the same batch twice is a no-op. A byte cap provides
// backpressure: once the backlog reaches the cap, Enqueue refuses new items so a
// long outage cannot fill the disk.
package queue

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrFull is returned by Enqueue when the durable backlog is at its byte cap.
var ErrFull = errors.New("queue: durable backlog is full")

// Item is one result batch awaiting upload.
type Item struct {
	Key               string `json:"key"`
	JobID             string `json:"job_id"`
	AttemptID         string `json:"attempt_id,omitempty"`
	LeaseID           string `json:"lease_id,omitempty"`
	FencingToken      int64  `json:"fencing_token,omitempty"`
	Stage             string `json:"stage"`
	Scanner           string `json:"scanner"`
	Raw               []byte `json:"raw"`
	Complete          bool   `json:"complete,omitempty"`
	CreatedAtUnixNano int64  `json:"created_at_unix_nano,omitempty"`
}

func itemKey(it Item) string {
	h := sha256.New()
	if it.AttemptID != "" {
		h.Write([]byte(it.AttemptID + "\x00"))
		h.Write([]byte(fmt.Sprintf("%d\x00", it.FencingToken)))
	}
	h.Write([]byte(Key(it.JobID, it.Stage, it.Scanner, it.Raw, it.Complete)))
	return hex.EncodeToString(h.Sum(nil))
}

// Key derives the stable idempotency key for a batch from its content, so the
// same batch always maps to the same queue file and the same server-side key.
func Key(jobID, stage, scanner string, raw []byte, complete ...bool) string {
	h := sha256.New()
	h.Write([]byte(jobID + "\x00" + stage + "\x00" + scanner + "\x00"))
	if len(complete) > 0 && complete[0] {
		h.Write([]byte("1\x00"))
	} else {
		h.Write([]byte("0\x00"))
	}
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// Queue is a durable directory-backed result queue.
type Queue struct {
	dir           string
	maxBytes      int64
	lastCreatedAt int64
	mu            sync.Mutex
}

// Open returns a Queue rooted at dir (created 0700), capped at maxBytes of
// pending payload. A non-positive maxBytes disables the cap.
func Open(dir string, maxBytes int64) (*Queue, error) {
	if dir == "" {
		return nil, errors.New("queue: directory must not be empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	q := &Queue{dir: dir, maxBytes: maxBytes}
	items, err := q.pendingLocked()
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if item.CreatedAtUnixNano > q.lastCreatedAt {
			q.lastCreatedAt = item.CreatedAtUnixNano
		}
	}
	return q, nil
}

func (q *Queue) file(key string) string { return filepath.Join(q.dir, key+".json") }

// Enqueue durably records an item. Enqueuing an item already present is a no-op
// (idempotent). It returns ErrFull when the backlog is at the byte cap.
func (q *Queue) Enqueue(it Item) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if it.Key == "" {
		it.Key = itemKey(it)
	}
	if _, err := os.Stat(q.file(it.Key)); err == nil {
		return nil // already queued
	}
	if it.CreatedAtUnixNano == 0 {
		it.CreatedAtUnixNano = time.Now().UnixNano()
		if it.CreatedAtUnixNano <= q.lastCreatedAt {
			it.CreatedAtUnixNano = q.lastCreatedAt + 1
		}
	}
	if it.CreatedAtUnixNano > q.lastCreatedAt {
		q.lastCreatedAt = it.CreatedAtUnixNano
	}

	if q.maxBytes > 0 {
		_, bytesPending, err := q.backlogLocked()
		if err != nil {
			return err
		}
		if bytesPending+int64(len(it.Raw)) > q.maxBytes {
			return ErrFull
		}
	}

	data, err := json.Marshal(it)
	if err != nil {
		return err
	}
	// Write to a temp file then rename so a crash never leaves a partial item.
	tmp := q.file(it.Key) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, q.file(it.Key))
}

// Pending returns queued items in durable insertion order.
func (q *Queue) Pending() ([]Item, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.pendingLocked()
}

func (q *Queue) pendingLocked() ([]Item, error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	items := make([]Item, 0, len(names))
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(q.dir, name))
		if err != nil {
			return nil, err
		}
		var it Item
		if err := json.Unmarshal(data, &it); err != nil {
			// Never skip past a corrupt result: a later completion marker could
			// otherwise finalize verification without the missing evidence.
			return nil, fmt.Errorf("queue: decode %s: %w", name, err)
		}
		items = append(items, it)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAtUnixNano == items[j].CreatedAtUnixNano {
			return items[i].Key < items[j].Key
		}
		return items[i].CreatedAtUnixNano < items[j].CreatedAtUnixNano
	})
	return items, nil
}

// Backlog returns the number of pending items and their total payload bytes, so
// the Scout can surface the backlog and a storage estimate.
func (q *Queue) Backlog() (count int, bytes int64, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.backlogLocked()
}

func (q *Queue) backlogLocked() (int, int64, error) {
	items, err := q.pendingLocked()
	if err != nil {
		return 0, 0, err
	}
	var total int64
	for _, it := range items {
		total += int64(len(it.Raw))
	}
	return len(items), total, nil
}

// UploadFunc uploads one item; a nil return means the item was accepted.
type UploadFunc func(ctx context.Context, it Item) error

// Drain uploads pending items oldest-first, removing each on success. It stops at
// the first failure (leaving that item and the rest for a later attempt) and
// returns how many were uploaded. Because uploads are idempotent, an item whose
// acknowledgement was lost is safely retried on the next Drain.
func (q *Queue) Drain(ctx context.Context, upload UploadFunc) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	items, err := q.pendingLocked()
	if err != nil {
		return 0, err
	}
	uploaded := 0
	for _, it := range items {
		if err := ctx.Err(); err != nil {
			return uploaded, err
		}
		if err := upload(ctx, it); err != nil {
			return uploaded, err
		}
		if err := os.Remove(q.file(it.Key)); err != nil && !os.IsNotExist(err) {
			return uploaded, err
		}
		uploaded++
	}
	return uploaded, nil
}
