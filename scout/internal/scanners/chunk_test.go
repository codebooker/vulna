package scanners

import "testing"

func TestChunkTargets(t *testing.T) {
	cases := []struct {
		name       string
		in         []string
		max        int
		wantChunks int
	}{
		{"single /24 is one chunk", []string{"10.0.0.0/24"}, 256, 1},
		{"/23 splits into two /24 chunks", []string{"10.0.0.0/23"}, 256, 2},
		{
			"seven /24s produce seven chunks",
			[]string{
				"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24",
				"10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24",
			},
			256, 7,
		},
		{"small prefix stays one chunk", []string{"10.0.0.0/28"}, 256, 1},
		{"single ip is one chunk", []string{"10.0.0.5"}, 256, 1},
		{"ipv6 prefix is not subdivided", []string{"2001:db8::/64"}, 256, 1},
		{"zero max yields a single chunk", []string{"10.0.0.0/16"}, 0, 1},
		{"empty input yields a single chunk", nil, 256, 1},
	}
	for _, c := range cases {
		got := ChunkTargets(c.in, c.max)
		if len(got) != c.wantChunks {
			t.Errorf("%s: got %d chunks, want %d: %v", c.name, len(got), c.wantChunks, got)
		}
	}
}

func TestChunkTargetsCoversEveryAddressOnce(t *testing.T) {
	// /22 = four /24s = 1024 addresses; at 256/chunk that is four chunks with no
	// gaps and no overlap.
	chunks := ChunkTargets([]string{"10.0.0.0/22"}, 256)
	if len(chunks) != 4 {
		t.Fatalf("expected 4 chunks, got %d: %v", len(chunks), chunks)
	}
	seen := map[string]bool{}
	for _, ch := range chunks {
		for _, u := range ch {
			if seen[u] {
				t.Errorf("duplicate unit %q across chunks", u)
			}
			seen[u] = true
		}
	}
	for _, want := range []string{"10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"} {
		if !seen[want] {
			t.Errorf("missing sub-prefix %q; got %v", want, chunks)
		}
	}
}
