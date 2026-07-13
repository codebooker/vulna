package scanners

import (
	"encoding/binary"
	"math"
	"net/netip"
)

// discoveryChunkAddresses is the target number of addresses per scan chunk. One
// /24 per chunk gives operators live, per-subnet results as the scan runs,
// without excessive per-invocation overhead on larger ranges.
const discoveryChunkAddresses = 256

// maxSubdivideParts bounds how many sub-prefixes a single target is split into,
// so a very large supernet doesn't explode into an unreasonable number of
// chunks; beyond it the target is scanned whole.
const maxSubdivideParts = 4096

// ChunkTargets splits scan targets into batches of roughly maxAddrs addresses so
// each batch's results can be uploaded as it completes. IPv4 prefixes larger
// than a chunk are subdivided along /24 boundaries; individual IPs, IPv6
// prefixes, and prefixes already within a chunk pass through. Order is preserved
// and every address in the input appears in exactly one chunk.
func ChunkTargets(targets []string, maxAddrs int) [][]string {
	if maxAddrs <= 0 || len(targets) == 0 {
		return [][]string{targets}
	}
	units := make([]string, 0, len(targets))
	for _, t := range targets {
		units = append(units, subdivide(t, maxAddrs)...)
	}
	var chunks [][]string
	var cur []string
	curCount := 0
	for _, u := range units {
		n := unitSize(u)
		if curCount > 0 && curCount+n > maxAddrs {
			chunks = append(chunks, cur)
			cur = nil
			curCount = 0
		}
		cur = append(cur, u)
		curCount += n
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	if len(chunks) == 0 {
		return [][]string{targets}
	}
	return chunks
}

// subdivide splits an IPv4 prefix wider than maxAddrs into /24-aligned
// sub-prefixes. Anything else — an IP, an IPv6 prefix, a prefix already within
// maxAddrs, or one that would exceed maxSubdivideParts pieces — passes through
// unchanged.
func subdivide(target string, maxAddrs int) []string {
	p, err := netip.ParsePrefix(target)
	if err != nil || !p.Addr().Is4() {
		return []string{target}
	}
	p = p.Masked()
	if prefixSize(p) <= maxAddrs {
		return []string{p.String()}
	}
	const subBits = 24
	if p.Bits() >= subBits {
		return []string{p.String()}
	}
	parts := 1 << (subBits - p.Bits())
	if parts > maxSubdivideParts {
		return []string{p.String()}
	}
	out := make([]string, 0, parts)
	addr := p.Addr()
	for i := 0; i < parts; i++ {
		out = append(out, netip.PrefixFrom(addr, subBits).String())
		addr = addUint32(addr, 256) // advance one /24
	}
	return out
}

// unitSize is the number of addresses a chunk unit (an IP or a prefix) covers.
func unitSize(u string) int {
	if _, err := netip.ParseAddr(u); err == nil {
		return 1
	}
	if p, err := netip.ParsePrefix(u); err == nil {
		return prefixSize(p)
	}
	return 1
}

// prefixSize is the address count of a prefix, capped to avoid overflow.
func prefixSize(p netip.Prefix) int {
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits <= 0 {
		return 1
	}
	if hostBits >= 31 {
		return math.MaxInt32
	}
	return 1 << hostBits
}

// addUint32 advances an IPv4 address by n (used to step across /24 boundaries).
func addUint32(a netip.Addr, n uint32) netip.Addr {
	b := a.As4()
	binary.BigEndian.PutUint32(b[:], binary.BigEndian.Uint32(b[:])+n)
	return netip.AddrFrom4(b)
}
