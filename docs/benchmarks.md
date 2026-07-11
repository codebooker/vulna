# Reference benchmarks

Coarse reference points for what to expect on the three resource tiers. These are
guidance, not guarantees — real timing depends on the network, the targets, and
the preset. See [low-resource](low-resource.md) and the
[support matrix](support-matrix.md).

## Reference hardware

| Tier | Profile | Example | CPU | Memory |
|---|---|---|---|---|
| Constrained | Lite | Raspberry Pi 4 / small VM | 1-2 cores | up to 2 GB |
| Standard | Standard | Mini PC / NUC / VM | 2 cores | 4 GB |
| Large | Full | Server / large VM | 4+ cores | 8 GB+ |

## What "good" looks like

- **Standard preset over a /24** (discovery + service detection + non-intrusive
  vulnerability checks + TLS):
  - Constrained: heavy stages run one at a time; completes without out-of-memory
    termination; expect a longer wall time.
  - Standard: moderate concurrency; completes in minutes to tens of minutes.
  - Large: full concurrency; fastest.
- **Dashboard** stays responsive on the Standard tier for a homelab-sized data set
  (hundreds of assets, thousands of findings).

## How they are used

The release qualification runs small, standard, and constrained reference
benchmarks to catch regressions in resource behavior — most importantly that the
**Lite profile completes the documented safe assessment on the minimum reference
hardware without out-of-memory termination** (see the Phase 27 acceptance
criteria and [low-resource](low-resource.md)).
