# Support matrix

The environments Vulna is tested on and supports. It is deliberately limited to
what the project can test continuously — a small, honest matrix beats a long,
untested one. The machine-readable version is
[`deploy/release/support-matrix.json`](../deploy/release/support-matrix.json).

## Operating systems

| Distribution | Versions | Tier |
|---|---|---|
| Ubuntu | 22.04 LTS, 24.04 LTS | official |
| Debian | 12 | official |
| Fedora | 40 | community |

## Container runtime

- Docker Engine 24.0+ with Compose v2.20+.
- Podman with a compatible Compose is community-tier.

## Architectures

`amd64` and `arm64`. Official Scout and installer builds ship for both.

## Single-host resource tiers

| Tier | Profile | CPU | Memory | Disk |
|---|---|---|---|---|
| Constrained | Lite | 1-2 cores | up to 2 GB | 10 GB |
| Standard | Standard | 2 cores | 4 GB | 20 GB |
| Large | Full | 4+ cores | 8 GB+ | 40 GB+ |

See [low-resource](low-resource.md) and [benchmarks](benchmarks.md).

## Browsers

Current Firefox (+ESR), Chrome/Chromium, Safari, and Edge.

## Compatibility

- A VulnaScout must be within **one minor version** of VulnaDash.
- Signed job/policy formats are versioned; a Scout verifies before running.

## Scanners

| Scanner | Minimum |
|---|---|
| nmap | 7.80 |
| Nuclei | 3.0 |
| testssl.sh | 3.0 |
| OWASP ZAP | 2.14 |

## Release channels

- **stable** — minor releases; the current and one prior minor are supported.
- **maintenance** — security/critical fixes only; a slower-moving channel enabled
  once the project has capacity.

See [release process](release-process.md).
