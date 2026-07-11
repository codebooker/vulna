# syntax=docker/dockerfile:1
#
# Co-located "local Scout" image for the single-host Vulna deployment (Phase 17).
#
# It is the ordinary VulnaScout probe binary plus the standard scanner capability
# pack (nmap + nuclei + testssl.sh) and an auto-enroll entrypoint. Build context
# is the repository root so the Go sources under scout/ are available.
#
#   docker build -f deploy/single-host/local-scout.Dockerfile -t vulna-local-scout .

# ---- Build the probe binary (stdlib-only, CGO-free) ----
FROM golang:1.26-alpine AS build
WORKDIR /src/scout
COPY scout/go.mod ./
RUN go mod download
COPY scout/ ./
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=0.1.0
ARG COMMIT=unknown
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags "-s -w \
      -X github.com/codebooker/vulna/scout/internal/buildinfo.Version=${VERSION} \
      -X github.com/codebooker/vulna/scout/internal/buildinfo.Commit=${COMMIT} \
      -X github.com/codebooker/vulna/scout/internal/buildinfo.Date=${BUILD_DATE}" \
    -o /out/vulnascout ./cmd/vulnascout

# ---- Fetch the scanner pack (pinned; integrity-checked) ----
FROM alpine:3.21 AS tools
RUN apk add --no-cache curl unzip tar coreutils
# nuclei — verified against the release's own checksums manifest.
ARG NUCLEI_VERSION=3.3.7
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64)  arch=amd64 ;; \
      aarch64) arch=arm64 ;; \
      *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;; \
    esac; \
    base="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}"; \
    zip="nuclei_${NUCLEI_VERSION}_linux_${arch}.zip"; \
    cd /tmp; \
    curl -fsSL -o "$zip" "${base}/${zip}"; \
    curl -fsSL -o nuclei_checksums.txt "${base}/nuclei_${NUCLEI_VERSION}_checksums.txt"; \
    grep " ${zip}\$" nuclei_checksums.txt | sha256sum -c -; \
    unzip -j "$zip" nuclei -d /out; \
    chmod +x /out/nuclei
# nuclei-templates — pinned tag. Bundled so out-of-the-box (and offline) vuln
# scans have templates to match against; without them nuclei loads zero
# templates (update checks are disabled by policy) and every scan finds nothing.
ARG NUCLEI_TEMPLATES_VERSION=10.4.5
RUN set -eu; \
    curl -fsSL -o /tmp/nuclei-templates.tar.gz \
      "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz"; \
    mkdir -p /opt/nuclei-templates; \
    tar -xzf /tmp/nuclei-templates.tar.gz -C /opt/nuclei-templates --strip-components=1
# testssl.sh — pinned stable tag.
ARG TESTSSL_VERSION=3.0.9
RUN set -eu; \
    curl -fsSL -o /tmp/testssl.tar.gz \
      "https://github.com/testssl/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz"; \
    mkdir -p /opt/testssl; \
    tar -xzf /tmp/testssl.tar.gz -C /opt/testssl --strip-components=1

# ---- Runtime (non-root) ----
FROM alpine:3.21 AS runtime
RUN apk add --no-cache \
      nmap nmap-scripts \
      bash procps coreutils openssl bind-tools \
      ca-certificates \
 && addgroup -S vulna \
 && adduser -S -G vulna -u 10001 -h /var/lib/vulna vulna

COPY --from=build /out/vulnascout /usr/local/bin/vulnascout
COPY --from=tools /out/nuclei /usr/local/bin/nuclei
COPY --from=tools /opt/nuclei-templates /opt/nuclei-templates
COPY --from=tools /opt/testssl /opt/testssl
RUN ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
COPY deploy/single-host/local-scout-entrypoint.sh /usr/local/bin/local-scout-entrypoint.sh
RUN chmod +x /usr/local/bin/local-scout-entrypoint.sh

# nuclei writes its config under $HOME; VULNA_NUCLEI_TEMPLATES points the Scout's
# nuclei adapter at the bundled template set (see scanners/nuclei).
ENV HOME=/var/lib/vulna \
    VULNA_NUCLEI_TEMPLATES=/opt/nuclei-templates
USER vulna
ENTRYPOINT ["/usr/local/bin/local-scout-entrypoint.sh"]
