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
FROM golang:1.26-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build
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
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS tools
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
ARG NUCLEI_TEMPLATES_SHA256=34f5f8a24400a4fff33a57806c2fbc842cdf599589f477430800140845e299cb
RUN set -eu; \
    curl -fsSL -o /tmp/nuclei-templates.tar.gz \
      "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz"; \
    echo "${NUCLEI_TEMPLATES_SHA256}  /tmp/nuclei-templates.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/nuclei-templates; \
    tar -xzf /tmp/nuclei-templates.tar.gz -C /opt/nuclei-templates --strip-components=1
# testssl.sh — pinned stable tag.
ARG TESTSSL_VERSION=3.0.9
ARG TESTSSL_SHA256=75ecbe4470e74f9ad17f4c4ac733be123b0f67d676ed24cc2b30adb41561e05f
RUN set -eu; \
    curl -fsSL -o /tmp/testssl.tar.gz \
      "https://github.com/testssl/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz"; \
    echo "${TESTSSL_SHA256}  /tmp/testssl.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/testssl; \
    tar -xzf /tmp/testssl.tar.gz -C /opt/testssl --strip-components=1

# Point nuclei's config at the bundled templates. nuclei resolves RELATIVE
# template/workflow references and helper (wordlist) files against its config's
# templates directory — NOT the -templates flag the Scout passes — so without this
# ~730 of the ~10.5k templates fail to load ("could not find file" / "helper file
# denied"), silently shrinking what the vulnerability stage detects. XDG_CONFIG_HOME
# keeps the config independent of the runtime user's HOME so it survives the copy.
ENV XDG_CONFIG_HOME=/opt/nuclei-config
RUN mkdir -p /opt/nuclei-config/nuclei \
 && printf '{"nuclei-templates-directory":"/opt/nuclei-templates"}' \
      > /opt/nuclei-config/nuclei/.templates-config.json

# Fail the build if the template set does not actually load — a scanner that loads
# zero or a broken template set finds nothing while looking successful. Require a
# healthy template count and keep validation errors within the small intrinsic set
# (upstream templates needing code/py/ruby engines this image doesn't ship).
RUN set -eu; \
    count="$(/out/nuclei -tl -templates /opt/nuclei-templates -disable-update-check -silent 2>/dev/null | grep -c '\.yaml$' || true)"; \
    echo "nuclei: ${count} templates listed"; \
    [ "$count" -ge 5000 ] || { echo "FAIL: too few templates loaded (${count})"; exit 1; }; \
    errs="$(/out/nuclei -validate -templates /opt/nuclei-templates -disable-update-check -no-color 2>&1 | grep -c '^\[ERR\]' || true)"; \
    echo "nuclei: ${errs} template validation errors"; \
    [ "$errs" -le 50 ] || { echo "FAIL: ${errs} validation errors — template dir/version regression"; exit 1; }

# ---- Runtime: scanner pack + Metasploit, still unprivileged (uid 10001) ----
#
# Metasploit ships in the Scout image by default. That is deliberate and safe:
# the engine is inert until VulnaDash authorizes it. Controlled-pentest execution
# requires BOTH the Scout's signed policy to permit controlled_pentest (the
# per-scout "pentest" toggle) AND per-session approval by an approver; DoS and
# non-allowlisted modules are refused locally regardless. So possession of the
# binary grants nothing — authorization does. Bundling it makes "enable pentest"
# a one-click, offline-capable action instead of a runtime download, and the
# engine runs as the same unprivileged uid-10001 user as the scanner pack (its
# connect-based auxiliary modules need no elevated capabilities).
#
# Base: the official Metasploit image (Alpine + Ruby + nmap), pinned by digest
# for reproducibility. VULNA_MSF_CONSOLE (set below) is what activates the
# controlled-pentest worker on the Scout — see scout/internal/cli.
FROM metasploitframework/metasploit-framework@sha256:ba9ecc0172052ea687adb3b3e6356b24dba4497d1bf73a6de0e201f1e25e9777 AS runtime
USER root
RUN apk add --no-cache \
      nmap nmap-scripts \
      bash procps coreutils openssl bind-tools \
      ca-certificates libcap \
 && addgroup -S vulna \
 && adduser -S -G vulna -u 10001 -h /var/lib/vulna vulna \
 # The Metasploit base grants file capabilities (e.g. cap_net_raw on the ruby
 # interpreter) so it can raw-socket as non-root. This scout runs with
 # `cap_drop: ALL` + `no-new-privileges`, under which the kernel REFUSES to exec
 # a capability-bearing file as a non-root user (EPERM) — so msfconsole (a ruby
 # script) would fail to launch. The dropped caps are unusable here anyway and
 # the scanners are connect-based, so strip every file capability to keep the
 # hardened, unprivileged posture while letting the interpreters exec.
 && getcap -r / 2>/dev/null | awk '{print $1}' | while read -r f; do setcap -r "$f" 2>/dev/null || true; done

COPY --from=build /out/vulnascout /usr/local/bin/vulnascout
COPY --from=tools /out/nuclei /usr/local/bin/nuclei
COPY --from=tools /opt/nuclei-templates /opt/nuclei-templates
# The nuclei config that resolves relative template/helper references to the
# bundled pack (see the tools stage); XDG_CONFIG_HOME below activates it. Owned by
# the vulna user because nuclei writes a provider-config there on first run.
COPY --from=tools --chown=vulna:vulna /opt/nuclei-config /opt/nuclei-config
COPY --from=tools /opt/testssl /opt/testssl
RUN ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh
COPY deploy/single-host/local-scout-entrypoint.sh /usr/local/bin/local-scout-entrypoint.sh
RUN chmod +x /usr/local/bin/local-scout-entrypoint.sh

# nuclei writes its config under XDG_CONFIG_HOME; VULNA_NUCLEI_TEMPLATES points the
# Scout's nuclei adapter at the bundled template set (see scanners/nuclei), and
# XDG_CONFIG_HOME points nuclei at the config that resolves its relative template
# and helper references to that same set. VULNA_MSF_CONSOLE points the
# controlled-pentest worker at the bundled msfconsole; the worker only runs a
# module when the signed policy + a per-session approval authorize it.
ENV HOME=/var/lib/vulna \
    XDG_CONFIG_HOME=/opt/nuclei-config \
    VULNA_NUCLEI_TEMPLATES=/opt/nuclei-templates \
    VULNA_MSF_CONSOLE=/usr/src/metasploit-framework/msfconsole
USER vulna
ENTRYPOINT ["/usr/local/bin/local-scout-entrypoint.sh"]
