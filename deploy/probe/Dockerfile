# VulnaScout probe image. Build from the repository root:
#   docker build -f deploy/probe/Dockerfile -t vulnascout .
#
# The probe is a static, CGO-free binary. Nmap ships in the image for the
# discovery stage. ZAP ships too so passive web analysis automatically follows
# discovered HTTP(S) services; Nuclei/testssl.sh remain optional and, when absent,
# their workflow stages are skipped. Buildx builds
# linux/amd64 and linux/arm64 (Raspberry Pi-class) from the same file.
# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.22-bookworm@sha256:3d699e4d15d0f8f13c9195c0632a16702b8cbdece2955af1c23b37ae5d55a253 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY scout/ ./scout/
WORKDIR /src/scout
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/vulnascout ./cmd/vulnascout

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS tools
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
ARG ZAP_VERSION=2.17.0
ARG ZAP_SHA256=efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a
RUN set -eu; \
    curl -fsSL -o /tmp/zap.tar.gz \
      "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz"; \
    echo "${ZAP_SHA256}  /tmp/zap.tar.gz" | sha256sum -c -; \
    mkdir -p /opt/zap; \
    tar -xzf /tmp/zap.tar.gz -C /opt/zap --strip-components=1; \
    test -x /opt/zap/zap.sh

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin vulna \
    && mkdir -p /var/lib/vulna \
    && chown vulna:vulna /var/lib/vulna
COPY --from=build /out/vulnascout /usr/bin/vulnascout
COPY --from=tools /opt/zap /opt/zap
RUN ln -s /opt/zap/zap.sh /usr/local/bin/zap.sh
USER vulna
ENV VULNA_DATA=/var/lib/vulna \
    VULNA_SCANNER_SANDBOX_HELPER=/usr/bin/vulnascout
VOLUME ["/var/lib/vulna"]
ENTRYPOINT ["/usr/bin/vulnascout"]
CMD ["run"]
