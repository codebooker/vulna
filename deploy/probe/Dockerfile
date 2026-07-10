# VulnaScout probe image. Build from the repository root:
#   docker build -f deploy/probe/Dockerfile -t vulnascout .
#
# The probe is a static, CGO-free binary. Nmap ships in the image for the
# discovery stage; Nuclei/testssl.sh/ZAP are optional and, when absent, their
# workflow stages are skipped (the adapters degrade gracefully). Buildx builds
# linux/amd64 and linux/arm64 (Raspberry Pi-class) from the same file.
# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.22-bookworm AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY scout/ ./scout/
WORKDIR /src/scout
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/vulnascout ./cmd/vulnascout

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -s /usr/sbin/nologin vulna \
    && mkdir -p /var/lib/vulna \
    && chown vulna:vulna /var/lib/vulna
COPY --from=build /out/vulnascout /usr/bin/vulnascout
USER vulna
ENV VULNA_DATA=/var/lib/vulna
VOLUME ["/var/lib/vulna"]
ENTRYPOINT ["/usr/bin/vulnascout"]
CMD ["run"]
