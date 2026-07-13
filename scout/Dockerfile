# syntax=docker/dockerfile:1

# ---- Build ----
FROM golang:1.24-alpine@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS build
WORKDIR /src
# Cache modules first (no external deps yet, but keeps the layer stable).
COPY go.mod ./
RUN go mod download
COPY . .
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

# ---- Runtime (minimal, non-root) ----
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS runtime
RUN addgroup -S vulna && adduser -S -G vulna -u 10001 vulna
COPY --from=build /out/vulnascout /usr/local/bin/vulnascout
USER vulna
ENTRYPOINT ["vulnascout"]
CMD ["self-test"]
