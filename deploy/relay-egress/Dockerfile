# syntax=docker/dockerfile:1
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
RUN apk add --no-cache curl jq wireguard-tools iproute2 iptables ca-certificates
COPY deploy/relay-egress/controller.sh /usr/local/bin/vulna-relay-egress
RUN chmod 0755 /usr/local/bin/vulna-relay-egress
ENTRYPOINT ["/usr/local/bin/vulna-relay-egress"]
