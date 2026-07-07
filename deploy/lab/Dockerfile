# syntax=docker/dockerfile:1

FROM golang:1.25-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /obscura ./cmd/obscura

FROM debian:bookworm-slim AS sing-box
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
	ca-certificates \
	curl \
	&& rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY internal/install/assets.yaml internal/install/assets.yaml
COPY deploy/lab/fetch-sing-box.sh deploy/lab/fetch-sing-box.sh
RUN chmod +x deploy/lab/fetch-sing-box.sh
RUN --mount=type=cache,target=/var/cache/sing-box \
	deploy/lab/fetch-sing-box.sh /sing-box /var/cache/sing-box

FROM jrei/systemd-ubuntu:24.04
ENV container=docker

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
	ufw \
	curl \
	ca-certificates \
	iptables \
	iproute2 \
	jq \
	&& rm -rf /var/lib/apt/lists/*

COPY --from=build /obscura /usr/local/bin/obscura
COPY --from=sing-box /sing-box /usr/local/bin/sing-box
COPY deploy/lab/smoke.sh /usr/local/bin/smoke.sh
RUN chmod +x /usr/local/bin/smoke.sh

CMD ["/sbin/init"]
