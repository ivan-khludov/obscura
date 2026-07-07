# VMess

## What it is

VMess is the original V2Ray proxy protocol. It wraps traffic in TLS and supports a range of V2Ray transport layers (WebSocket, gRPC, HTTP, HTTPUpgrade, QUIC). VMess includes its own lightweight authentication layer on top of TLS. It is widely supported across all major proxy client apps and has a large ecosystem of configuration tools.

## When to use

- When compatibility with V2Ray-based client apps and infrastructure is required
- When flexible transport options are needed (WebSocket for CDN, gRPC for multiplexed streams)
- Trusted internal networks where you want to disable TLS overhead (`--vmess-no-tls` equivalent via plain TCP transport)
- When multiplex or brutal congestion control is needed alongside a flexible transport

VLESS is generally preferred over VMess for new deployments because it removes the VMess authentication overhead and supports Reality. Consider VMess if you need backward compatibility with older clients.

## Quick create

```bash
sudo obscura vpn create --name vmess --protocol vmess --client-name phone
sudo obscura client show --vpn vmess --name phone --qr
```

## Key options

VMess uses the same TLS and transport flags as Trojan. See [TLS and Certificates](../tls-and-certificates.md).

| Flag | Description |
|---|---|
| `--transport` | V2Ray transport: `ws`, `grpc`, `http`, `httpupgrade`, `quic` |
| `--transport-path` | HTTP path for `ws` or `http` transport |
| `--transport-host` | Host header for `ws` or `http` transport |
| `--transport-service-name` | gRPC service name |
| `--acme-domain` | Enable ACME for a real domain certificate |
| `--acme-email` | ACME account email |
| `--multiplex` | Enable sing-box multiplex |
| `--multiplex-brutal` | Enable TCP Brutal congestion control in multiplex |
| `--multiplex-brutal-up-mbps` | Upload bandwidth for Brutal CC (Mbps) |
| `--multiplex-brutal-down-mbps` | Download bandwidth for Brutal CC (Mbps) |

## Recipes

### Standard VMess with TLS

Obscura auto-generates a self-signed certificate. The fingerprint is embedded in the client URI:

```bash
sudo obscura vpn create --name vmess --protocol vmess
```

### With WebSocket transport (CDN-compatible)

WebSocket transport allows traffic to pass through a CDN. Configure the CDN to forward WebSocket connections:

```bash
sudo obscura vpn create \
  --name vmess-ws \
  --protocol vmess \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com \
  --transport ws \
  --transport-path /api
```

### With gRPC transport

gRPC provides better multiplexing than WebSocket for high-concurrency workloads. Some CDNs support gRPC proxying:

```bash
sudo obscura vpn create \
  --name vmess-grpc \
  --protocol vmess \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com \
  --transport grpc \
  --transport-service-name grpc
```

### With multiplex and Brutal congestion control

Multiplex reduces TCP handshake overhead. Brutal CC allows saturating the link by specifying the available bandwidth:

```bash
sudo obscura vpn create \
  --name vmess-mux \
  --protocol vmess \
  --multiplex \
  --multiplex-brutal \
  --multiplex-brutal-up-mbps 200 \
  --multiplex-brutal-down-mbps 500
```

### Add multiple clients

```bash
sudo obscura client add --vpn vmess --name laptop
sudo obscura client add --vpn vmess --name tablet --qr
```

## Compatible clients

| Platform | App |
|---|---|
| iOS | Shadowrocket, Sing-Box, Hiddify |
| Android | v2rayNG, Hiddify, Sing-Box |
| Windows / macOS / Linux | Clash Verge, Hiddify-Next, v2rayN, sing-box client |
