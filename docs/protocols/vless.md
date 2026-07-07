# VLESS

## What it is

VLESS is a stripped-down successor to VMess. It removes the VMess authentication overhead (the UUID-based time-based MAC), relying entirely on TLS for security. This makes it slightly more efficient and also enables Reality, a TLS extension that makes connections indistinguishable from traffic to a real website. VLESS also supports XTLS Vision flow, which passes TLS-in-TLS directly to bypass deep packet inspection that looks for this pattern.

## When to use

- New deployments where you want the best combination of performance and stealth
- Environments where a domain name is not available: use Reality to mimic a real site
- Environments with DPI that targets TLS-in-TLS: use `--vless-flow xtls-rprx-vision`
- CDN setups with WebSocket or gRPC transport and a real domain

VLESS with Reality is the recommended default for personal VPN servers.

## Quick create

```bash
# With Reality (no domain required, maximum stealth)
sudo obscura vpn create \
  --name vless \
  --protocol vless \
  --reality \
  --reality-handshake www.google.com \
  --client-name phone

sudo obscura client show --vpn vless --name phone --qr
```

## Key options

VLESS uses the same TLS and transport flags as Trojan and VMess. See [TLS and Certificates](../tls-and-certificates.md).

| Flag | Default | Description |
|---|---|---|
| `--reality` | off | Enable Reality extension (no domain required) |
| `--reality-handshake` | (required with `--reality`) | Domain to mimic, e.g. `www.google.com`, `www.apple.com` |
| `--reality-handshake-port` | `443` | Port of the handshake server |
| `--reality-fingerprint` | `chrome` | uTLS fingerprint embedded in client URIs |
| `--vless-flow` | | VLESS flow: `xtls-rprx-vision` for direct TLS DPI bypass |
| `--transport` | | V2Ray transport: `ws`, `grpc`, `http`, `httpupgrade`, `quic` |
| `--acme-domain` | | Enable ACME with a real domain |
| `--multiplex` | off | Enable sing-box multiplex |
| `--multiplex-brutal` | off | Enable TCP Brutal congestion control in multiplex |

## Recipes

### With Reality (recommended for most deployments)

Choose a handshake server that supports TLS 1.3 and has large traffic volume (makes mimicry more convincing):

```bash
sudo obscura vpn create \
  --name vless \
  --protocol vless \
  --reality \
  --reality-handshake www.google.com
```

Good handshake servers: `www.google.com`, `www.apple.com`, `www.microsoft.com`, `www.cloudflare.com`.

### Self-signed TLS (no domain, no Reality)

```bash
sudo obscura vpn create --name vless --protocol vless
```

Simpler than Reality but less stealthy. The self-signed certificate fingerprint is embedded in client URIs.

### With Vision flow (direct TLS DPI bypass)

Vision flow carries the inner TLS connection directly without wrapping, which bypasses firewalls that detect TLS-in-TLS patterns. Requires a real TLS connection (not Reality) with `--vless-flow`:

```bash
sudo obscura vpn create \
  --name vless-vision \
  --protocol vless \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com \
  --vless-flow xtls-rprx-vision
```

### With gRPC transport and ACME

```bash
sudo obscura vpn create \
  --name vless-grpc \
  --protocol vless \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com \
  --transport grpc \
  --transport-service-name grpc
```

### With WebSocket transport (CDN)

```bash
sudo obscura vpn create \
  --name vless-ws \
  --protocol vless \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com \
  --transport ws \
  --transport-path /ws
```

### With multiplex and Brutal congestion control

```bash
sudo obscura vpn create \
  --name vless-mux \
  --protocol vless \
  --reality \
  --reality-handshake www.google.com \
  --multiplex \
  --multiplex-brutal \
  --multiplex-brutal-up-mbps 300 \
  --multiplex-brutal-down-mbps 600
```

### Add clients

```bash
sudo obscura client add --vpn vless --name laptop --qr
```

## Compatible clients

| Platform | App |
|---|---|
| iOS | Shadowrocket, Sing-Box, Hiddify |
| Android | v2rayNG, Hiddify, Sing-Box |
| Windows / macOS / Linux | Clash Verge, Hiddify-Next, v2rayN, sing-box client |
