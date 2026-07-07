# Trojan

## What it is

Trojan is a proxy protocol that tunnels traffic over TLS, making it indistinguishable from ordinary HTTPS traffic. Unlike Shadowsocks, Trojan requires TLS, but in return the connection looks exactly like a web server to passive observers. Clients that send invalid credentials receive a fallback response, further hiding the presence of a proxy.

## When to use

- Environments where Shadowsocks-like random noise is blocked but HTTPS traffic passes freely
- Servers with a real domain name where ACME certificates can make the TLS look legitimate
- Behind a CDN such as Cloudflare, when combined with WebSocket transport and a fallback stub
- When you want a proxy that responds to port scans with real HTTP content (via fallback)

## Quick create

```bash
# Self-signed TLS (no domain required)
sudo obscura vpn create --name trojan --protocol trojan --client-name phone
```

## Key options

TLS flags are shared with VMess and VLESS. See [TLS and Certificates](../tls-and-certificates.md) for the full reference.

| Flag | Description |
|---|---|
| `--acme-domain` | Enable ACME; domain name pointing to this server (repeatable) |
| `--acme-email` | ACME account email |
| `--tls-server-name` | Override TLS SNI sent in client URIs |
| `--transport` | V2Ray transport layer: `ws`, `grpc`, `http`, `httpupgrade`, `quic` |
| `--transport-path` | Transport path (required for `ws` and `http`) |
| `--fallback-stub` | Use local Caddy stub as fallback (run `bootstrap --with-fallback-stub` first) |
| `--fallback-server` | Custom fallback server address |
| `--fallback-port` | Custom fallback server port |
| `--multiplex` | Enable sing-box multiplex |

## Recipes

### Self-signed TLS (simplest setup)

Obscura auto-generates a certificate. The certificate fingerprint is embedded in the client URI and trusted automatically by compatible clients:

```bash
sudo obscura vpn create --name trojan --protocol trojan
sudo obscura client show --vpn trojan --name default --qr
```

### With ACME (real domain, Let's Encrypt certificate)

Port 80 must be open for the HTTP-01 challenge. The certificate is automatically renewed:

```bash
sudo obscura vpn create \
  --name trojan \
  --protocol trojan \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com
```

### With WebSocket transport (CDN-compatible)

WebSocket transport allows the Trojan connection to pass through a CDN (e.g. Cloudflare). Set up the CDN to proxy WebSocket connections to your server's port:

```bash
sudo obscura vpn create \
  --name trojan-ws \
  --protocol trojan \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com \
  --transport ws \
  --transport-path /ws
```

Configure the CDN to forward HTTPS traffic for `vpn.example.com` to your server with WebSocket support enabled.

### With fallback stub (CDN-ready, port scan resistant)

The fallback stub is a local Caddy instance that returns real HTTP responses to probing clients. First install it during bootstrap:

```bash
sudo obscura bootstrap --yes --with-fallback-stub
```

Then create the Trojan instance with fallback enabled:

```bash
sudo obscura vpn create \
  --name trojan-fb \
  --protocol trojan \
  --acme-domain vpn.example.com \
  --acme-email admin@example.com \
  --fallback-stub
```

Clients that connect without a valid Trojan password receive an HTTP response from Caddy, making the server appear to be a regular web server.

### Add a client

```bash
sudo obscura client add --vpn trojan --name tablet --qr
```

## Compatible clients

| Platform | App |
|---|---|
| iOS | Shadowrocket, Sing-Box, Hiddify |
| Android | v2rayNG, Hiddify, Sing-Box |
| Windows / macOS / Linux | Clash Verge, Hiddify-Next, sing-box client |
