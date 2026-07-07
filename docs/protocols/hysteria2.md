# Hysteria2

## What it is

Hysteria2 is a high-performance proxy protocol built on QUIC (UDP). It uses a custom congestion control algorithm called Brutal that saturates the available bandwidth by treating packet loss as a signal to keep sending rather than to back off. This makes it exceptionally fast on connections with high latency, packet loss, or artificial rate limiting, such as international links or mobile data connections.

Hysteria2 is not designed for traffic camouflage. QUIC traffic is identifiable. Use VLESS with Reality or Shadowsocks with ShadowTLS if stealth is required.

## When to use

- Connections with high packet loss or latency where TCP-based protocols underperform
- Links with ISP rate limiting that Brutal CC can circumvent
- Maximum download/upload speed is the primary goal
- Mobile connections on congested or lossy networks

## Quick create

```bash
sudo obscura vpn create --name hy2 --protocol hysteria2 --client-name phone
sudo obscura client show --vpn hy2 --name phone --qr
```

## Key options

Hysteria2 TLS flags are prefixed with `--hy2-` (e.g. `--hy2-acme-domain`, `--hy2-cert-path`). See [TLS and Certificates](../tls-and-certificates.md).

| Flag | Description |
|---|---|
| `--hy2-up-mbps` | Server uplink bandwidth in Mbps; enables Brutal CC when set |
| `--hy2-down-mbps` | Server downlink bandwidth in Mbps |
| `--hy2-ignore-client-bandwidth` | Force all clients to use BBR instead of Brutal CC |
| `--hy2-obfs-password` | Salamander obfuscation password (disguises QUIC as random UDP) |
| `--hy2-bbr-profile` | BBR profile when not using Brutal: `conservative`, `standard`, `aggressive` |
| `--hy2-brutal-debug` | Log Brutal CC statistics |
| `--hy2-masquerade` | URL the server presents to non-Hysteria2 HTTP/3 clients |
| `--hy2-masquerade-type` | Masquerade mode: `file` (serve a directory), `proxy` (reverse proxy), `string` (fixed response) |
| `--hy2-masquerade-url` | Reverse proxy target URL for masquerade |
| `--hy2-initial-packet-size` | Initial QUIC packet size (tune for path MTU) |
| `--hy2-acme-domain` | ACME domain for a real certificate |
| `--hy2-acme-email` | ACME account email |

## Recipes

### Basic setup

```bash
sudo obscura vpn create --name hy2 --protocol hysteria2
```

Without `--hy2-up-mbps`, Hysteria2 uses BBR congestion control. Clients can still set their own bandwidth.

### With Brutal CC bandwidth limits

Specify the server's uplink and downlink capacity. Hysteria2 will try to saturate these limits:

```bash
sudo obscura vpn create \
  --name hy2 \
  --protocol hysteria2 \
  --hy2-up-mbps 200 \
  --hy2-down-mbps 500
```

Set these to your actual server bandwidth for best results. Overestimating causes excessive congestion; underestimating leaves bandwidth unused.

### With Salamander obfuscation

Salamander disguises QUIC traffic as unrecognized UDP, preventing firewalls from identifying it as QUIC or Hysteria2:

```bash
sudo obscura vpn create \
  --name hy2 \
  --protocol hysteria2 \
  --hy2-obfs-password "my-secret-obfs-password"
```

The client must configure the same password. Obscura embeds it in the client URI.

### With ACME certificate

```bash
sudo obscura vpn create \
  --name hy2 \
  --protocol hysteria2 \
  --hy2-acme-domain vpn.example.com \
  --hy2-acme-email admin@example.com
```

### With masquerade as a website

The masquerade makes the server respond to plain HTTP/3 requests with content from a reverse proxy, so it looks like a real web server to scanners:

```bash
sudo obscura vpn create \
  --name hy2 \
  --protocol hysteria2 \
  --hy2-masquerade-type proxy \
  --hy2-masquerade-url https://www.bing.com
```

### Force BBR for all clients

If you do not want clients to use Brutal CC regardless of their configuration:

```bash
sudo obscura vpn create \
  --name hy2 \
  --protocol hysteria2 \
  --hy2-ignore-client-bandwidth
```

## Compatible clients

| Platform | App |
|---|---|
| iOS | Sing-Box, Hiddify, Shadowrocket |
| Android | Hiddify, Sing-Box |
| Windows / macOS / Linux | Hiddify-Next, sing-box client, official Hysteria2 client |
