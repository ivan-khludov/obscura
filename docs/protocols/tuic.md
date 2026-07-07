# TUIC

## What it is

TUIC (Tailored UDP Internet Connection) is a QUIC-based proxy protocol optimized for low latency rather than maximum throughput. Its key feature is a 0-RTT handshake option that allows clients to send data in the very first packet without waiting for a round trip to complete authentication. TUIC uses per-stream congestion control within QUIC multiplexing, which reduces head-of-line blocking compared to TCP-based protocols.

Like Hysteria2, TUIC uses UDP and is not designed for traffic obfuscation. Consider VLESS or Shadowsocks if concealment is required.

## When to use

- Latency-sensitive applications where round-trip time matters more than raw throughput
- Networks where QUIC passes more freely than TCP (some networks shape TCP but leave UDP alone)
- As an alternative to Hysteria2 when you prefer per-stream congestion control over Brutal CC
- When 0-RTT connection reuse is important for short-lived sessions

## Quick create

```bash
sudo obscura vpn create --name tuic --protocol tuic --client-name phone
sudo obscura client show --vpn tuic --name phone --qr
```

## Key options

TUIC TLS flags are prefixed with `--tuic-`. See [TLS and Certificates](../tls-and-certificates.md).

| Flag | Default | Description |
|---|---|---|
| `--tuic-congestion-control` | `bbr` | QUIC congestion control: `cubic`, `new_reno`, `bbr` |
| `--tuic-zero-rtt-handshake` | off | Enable 0-RTT QUIC handshake (reduces latency, minor replay risk) |
| `--tuic-auth-timeout` | | Client authentication timeout |
| `--tuic-heartbeat` | | Heartbeat interval for keeping idle connections alive |
| `--tuic-acme-domain` | | ACME domain |
| `--tuic-acme-email` | | ACME account email |

QUIC tuning flags (shared with Hysteria2, prefixed `--tuic-`):

| Flag | Description |
|---|---|
| `--tuic-initial-packet-size` | Initial QUIC packet size |
| `--tuic-disable-path-mtu-discovery` | Disable path MTU discovery |
| `--tuic-http2-stream-receive-window` | Per-stream receive window |
| `--tuic-http2-connection-receive-window` | Per-connection receive window |

## Recipes

### Standard setup with BBR

```bash
sudo obscura vpn create --name tuic --protocol tuic
```

BBR is the default congestion algorithm and works well for most networks.

### With BBR congestion (explicit)

```bash
sudo obscura vpn create \
  --name tuic \
  --protocol tuic \
  --tuic-congestion-control bbr
```

### With Cubic congestion control

Cubic may perform better on very low-latency, high-bandwidth links:

```bash
sudo obscura vpn create \
  --name tuic \
  --protocol tuic \
  --tuic-congestion-control cubic
```

### With 0-RTT handshake

Reduces connection establishment latency for clients that reconnect frequently. The 0-RTT data is potentially replayable, so do not use this for sensitive transaction-like workloads:

```bash
sudo obscura vpn create \
  --name tuic \
  --protocol tuic \
  --tuic-zero-rtt-handshake
```

### With ACME certificate

```bash
sudo obscura vpn create \
  --name tuic \
  --protocol tuic \
  --tuic-acme-domain vpn.example.com \
  --tuic-acme-email admin@example.com
```

### With heartbeat for mobile clients

Mobile connections frequently sleep and wake. A heartbeat keeps the QUIC connection alive and prevents clients from needing a full reconnect:

```bash
sudo obscura vpn create \
  --name tuic \
  --protocol tuic \
  --tuic-heartbeat 10s
```

### Add multiple clients

```bash
sudo obscura client add --vpn tuic --name laptop
sudo obscura client add --vpn tuic --name tablet --qr
```

## Compatible clients

| Platform | App |
|---|---|
| iOS | Sing-Box, Hiddify, Shadowrocket |
| Android | Hiddify, Sing-Box |
| Windows / macOS / Linux | Hiddify-Next, sing-box client |
