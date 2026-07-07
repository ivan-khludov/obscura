# Shadowsocks

## What it is

Shadowsocks is an encrypted proxy protocol designed to resist traffic analysis. Unlike VPN protocols, it looks like random noise rather than a recognizable VPN handshake, making it harder for firewalls to detect and block. Obscura uses the modern AEAD 2022 cipher suite by default (`2022-blake3-aes-128-gcm`), which provides strong encryption and replay protection.

## When to use

- Networks with basic deep packet inspection (DPI) where simple encryption is sufficient
- Clients that need wide compatibility (Shadowsocks is supported by essentially every proxy client)
- Pairing with ShadowTLS for additional TLS-layer camouflage in stricter network environments
- High-throughput scenarios where multiplex can reduce connection overhead

## Quick create

```bash
sudo obscura vpn create --name ss --protocol shadowsocks --client-name phone
```

## Key options

| Flag | Default | Description |
|---|---|---|
| `--method` | `2022-blake3-aes-128-gcm` | AEAD cipher; other 2022 options: `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305` |
| `--multiplex` | off | Enable sing-box multiplex to reduce handshake overhead |
| `--multiplex-padding` | off | Require padding in multiplexed connections (improves obfuscation) |
| `--shadowtls` | off | Front the connection with ShadowTLS v3 (see recipes below) |
| `--shadowtls-handshake` | `www.bing.com` | Domain to mimic during ShadowTLS handshake |
| `--shadowtls-strict-mode` | off | Reject clients that do not send a valid TLS ticket |
| `--shadowtls-handshake-port` | `443` | Handshake server port |

## Recipes

### Basic Shadowsocks

```bash
sudo obscura vpn create --name ss --protocol shadowsocks
sudo obscura client show --vpn ss --name default --qr
```

### With multiplex

Multiplex reduces per-request latency by reusing connections. Recommended for HTTP(S) browsing workloads:

```bash
sudo obscura vpn create \
  --name ss-mux \
  --protocol shadowsocks \
  --multiplex
```

### With ShadowTLS (recommended for restricted networks)

ShadowTLS wraps Shadowsocks in a TLS handshake that exactly mirrors a real TLS server. An observer sees a valid TLS session with the handshake domain, but the actual Shadowsocks payload is tunneled inside. Obscura handles the port coordination automatically:

```bash
sudo obscura vpn create \
  --name ss-stls \
  --protocol shadowsocks \
  --shadowtls \
  --shadowtls-handshake www.apple.com
```

The client URI includes both the ShadowTLS and Shadowsocks configuration. Import it into a compatible client (sing-box, Shadowrocket, v2rayNG).

### With ShadowTLS strict mode

Strict mode rejects any connection that does not include a valid TLS session ticket issued by the handshake server. This prevents active probing attacks:

```bash
sudo obscura vpn create \
  --name ss-stls-strict \
  --protocol shadowsocks \
  --shadowtls \
  --shadowtls-handshake www.cloudflare.com \
  --shadowtls-strict-mode
```

### Add multiple clients

```bash
sudo obscura client add --vpn ss --name laptop
sudo obscura client add --vpn ss --name tablet
```

Each client has its own password embedded in its URI.

### Rotate a client password

```bash
sudo obscura client rotate-password --vpn ss --name phone --qr
```

## Compatible clients

| Platform | App |
|---|---|
| iOS | Shadowrocket, Sing-Box, Hiddify |
| Android | v2rayNG, Hiddify, Sing-Box |
| Windows / macOS / Linux | Clash Verge, Hiddify-Next, sing-box client |
