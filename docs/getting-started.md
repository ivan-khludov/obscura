# Getting Started

Obscura manages [sing-box](https://sing-box.sagernet.org/) VPN servers from the terminal. It handles installation, configuration, TLS certificates, client management, firewall rules, and backups through a single command-line tool.

## Prerequisites

- A Linux server (amd64 or arm64) with root access
- Obscura installed on the server (see [installation in README](../README.md#install))

## 1. Bootstrap the server

Run bootstrap once after installing obscura. It downloads and installs sing-box, applies kernel sysctl tuning, configures UFW firewall rules, and registers a systemd service:

```bash
sudo obscura bootstrap --yes
```

Add `--with-fallback-stub` if you plan to use Trojan with a CDN-compatible fallback (installs Caddy on `127.0.0.1:8080`):

```bash
sudo obscura bootstrap --yes --with-fallback-stub
```

Verify the setup completed cleanly:

```bash
sudo obscura doctor
```

## 2. Create a VPN instance

Each VPN instance is an independent sing-box inbound with its own port, protocol, and client list. Choose a protocol based on your network environment:

| Protocol | Best for |
|---|---|
| `vless` | General-purpose, Reality for maximum stealth |
| `trojan` | Looks like HTTPS; works behind CDN with domain |
| `hysteria2` | High speed on lossy or restricted connections |
| `shadowsocks` | Lightweight, well-supported by all clients |
| `wireguard` | Full Layer 3 tunnel, not just proxy |
| `tuic` | Low latency QUIC proxy |
| `vmess` | V2Ray-compatible with flexible transports |
| `socks5` | Simple proxy for trusted internal networks |
| `http` | HTTP/HTTPS proxy for tooling and scripts |

Create a VPN with an initial client:

```bash
sudo obscura vpn create --name my-vpn --protocol vless --client-name phone
```

See [docs/protocols/](protocols/) for protocol-specific options and recipes.

## 3. Get the client connection link

```bash
sudo obscura client show --vpn my-vpn --name phone --qr
```

This prints a connection URI and draws a QR code in the terminal. Scan it with a compatible client app:

- **iOS**: Shadowrocket, Sing-Box, Hiddify
- **Android**: v2rayNG, Hiddify, Sing-Box
- **Desktop**: Clash Verge, Hiddify, sing-box client

## 4. Add more clients

Each client gets its own credentials. Add a client to an existing VPN:

```bash
sudo obscura client add --vpn my-vpn --name laptop --qr
```

List all clients for a VPN:

```bash
sudo obscura client list --vpn my-vpn
```

## 5. Check status

```bash
# Show all VPN instances and their client counts
sudo obscura status

# Run health checks (port conflicts, service state, sing-box version)
sudo obscura doctor

# Follow live sing-box logs
sudo obscura logs --follow
```

## Next steps

- [Protocol guides](protocols/) - choose and configure the right protocol
- [TLS and Certificates](tls-and-certificates.md) - ACME (Let's Encrypt), Reality, self-signed
- [CLI Reference](cli-reference.md) - complete command and flag reference
- [Network Tuning](network-tuning.md) - enable BBR, manage TCP congestion, change SSH port
- [Backup and Restore](backup-and-restore.md) - protect your configuration and keys
