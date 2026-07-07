# CLI Reference

All commands require root (`sudo`). Run any command with `--help` for the full flag list.

## Global flags

| Flag | Description |
|---|---|
| `--dev` | Use development paths under `~/.obscura` instead of `/etc/obscura` |
| `--json` | Output results as JSON |

---

## bootstrap

Initialize obscura on this server: install sing-box, apply sysctl tuning, configure UFW, and set up the systemd service.

```bash
sudo obscura bootstrap [flags]
```

| Flag | Description |
|---|---|
| `--yes` | Skip interactive confirmation |
| `--with-fallback-stub` | Install Caddy HTTP stub on `127.0.0.1:8080` for Trojan TLS inbound fallback |

---

## apply

Render the current configuration and reload sing-box.

```bash
sudo obscura apply [flags]
```

| Flag | Description |
|---|---|
| `--dry-run` | Validate configuration without writing or reloading |

---

## rollback

Restore the previous sing-box configuration and reload.

```bash
sudo obscura rollback
```

---

## status

Show a summary of all VPN instances, their protocol, port, and client count.

```bash
sudo obscura status
```

---

## doctor

Run health checks: sing-box service state, version compatibility, port conflicts.

```bash
sudo obscura doctor
```

Exits with a non-zero code if any check fails (useful in scripts). Use `--json` to get structured output.

---

## logs

Show sing-box service logs via journald.

```bash
sudo obscura logs [flags]
```

| Flag | Description |
|---|---|
| `-f`, `--follow` | Follow log output (like `journalctl -f`) |
| `--since` | Show logs since timestamp (default: `1 hour ago`) |

---

## version

Print the obscura version.

```bash
sudo obscura version
```

---

## vpn create

Create a new VPN instance with an initial client.

```bash
sudo obscura vpn create --name NAME --protocol PROTOCOL [flags]
```

**Required:**

| Flag | Description |
|---|---|
| `--name` | VPN instance name (must be unique) |

**Core options:**

| Flag | Default | Description |
|---|---|---|
| `--protocol` | `socks5` | Protocol: `http`, `socks5`, `shadowsocks`, `trojan`, `wireguard`, `vmess`, `vless`, `hysteria2`, `tuic` |
| `--client-name` | `default` | Name for the initial client |
| `--client-host` | server hostname | Host or IP embedded in client share links |
| `--port` | auto-assigned | Listen port |
| `--listen` | `0.0.0.0` | Listen address |
| `--enabled` | `true` | Start VPN enabled |

**TLS options** (Trojan, VMess, VLESS - see [TLS and Certificates](tls-and-certificates.md)):

| Flag | Description |
|---|---|
| `--tls-server-name` | TLS SNI (defaults to server hostname) |
| `--acme-domain` | Enable ACME; domain name (repeatable) |
| `--acme-email` | ACME account email |
| `--reality` | Enable Reality TLS extension (VLESS) |
| `--reality-handshake` | Reality handshake server (e.g. `www.google.com`) |
| `--cert-path` / `--key-path` | Custom TLS certificate and key paths |
| `--ech` | Enable TLS ECH |

**Transport options** (Trojan, VMess, VLESS):

| Flag | Values | Description |
|---|---|---|
| `--transport` | `ws`, `grpc`, `http`, `httpupgrade`, `quic` | V2Ray transport layer |
| `--transport-path` | | Transport path (WebSocket or HTTP) |
| `--transport-host` | | Transport host header |
| `--transport-service-name` | | gRPC service name |

**Multiplex options** (Shadowsocks, Trojan, VMess, VLESS):

| Flag | Description |
|---|---|
| `--multiplex` | Enable sing-box multiplex |
| `--multiplex-padding` | Require padded multiplex connections |
| `--multiplex-brutal` | Enable TCP Brutal congestion in multiplex |
| `--multiplex-brutal-up-mbps` | Upload bandwidth for Brutal CC (Mbps) |
| `--multiplex-brutal-down-mbps` | Download bandwidth for Brutal CC (Mbps) |

**Trojan-specific:**

| Flag | Description |
|---|---|
| `--fallback-stub` | Enable TLS fallback to local Caddy stub (`127.0.0.1:8080`) |
| `--fallback-server` | Custom fallback server address |
| `--fallback-port` | Custom fallback server port |

**Shadowsocks-specific:**

| Flag | Default | Description |
|---|---|---|
| `--method` | `2022-blake3-aes-128-gcm` | AEAD cipher |
| `--shadowtls` | | Front with ShadowTLS v3 |
| `--shadowtls-handshake` | `www.bing.com` | ShadowTLS handshake server |
| `--shadowtls-strict-mode` | | Enable ShadowTLS strict mode |

**WireGuard-specific:**

| Flag | Default | Description |
|---|---|---|
| `--wg-address` | `10.8.0.1/24` | Tunnel CIDR address (repeatable) |
| `--wg-mtu` | `1408` | WireGuard MTU |
| `--wg-system` | | Use kernel WireGuard interface instead of userspace |

**Hysteria2-specific:**

| Flag | Description |
|---|---|
| `--hy2-up-mbps` | Server uplink bandwidth in Mbps (enables Brutal CC) |
| `--hy2-down-mbps` | Server downlink bandwidth in Mbps |
| `--hy2-obfs-password` | Salamander obfuscation password |
| `--hy2-masquerade` | Masquerade URL (`file://` or `http(s)://`) |
| `--hy2-ignore-client-bandwidth` | Force all clients to use BBR instead of Brutal CC |

**TUIC-specific:**

| Flag | Default | Description |
|---|---|---|
| `--tuic-congestion-control` | `bbr` | QUIC congestion control: `cubic`, `new_reno`, `bbr` |
| `--tuic-zero-rtt-handshake` | | Enable 0-RTT handshake |
| `--tuic-heartbeat` | | Heartbeat interval |

**VLESS-specific:**

| Flag | Description |
|---|---|
| `--vless-flow` | VLESS flow (`xtls-rprx-vision` for direct TLS DPI bypass) |

**HTTP-specific:**

| Flag | Description |
|---|---|
| `--tls` | Enable TLS with a self-signed certificate |

---

## vpn edit

Edit a VPN instance. Only the specified flags are changed.

```bash
sudo obscura vpn edit NAME [flags]
```

| Flag | Description |
|---|---|
| `--new-name` | Rename the VPN |
| `--client-host` | Update the client connect host |
| `--clear-client-host` | Reset client host to server hostname |
| `--enabled` | Enable the VPN |
| `--disabled` | Disable the VPN |
| `--tls` | Enable TLS (HTTP only) |
| `--no-tls` | Disable TLS (HTTP only) |
| `--apply` | Apply configuration after edit (default: `true`) |
| `--port`, `--listen`, and other listen flags | Update listen settings |

---

## vpn list

List all VPN instances.

```bash
sudo obscura vpn list
```

---

## vpn show

Show details for a single VPN instance.

```bash
sudo obscura vpn show NAME
```

---

## vpn delete

Delete a VPN instance and all its clients.

```bash
sudo obscura vpn delete NAME
```

---

## client add

Add a client to an existing VPN. The new client receives its own credentials.

```bash
sudo obscura client add --vpn VPN --name NAME [--qr]
```

| Flag | Description |
|---|---|
| `--vpn` | VPN instance name (required) |
| `--name` | Client name (required) |
| `--qr` | Print QR code after adding |
| `--no-apply` | Skip configuration reload |

---

## client list

List clients for a VPN.

```bash
sudo obscura client list --vpn VPN
```

---

## client show

Print a client's connection URI. Optionally show QR code.

```bash
sudo obscura client show --vpn VPN --name NAME [--qr]
```

---

## client remove

Remove a client from a VPN.

```bash
sudo obscura client remove --vpn VPN --name NAME
```

---

## client rotate-password

Generate new credentials for a client. The old URI stops working immediately.

```bash
sudo obscura client rotate-password --vpn VPN --name NAME [--qr]
```

---

## client edit

Edit client metadata. Only the specified flags are applied.

```bash
sudo obscura client edit --vpn VPN --name NAME [flags]
```

| Flag | Description |
|---|---|
| `--new-name` | Rename the client |
| `--username` | Set a custom username |
| `--password` | Set a custom password |
| `--enabled` | Enable the client |
| `--disabled` | Disable the client |
| `--apply` | Apply configuration after edit (default: `true`) |

---

## backup create

Create a backup archive containing the database, rendered configuration, and TLS keys.

```bash
sudo obscura backup create
```

Prints the archive path on success.

---

## backup restore

Restore from a backup archive and reload sing-box.

```bash
sudo obscura backup restore /path/to/archive.tar.gz
```

---

## network congestion list

Show the current and available TCP congestion control algorithms.

```bash
sudo obscura network congestion list
```

---

## network congestion set

Set the TCP congestion control algorithm.

```bash
sudo obscura network congestion set bbr
```

Common values: `bbr` (recommended), `cubic`, `reno`.

---

## system ssh port set

Change the SSH port. Obscura updates `sshd_config`, restarts sshd, and updates the UFW firewall rule.

```bash
sudo obscura system ssh port set PORT
```

---

## uninstall

Remove obscura-managed resources.

```bash
sudo obscura uninstall [flags]
```

| Flag | Description |
|---|---|
| `--dry-run` | Preview actions without making changes |
| `--full` | Full uninstall (remove sing-box, firewall rules, systemd service) |
| `--wipe-data` | Also remove the data directory (`/etc/obscura`) |
| `--confirm destroy` | Required to confirm a full uninstall |
