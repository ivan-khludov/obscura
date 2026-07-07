# WireGuard

## What it is

WireGuard is a modern VPN protocol that creates a full Layer 3 tunnel between the client and the server. Unlike proxy protocols (SOCKS5, Trojan, VLESS), WireGuard routes all network traffic from the client device, not just individual app connections. Each client receives a private IP address within the tunnel subnet. WireGuard uses state-of-the-art cryptography (Curve25519, ChaCha20-Poly1305) and has a very small attack surface.

Obscura manages WireGuard in userspace mode by default (via sing-box), which requires no kernel module and works without root on the client side. Kernel mode is also supported.

## When to use

- Full device VPN where all traffic should route through the server
- Accessing the server's local network from a remote client
- Mobile devices where you want OS-level VPN integration (WireGuard apps are available on all platforms)
- Situations where a proxy (SOCKS5, Trojan, etc.) is insufficient because some applications do not respect proxy settings

WireGuard traffic is recognizable as WireGuard by its UDP pattern. It is not designed for obfuscation. Use Shadowsocks or VLESS with Reality if traffic camouflage is required.

## Quick create

```bash
sudo obscura vpn create --name wg --protocol wireguard --client-name phone
sudo obscura client show --vpn wg --name phone --qr
```

The client URI is a standard WireGuard configuration that can be imported into any WireGuard client app.

## Key options

| Flag | Default | Description |
|---|---|---|
| `--wg-address` | `10.8.0.1/24` | Tunnel CIDR address for the server (repeatable for dual-stack) |
| `--wg-mtu` | `1408` | WireGuard MTU; lower values help with fragmentation on some networks |
| `--wg-system` | off | Use kernel WireGuard interface (`wg0`) instead of userspace |
| `--wg-name` | auto | WireGuard interface name (for kernel mode) |
| `--wg-peer-keepalive` | | Default persistent keepalive interval in seconds (recommended: 25 for NAT traversal) |
| `--wg-client-allowed-ips` | `0.0.0.0/0,::/0` | AllowedIPs embedded in client configuration |

## Recipes

### Standard userspace tunnel

```bash
sudo obscura vpn create --name wg --protocol wireguard
```

Each client added to this VPN receives the next IP in the `10.8.0.0/24` subnet.

### Custom subnet (avoid conflicts with existing networks)

Use a different subnet if `10.8.0.0/24` conflicts with your LAN:

```bash
sudo obscura vpn create \
  --name wg \
  --protocol wireguard \
  --wg-address 172.16.100.1/24
```

### Dual-stack (IPv4 + IPv6)

```bash
sudo obscura vpn create \
  --name wg \
  --protocol wireguard \
  --wg-address 10.8.0.1/24 \
  --wg-address fd00::1/64
```

### Kernel interface (system WireGuard)

Requires the WireGuard kernel module and root on the server. The interface is visible in `ip link`:

```bash
sudo obscura vpn create \
  --name wg \
  --protocol wireguard \
  --wg-system \
  --wg-name wg0
```

### Add clients

Each client gets an auto-assigned IP in the tunnel subnet:

```bash
sudo obscura client add --vpn wg --name laptop --qr
sudo obscura client add --vpn wg --name tablet --qr
sudo obscura client list --vpn wg
```

### Import on the client

Scan the QR code with the WireGuard app, or copy the printed configuration into a `.conf` file and import it:

```bash
# On macOS / Linux with wireguard-tools
sudo wg-quick up ./wg-phone.conf
```

## Compatible clients

| Platform | App |
|---|---|
| iOS | WireGuard (official), Sing-Box, Hiddify |
| Android | WireGuard (official), Sing-Box, Hiddify |
| Windows | WireGuard (official), Hiddify-Next |
| macOS | WireGuard (official), Hiddify-Next |
| Linux | `wg-quick` (wireguard-tools), NetworkManager, Hiddify-Next |
