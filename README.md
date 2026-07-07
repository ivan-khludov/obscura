# obscura

[![CI](https://github.com/ivan-khludov/obscura/actions/workflows/ci.yml/badge.svg)](https://github.com/ivan-khludov/obscura/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/ivan-khludov/obscura)](https://github.com/ivan-khludov/obscura/releases/latest)
[![Go](https://img.shields.io/badge/go-1.25+-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux-lightgrey)](#requirements)

Obscura is a terminal manager for sing-box VPN servers. It installs sing-box, manages VPN instances and clients, and handles TLS certificates, firewall rules, and backups.

## Requirements

- Linux (amd64 or arm64)
- Root access on the server
- SSH access to the server

## Getting started

If you are new to VPS servers, here is the full path from zero to a working VPN.

**1. Rent a server**

Get a Linux VPS from any provider, choose **Ubuntu 22.04** or **24.04**, amd64. Any plan with 1 CPU and 1 GB RAM is enough.

After payment, the provider will send you:
- **IP address** — e.g. `185.123.45.67`
- **Username** — usually `root`
- **Password** or an SSH key you set during signup

**2. Connect to the server via SSH**

Open a terminal (macOS/Linux: built-in Terminal; Windows: PowerShell or [PuTTY](https://putty.org)) and run:

```bash
ssh root@185.123.45.67
```

Enter the password when prompted. You are now inside your server.

**3. Install obscura and set up your VPN**

Continue with the [Install](#install) and [Quick start](#quick-start) sections below.

## Install

**From a release:**

```bash
VERSION=v0.0.1  # see https://github.com/ivan-khludov/obscura/releases for the latest version
ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSL "https://github.com/ivan-khludov/obscura/releases/download/${VERSION}/obscura_${VERSION}_linux_${ARCH}.tar.gz" \
  | sudo tar -xz -C /usr/local/bin obscura
```

**From source** (requires Go 1.25+):

```bash
git clone https://github.com/ivan-khludov/obscura.git
cd obscura
make build
sudo install -m 755 bin/obscura /usr/local/bin/
```

## Quick start

Obscura can be used from the command line or through an interactive menu. Both options provide the same functionality, so use whichever feels more convenient.

### Interactive menu

On an interactive terminal, run obscura with no subcommand to open the menu:

```bash
sudo obscura
```

Then follow the prompts:

1. **Bootstrap server**: Perform the initial server setup (sing-box, firewall, and sysctl).
2. **VPNs → Create VPN**: Choose a protocol and create a VPN with its first client.
3. **Clients → Show client URI**: View the client connection URI and QR code.

Scan the QR code with a compatible client app (eg. Shadowrocket, v2rayNG, sing-box, Hiddify, or Clash).

### CLI (example)

The commands below create a **VLESS** VPN named `my-vpn` with a client `phone`. Replace names, protocol, and flags to match your setup.

```bash
# Initialize sing-box, firewall, and system settings
sudo obscura bootstrap

# Create a VPN instance with an initial client
sudo obscura vpn create --name my-vpn --protocol vless --client-name phone

# Get the client connection URI and QR code
sudo obscura client show --vpn my-vpn --name phone --qr
```

## Documentation

See [docs/](docs/) for guides on protocols, TLS, backups, and network tuning.

## Support

If this project helps you, optional tips in **USDT (Tron / TRC-20)** are welcome:

<p align="left">
  <img src="assets/qr.png" alt="USDT TRC-20 QR code" width="200" />
</p>

**Address (TRC-20 / Tron):**

```
TNrPGfU3HqtfMPmmhdvrJsQng7Ck9fian4
```

Send **only** USDT over the **Tron network** to this address; using other chains can mean lost funds.

## Author

**Ivan Khludov** | [ivan.khludov.dev@gmail.com](mailto:ivan.khludov.dev@gmail.com)

## License

Licensed under the [MIT License](LICENSE).

Version history: [GitHub Releases](https://github.com/ivan-khludov/obscura/releases).
