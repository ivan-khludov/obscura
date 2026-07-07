# TLS and Certificates

Obscura supports four TLS modes for protocols that require encrypted transport (Trojan, VMess, VLESS, Hysteria2, TUIC): self-signed certificates, ACME (Let's Encrypt), Reality, and custom certificates.

## Self-signed TLS (default)

When you create a Trojan, VMess, or VLESS instance, obscura automatically generates a self-signed certificate and stores it in `/etc/obscura/certs/`. No domain name is needed.

```bash
sudo obscura vpn create --name my-vpn --protocol trojan
```

The certificate is embedded in the client connection URI. Client apps that support obscura URIs will trust the embedded certificate fingerprint, so no manual certificate installation is required.

Self-signed TLS is suitable for personal use where you control the client configuration.

## ACME (Let's Encrypt)

Use ACME if you have a domain name pointing to your server. Obscura will automatically obtain and renew a certificate from Let's Encrypt.

```bash
sudo obscura vpn create \
  --name my-vpn \
  --protocol trojan \
  --acme-domain example.com \
  --acme-email admin@example.com
```

ACME flags (prefix `--hy2-acme-` for Hysteria2, `--tuic-acme-` for TUIC):

| Flag | Description |
|---|---|
| `--acme-domain` | Domain to obtain a certificate for (repeatable for multiple domains) |
| `--acme-email` | Account email for certificate expiry notifications |
| `--acme-provider` | ACME directory URL (default: Let's Encrypt) |
| `--acme-data-directory` | Directory to store ACME account data |
| `--acme-default-server-name` | Default server name for SNI routing |
| `--acme-disable-http-challenge` | Disable HTTP-01 challenge (use TLS-ALPN only) |
| `--acme-disable-tls-alpn-challenge` | Disable TLS-ALPN-01 challenge (use HTTP only) |
| `--acme-alternative-http-port` | Alternative port for HTTP-01 challenge |
| `--acme-alternative-tls-port` | Alternative port for TLS-ALPN-01 challenge |

**Port requirements for ACME:** port 80 must be reachable for HTTP-01, or port 443 for TLS-ALPN-01. Obscura manages UFW rules, but ensure any upstream firewall (cloud provider security group) also allows these ports.

## Reality (VLESS)

Reality is an alternative to standard TLS that does not require a domain name. The server borrows the TLS fingerprint of a real website (the "handshake server"), so network observers see traffic that looks identical to legitimate connections to that website. No certificate is stored on the server.

```bash
sudo obscura vpn create \
  --name my-vpn \
  --protocol vless \
  --reality \
  --reality-handshake www.google.com
```

Reality flags:

| Flag | Default | Description |
|---|---|---|
| `--reality` | | Enable Reality extension |
| `--reality-handshake` | (required) | Domain to mimic (must support TLS 1.3, e.g. `www.google.com`, `www.apple.com`) |
| `--reality-handshake-port` | `443` | Handshake server port |
| `--reality-private-key` | auto-generated | Reality private key |
| `--reality-short-id` | auto-generated | Reality short_id (repeatable for multiple clients) |
| `--reality-max-time-difference` | | Maximum allowed clock skew |
| `--reality-fingerprint` | `chrome` | uTLS browser fingerprint embedded in client share links |

Reality is recommended for VLESS when you do not have a domain name and maximum stealth is required.

## ECH (Encrypted Client Hello)

ECH encrypts the SNI in the TLS ClientHello, preventing passive observers from seeing the destination hostname.

```bash
sudo obscura vpn create \
  --name my-vpn \
  --protocol vless \
  --ech
```

| Flag | Description |
|---|---|
| `--ech` | Enable ECH |
| `--ech-key-path` | Path to ECH key file (auto-generated if omitted) |

ECH flags are prefixed `--hy2-ech-` for Hysteria2 and `--tuic-ech-` for TUIC.

## Custom certificates

Provide your own certificate and key files instead of auto-generated ones:

```bash
sudo obscura vpn create \
  --name my-vpn \
  --protocol trojan \
  --cert-path /etc/ssl/certs/my-cert.pem \
  --key-path /etc/ssl/private/my-key.pem
```

Custom certificate flags are prefixed `--hy2-` for Hysteria2 and `--tuic-` for TUIC.

## Certificate storage

Obscura stores auto-generated certificates and ACME account data under `/etc/obscura/certs/`. These files are included in backups created by `obscura backup create`.

## TLS version and cipher tuning

For advanced hardening, the TLS handshake parameters can be restricted:

| Flag | Description |
|---|---|
| `--tls-min-version` | Minimum TLS version (e.g. `1.2`, `1.3`) |
| `--tls-max-version` | Maximum TLS version |
| `--tls-cipher-suites` | Comma-separated cipher suites for TLS 1.0-1.2 |
| `--tls-alpn` | ALPN protocol list |

These flags apply to Trojan, VMess, and VLESS. Use the `--hy2-tls-` or `--tuic-tls-` prefix for Hysteria2 and TUIC respectively.

## Mutual TLS (client certificate authentication)

Restrict access to clients that present a trusted certificate:

| Flag | Description |
|---|---|
| `--tls-client-auth` | Client auth mode: `require`, `request`, or `require_any` |
| `--tls-client-cert-path` | Path to trusted client CA certificate (repeatable) |
| `--tls-client-cert-pubkey-sha256` | Expected client certificate public key SHA-256 (repeatable) |
