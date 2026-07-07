# HTTP Proxy

## What it is

The HTTP proxy protocol is the classic `CONNECT`-based proxy, natively supported by browsers, package managers, and virtually every HTTP client library. It supports both plain HTTP and HTTPS tunneling (`CONNECT` method). Obscura can optionally wrap it with a self-signed TLS certificate to encrypt the connection between the client and the proxy.

## When to use

- System-wide proxy for package managers (`apt`, `pip`, `npm`, `cargo`) or CI runners
- Environments where only HTTP proxy settings are configurable (no SOCKS5 support)
- Quick proxy for a browser or desktop app without installing a client app
- Trusted network contexts where you want a simple, universally compatible proxy

Without TLS (`--tls`), the proxy connection itself is unencrypted. Use TLS if the proxy is reachable over the internet.

## Quick create

```bash
# Plain HTTP proxy
sudo obscura vpn create --name proxy --protocol http

# HTTPS proxy (TLS with self-signed certificate)
sudo obscura vpn create --name proxy --protocol http --tls
```

## Key options

| Flag | Default | Description |
|---|---|---|
| `--tls` | off | Wrap the proxy in TLS (self-signed certificate) |
| `--port` | auto-assigned | Listen port |
| `--listen` | `0.0.0.0` | Listen address |
| `--client-name` | `default` | Name for the initial client |

To enable or disable TLS on an existing instance:

```bash
sudo obscura vpn edit proxy --tls       # enable TLS
sudo obscura vpn edit proxy --no-tls    # disable TLS
```

## Recipes

### System proxy for apt

```bash
# Get connection details
sudo obscura client show --vpn proxy --name default

# In /etc/apt/apt.conf.d/01proxy
Acquire::http::Proxy "http://user:pass@your-server:PORT";
Acquire::https::Proxy "http://user:pass@your-server:PORT";
```

### Environment variable proxy (curl, pip, npm)

```bash
export http_proxy=http://user:pass@your-server:PORT
export https_proxy=http://user:pass@your-server:PORT
export no_proxy=localhost,127.0.0.1

# Now all HTTP clients that respect these variables will use the proxy
curl https://example.com
pip install requests
npm install
```

### Python requests

```python
import requests

proxies = {
    "http": "http://user:pass@your-server:PORT",
    "https": "http://user:pass@your-server:PORT",
}
resp = requests.get("https://example.com", proxies=proxies)
```

### HTTPS proxy with self-signed TLS

When `--tls` is enabled, clients must trust the self-signed certificate or bypass verification. For curl:

```bash
# Trust the certificate explicitly
curl --proxy-cacert /path/to/cert.pem https://example.com --proxy https://user:pass@your-server:PORT

# Or skip verification (not recommended in production)
curl --proxy-insecure https://example.com --proxy https://user:pass@your-server:PORT
```

Get the certificate from the server:

```bash
openssl s_client -connect your-server:PORT </dev/null 2>/dev/null | openssl x509 > proxy-cert.pem
```
