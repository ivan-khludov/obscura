# SOCKS5

## What it is

SOCKS5 is a lightweight proxy protocol that forwards TCP and UDP traffic without encryption. It authenticates clients with a username and password. Because there is no encryption overhead, it has minimal latency and CPU cost compared to other protocols.

## When to use

- Internal or trusted networks where encryption is handled at another layer (e.g. a WireGuard or SSH tunnel wrapping the SOCKS5 connection)
- Quick local proxy for development, testing, or scripting
- Situations where maximum raw throughput matters more than traffic obfuscation

SOCKS5 is not suitable for use over untrusted networks: traffic content is visible to anyone who can observe the connection.

## Quick create

```bash
sudo obscura vpn create --name internal --protocol socks5
```

## Key options

| Flag | Description |
|---|---|
| `--name` | VPN instance name (required) |
| `--port` | Listen port (default: auto-assigned) |
| `--listen` | Listen address (default: `0.0.0.0`) |
| `--client-name` | Name for the initial client (default: `default`) |

## Recipes

### Proxy for curl and wget

After creating the instance, get the connection URI to find the port and credentials:

```bash
sudo obscura client show --vpn internal --name default
```

Use in shell commands:

```bash
curl --socks5 user:pass@your-server:PORT https://api.example.com
wget --execute="https_proxy=socks5://user:pass@your-server:PORT" https://example.com
```

Or set environment variables for the session:

```bash
export ALL_PROXY=socks5://user:pass@your-server:PORT
curl https://api.example.com
```

### Add multiple clients

Each client gets separate credentials, useful for granting access to different users or machines:

```bash
sudo obscura client add --vpn internal --name laptop
sudo obscura client add --vpn internal --name ci-runner
sudo obscura client list --vpn internal
```

### Access internal resources

Combine with SSH port forwarding to reach resources on the server's local network:

```bash
# On the client machine
ssh -D 1080 -N user@your-server &
curl --socks5 127.0.0.1:1080 http://192.168.1.10/
```

Or configure your browser or system proxy settings to use the SOCKS5 endpoint directly.

### Rotate credentials

Generate new credentials for a client without removing it:

```bash
sudo obscura client rotate-password --vpn internal --name laptop
```

The old credentials become invalid immediately.
