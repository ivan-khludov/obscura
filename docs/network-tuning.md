# Network Tuning

## TCP congestion control

TCP congestion control determines how the kernel manages bandwidth when a connection is constrained. The default algorithm on most Linux systems is `cubic`, which is optimized for stable connections. For VPN and proxy workloads, `bbr` (Bottleneck Bandwidth and Round-trip propagation time) typically delivers better throughput and lower latency, especially on long-distance or lossy links.

Check the current algorithm and list available options:

```bash
sudo obscura network congestion list
```

Example output:

```
current: cubic
bbr
cubic
reno
```

Switch to BBR:

```bash
sudo obscura network congestion set bbr
```

The change takes effect immediately and persists across reboots (written to `/etc/sysctl.d/`).

**Note for Hysteria2 and TUIC:** These protocols use QUIC over UDP, so TCP congestion control does not apply to their data path. BBR is still beneficial for the TCP-based control channels and for any other services running on the same server.

## Kernel sysctl tuning at bootstrap

During `obscura bootstrap`, obscura applies a set of kernel parameters optimized for high-throughput proxy workloads. These are written to `/etc/sysctl.d/90-obscura.conf` and applied with `sysctl --system`.

Tuned parameters include:

- **Socket buffers** (`net.core.rmem_max`, `net.core.wmem_max`, `net.ipv4.tcp_rmem`, `net.ipv4.tcp_wmem`): enlarged to reduce backpressure on fast connections
- **Backlog** (`net.core.netdev_max_backlog`, `net.core.somaxconn`): increased to handle burst connections
- **IP forwarding** (`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`): enabled for WireGuard tunnel routing
- **TIME_WAIT recycling** and related TCP settings: tuned for server-side proxy patterns

To review the applied settings:

```bash
cat /etc/sysctl.d/90-obscura.conf
```

To apply them manually without re-running bootstrap:

```bash
sudo sysctl --system
```

## Changing the SSH port

Obscura can change your SSH listen port safely: it updates `/etc/ssh/sshd_config`, restarts sshd, and adjusts the UFW firewall rule in one operation. This avoids the common mistake of updating sshd_config and forgetting to update the firewall (or vice versa).

Show the current SSH port:

```bash
sudo obscura system ssh port
```

Change the SSH port to 2222:

```bash
sudo obscura system ssh port set 2222
```

**Important:** Open a second SSH session on the new port before closing the current one to verify connectivity:

```bash
ssh -p 2222 user@your-server
```

If the new port is not reachable, reconnect on the old port and investigate before your session ends.

## UFW firewall management

Obscura manages UFW rules automatically:

- `bootstrap` opens the port for each VPN instance and updates the SSH rule
- `vpn create` opens the new VPN's port
- `vpn delete` closes the port
- `system ssh port set` updates the SSH allow rule
- `uninstall --full` removes all obscura-managed UFW rules

You can inspect UFW rules at any time:

```bash
sudo ufw status numbered
```

Do not manually delete rules that obscura created, as it tracks them internally. Use obscura commands to manage VPN ports and SSH port changes.
