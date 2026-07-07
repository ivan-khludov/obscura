# Backup and Restore

Obscura stores all its state under `/etc/obscura/`: the database (VPN and client records), rendered sing-box configuration, and TLS certificates and private keys. Losing this data means losing all client credentials and configuration.

## What gets backed up

`obscura backup create` archives the following:

- SQLite database with all VPN and client records
- Rendered sing-box configuration (`config.json`)
- Previous configuration snapshot (`config.json.prev`) for rollback
- TLS certificates and private keys under `certs/`
- ACME account data under `certs/`
- Reality key material
- The obscura manifest (`manifest.json`) with installed versions and settings

The backup does **not** include the sing-box binary or obscura itself; those can be reinstalled with `bootstrap`.

## Creating a backup

```bash
sudo obscura backup create
```

The command prints the archive path on success, for example:

```
/etc/obscura/backups/obscura-backup-2026-07-06T15-04-05.tar.gz
```

The archive is a gzipped tar file. You can inspect its contents with:

```bash
tar -tzf /etc/obscura/backups/obscura-backup-2026-07-06T15-04-05.tar.gz
```

## Restoring from a backup

Copy the archive to the target server, then run:

```bash
sudo obscura backup restore /path/to/obscura-backup-2026-07-06T15-04-05.tar.gz
```

Obscura extracts the archive, overwrites the current state, and reloads sing-box. All VPN instances and client credentials are restored exactly as they were at backup time.

If the restored server has a different IP or hostname, existing client URIs will still work as long as you update the `--client-host` for each VPN:

```bash
sudo obscura vpn edit my-vpn --client-host new.server.ip
```

Then regenerate each client's share link:

```bash
sudo obscura client show --vpn my-vpn --name phone --qr
```

## Transferring a backup between servers

```bash
# On the old server
sudo obscura backup create
scp /etc/obscura/backups/obscura-backup-*.tar.gz user@new-server:/tmp/

# On the new server (after running obscura bootstrap)
sudo obscura backup restore /tmp/obscura-backup-*.tar.gz
```

## Backup schedule recommendations

Backups are not scheduled automatically. For production servers, set up a cron job or systemd timer:

```bash
# Daily backup at 03:00, keep 7 days
0 3 * * * root obscura backup create && find /etc/obscura/backups -name '*.tar.gz' -mtime +7 -delete
```

Add the cron entry to `/etc/cron.d/obscura-backup` and transfer archives to remote storage (S3, rsync, etc.) based on your retention policy.
