#!/bin/bash
set -euo pipefail

echo "==> bootstrap (enables ufw with SSH allowed)"
obscura bootstrap --yes

echo "==> create vpn (applies config)"
uri="$(obscura vpn create --name main --port 1080 --json | jq -r .uri)"
if [[ -z "$uri" || "$uri" == "null" ]]; then
	echo "missing client uri from vpn create" >&2
	exit 1
fi
echo "client uri: $uri"

echo "==> sing-box active"
if [[ "$(systemctl is-active sing-box)" != "active" ]]; then
	echo "sing-box not active" >&2
	systemctl status sing-box || true
	exit 1
fi

echo "==> doctor"
if ! obscura doctor; then
	echo "doctor reported failures" >&2
	exit 1
fi

echo "==> socks5 curl"
if ! curl --fail --silent --show-error --proxy "$uri" --max-time 30 -I https://example.com >/dev/null; then
	echo "socks5 curl failed" >&2
	exit 1
fi

echo "==> backup"
backup_path="$(obscura backup create --json | jq -r .path)"
if [[ -z "$backup_path" || "$backup_path" == "null" ]]; then
	echo "backup failed" >&2
	exit 1
fi
echo "backup: $backup_path"

echo "==> uninstall dry-run"
obscura uninstall --dry-run --json >/dev/null

echo "==> uninstall full"
obscura uninstall --full --confirm destroy --wipe-data

echo "==> lab smoke passed"
