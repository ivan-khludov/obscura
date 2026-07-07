#!/bin/bash
set -euo pipefail

echo "==> bootstrap (enables ufw with SSH allowed)"
obscura bootstrap --yes

echo "==> allowing proxy ports"
if [[ -n "${E2E_UFW_PORTS:-}" ]]; then
	for port in ${E2E_UFW_PORTS}; do
		ufw allow "${port}/tcp"
	done
fi
if [[ -n "${E2E_UFW_UDP_PORTS:-}" ]]; then
	for port in ${E2E_UFW_UDP_PORTS}; do
		ufw allow "${port}/udp"
	done
fi
if [[ -z "${E2E_UFW_PORTS:-}" && -z "${E2E_UFW_UDP_PORTS:-}" ]]; then
	ufw allow 8080/tcp
	ufw allow 8443/tcp
fi

echo "==> bootstrap"
obscura bootstrap --yes

echo "==> sing-box active"
if [[ "$(systemctl is-active sing-box)" != "active" ]]; then
	echo "sing-box not active" >&2
	systemctl status sing-box || true
	exit 1
fi

echo "==> e2e server ready"
