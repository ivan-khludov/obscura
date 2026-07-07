#!/usr/bin/env bash
# Install pinned sing-box for lab images (version/sha256 from internal/install/assets.yaml).
set -euo pipefail

dest="${1:?destination path required}"
cache_dir="${2:-}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
assets="${script_dir}/../../internal/install/assets.yaml"
if [[ ! -f "$assets" ]]; then
	assets="/src/internal/install/assets.yaml"
fi
if [[ ! -f "$assets" ]]; then
	echo "assets.yaml not found" >&2
	exit 1
fi

arch="$(dpkg --print-architecture 2>/dev/null || true)"
if [[ -z "$arch" ]]; then
	case "$(uname -m)" in
	x86_64) arch=amd64 ;;
	aarch64) arch=arm64 ;;
	*) echo "unsupported machine: $(uname -m)" >&2; exit 1 ;;
	esac
fi
case "$arch" in
amd64) key=linux-amd64 ;;
arm64) key=linux-arm64 ;;
*) echo "unsupported dpkg arch: $arch" >&2; exit 1 ;;
esac

version="$(sed -n 's/^version: "\(.*\)"/\1/p' "$assets")"
if [[ -z "$version" ]]; then
	echo "parse version from $assets" >&2
	exit 1
fi

read -r url sha bin <<<"$(awk -v key="$key" '
$0 ~ "^  " key ":" { block=1; next }
block && /^  [a-z0-9_-]+:/ { exit }
block && /url:/ { gsub(/"/, "", $2); url=$2 }
block && /sha256:/ { gsub(/"/, "", $2); sha=$2 }
block && /binary:/ { gsub(/"/, "", $2); bin=$2 }
END { print url, sha, bin }
' "$assets")"

if [[ -z "$url" || -z "$sha" || -z "$bin" ]]; then
	echo "parse $key asset from $assets" >&2
	exit 1
fi

if [[ -x "$dest" ]]; then
	installed="$("$dest" version 2>/dev/null | sed 's/^sing-box version //')"
	if [[ "$installed" == "$version" ]]; then
		echo "sing-box $version already at $dest" >&2
		exit 0
	fi
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
tar_path="$tmp/archive.tar.gz"

if [[ -n "$cache_dir" ]]; then
	mkdir -p "$cache_dir"
	cached="${cache_dir}/sing-box-${version}-${key}.tar.gz"
	if [[ -f "$cached" ]]; then
		cp "$cached" "$tar_path"
	fi
fi

if [[ ! -s "$tar_path" ]]; then
	echo "downloading sing-box ${version} (${key})..." >&2
	curl -fSL --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 900 --progress-bar \
		-o "$tar_path" "$url"
	if [[ -n "$cache_dir" ]]; then
		cp "$tar_path" "$cached"
	fi
fi

echo "${sha}  ${tar_path}" | sha256sum -c -
tar -xzf "$tar_path" -C "$tmp"
install -m 755 "${tmp}/${bin}" "$dest"
echo "installed sing-box ${version} -> ${dest}" >&2
"$dest" version >&2
