#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this helper as root." >&2
  exit 1
fi

site_id="${1:-}"
site_user="${2:-}"
if [[ ! "$site_id" =~ ^[a-z0-9][a-z0-9_-]{0,190}$ ]]; then
  echo "Usage: $0 <site-id> <php-fpm-user>" >&2
  echo "site-id must use lowercase letters, digits, underscore, or hyphen." >&2
  exit 1
fi
if [[ -z "$site_user" ]] || ! id "$site_user" >/dev/null 2>&1; then
  echo "Unknown PHP-FPM user: $site_user" >&2
  exit 1
fi
getent group sentinel >/dev/null 2>&1 || groupadd --system sentinel
if ! id -nG "$site_user" | tr ' ' '\n' | grep -qx sentinel; then
  usermod -aG sentinel "$site_user"
  group_changed=1
else
  group_changed=0
fi

path="/var/lib/argent-sentinel/drop/wordpress/$site_id/incoming"
install -d -o "$site_user" -g sentinel -m 2770 "$path"
printf '%s\n' "$path"
if [[ $group_changed -eq 1 ]]; then
  echo "Added $site_user to the sentinel group. Restart the relevant PHP-FPM service before exporting."
fi
