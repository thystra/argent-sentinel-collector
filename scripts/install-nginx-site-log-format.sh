#!/bin/sh
set -eu

SOURCE=/usr/share/argent-sentinel/nginx-site-access-log-format.conf.example
DEST=/etc/nginx/conf.d/argent-sentinel-site-access-format.conf
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
BACKUP="${DEST}.pre-argent-sentinel-${STAMP}"

if [ ! -r "$SOURCE" ]; then
    echo "Missing packaged log-format example: $SOURCE" >&2
    exit 1
fi

if [ -e "$DEST" ]; then
    cp -a "$DEST" "$BACKUP"
fi

install -o root -g root -m 0644 "$SOURCE" "$DEST"

if ! nginx -t; then
    if [ -e "$BACKUP" ]; then
        mv "$BACKUP" "$DEST"
    else
        rm -f "$DEST"
    fi
    echo "Nginx validation failed; restored the previous configuration." >&2
    exit 1
fi

systemctl reload nginx
echo "Installed Nginx log format: argent_site_access"
echo "Add one full per-site access_log and retain the filtered Sentinel JSONL."
