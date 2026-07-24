#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this installer as root." >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

getent group sentinel >/dev/null 2>&1 || groupadd --system sentinel

install -d -o root -g root -m 0755 /usr/local/libexec/argent-sentinel
install -m 0755 -o root -g root "$script_dir/src/collector.py" \
  /usr/local/libexec/argent-sentinel/collector.py

install -d -o root -g root -m 0750 /etc/argent-sentinel
if [[ ! -e /etc/argent-sentinel/collector.json ]]; then
  install -m 0600 -o root -g root "$script_dir/config/collector.json.example" \
    /etc/argent-sentinel/collector.json
  echo "Installed dry-run configuration at /etc/argent-sentinel/collector.json"
else
  echo "Preserved existing /etc/argent-sentinel/collector.json"
fi

install -d -o root -g sentinel -m 0750 \
  /var/lib/argent-sentinel \
  /var/lib/argent-sentinel/drop \
  /var/lib/argent-sentinel/drop/wordpress
install -d -o root -g root -m 0750 \
  /var/lib/argent-sentinel/collector \
  /var/lib/argent-sentinel/collector/processing \
  /var/lib/argent-sentinel/collector/archive \
  /var/lib/argent-sentinel/collector/rejected

install -d -o root -g root -m 0755 /usr/local/share/doc/argent-sentinel-collector
install -m 0644 -o root -g root "$script_dir/README.md" \
  /usr/local/share/doc/argent-sentinel-collector/README.md

install -m 0644 -o root -g root "$script_dir/systemd/argent-sentinel-collector.service" \
  /etc/systemd/system/argent-sentinel-collector.service
install -m 0644 -o root -g root "$script_dir/systemd/argent-sentinel-collector.timer" \
  /etc/systemd/system/argent-sentinel-collector.timer

/usr/local/libexec/argent-sentinel/collector.py \
  --config /etc/argent-sentinel/collector.json validate-config

systemctl daemon-reload
systemd-analyze verify \
  /etc/systemd/system/argent-sentinel-collector.service \
  /etc/systemd/system/argent-sentinel-collector.timer
systemctl enable --now argent-sentinel-collector.timer

echo
echo "Argent Sentinel collector installed in dry-run mode."
echo "Create each WordPress drop with create-wordpress-drop.sh, export a batch,"
echo "then inspect: /usr/local/libexec/argent-sentinel/collector.py --config /etc/argent-sentinel/collector.json status"
