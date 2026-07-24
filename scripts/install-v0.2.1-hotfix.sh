#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this hotfix installer as root." >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source_file="$script_dir/src/collector.py"
target_file="/usr/local/libexec/argent-sentinel/collector.py"
config_file="/etc/argent-sentinel/collector.json"
timestamp="$(date +%Y%m%d-%H%M%S)"
backup_file="${target_file}.bak-${timestamp}"

echo "Validating hotfix source and tests..."
python3 -m py_compile "$source_file"
python3 "$script_dir/tests/test_collector.py"

if [[ ! -f "$target_file" ]]; then
  echo "Collector is not installed at $target_file" >&2
  exit 1
fi
if [[ ! -f "$config_file" ]]; then
  echo "Collector configuration is missing at $config_file" >&2
  exit 1
fi

systemctl stop argent-sentinel-collector.timer || true
systemctl stop argent-sentinel-collector.service || true

install -m 0755 -o root -g root "$target_file" "$backup_file"
install -m 0755 -o root -g root "$source_file" "$target_file"

if ! "$target_file" --config "$config_file" validate-config; then
  echo "Configuration validation failed; restoring $backup_file" >&2
  install -m 0755 -o root -g root "$backup_file" "$target_file"
  systemctl start argent-sentinel-collector.timer || true
  exit 1
fi

systemctl start argent-sentinel-collector.timer
systemctl start argent-sentinel-collector.service

echo
printf 'Installed Argent Sentinel collector 0.2.1 hotfix.\nBackup: %s\n' "$backup_file"
echo "Check with:"
echo "  $target_file --config $config_file status"
echo "  systemctl status argent-sentinel-collector.service --no-pager -l"
