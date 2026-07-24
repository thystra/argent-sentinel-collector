#!/usr/bin/env bash
set -euo pipefail
if command -v argent-sentinel >/dev/null 2>&1; then
  exec argent-sentinel --config /etc/argent-sentinel/collector.json status
fi
exec /usr/local/libexec/argent-sentinel/collector.py \
  --config /etc/argent-sentinel/collector.json status
