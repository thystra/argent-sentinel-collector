#!/usr/bin/env bash
set -euo pipefail
exec /usr/local/libexec/argent-sentinel/collector.py \
  --config /etc/argent-sentinel/collector.json status
