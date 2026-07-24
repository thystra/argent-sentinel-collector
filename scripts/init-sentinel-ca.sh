#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
pki_dir="${1:-/etc/argent-sentinel/pki}"
install -d -o root -g root -m 0700 "$pki_dir"
key="$pki_dir/ca.key"
cert="$pki_dir/ca.crt"
if [[ -e $key || -e $cert ]]; then
  [[ -s $key && -s $cert ]] || { echo "Partial CA state exists in $pki_dir" >&2; exit 1; }
  echo "Existing Sentinel CA preserved: $cert"
  exit 0
fi
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$key"
chmod 0600 "$key"
openssl req -x509 -new -sha384 -days 3650 \
  -key "$key" -out "$cert" \
  -subj "/CN=Argent Sentinel Node CA/O=Argent Wolf/"
chmod 0644 "$cert"
echo "Created Sentinel node CA: $cert"
