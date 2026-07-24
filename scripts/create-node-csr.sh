#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ $# -ge 1 && $# -le 2 ]] || { echo "Usage: $0 NODE_ID [PKI_DIR]" >&2; exit 2; }
node_id="$1"
[[ $node_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || { echo "Invalid node ID" >&2; exit 2; }
pki_dir="${2:-/etc/argent-sentinel/pki}"
install -d -o root -g root -m 0700 "$pki_dir"
key="$pki_dir/node.key"
csr="$pki_dir/node.csr"
[[ ! -e $key && ! -e $csr ]] || { echo "Node key or CSR already exists; refusing to overwrite." >&2; exit 1; }
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$key"
chmod 0600 "$key"
openssl req -new -sha384 -key "$key" -out "$csr" -subj "/CN=$node_id/O=Argent Sentinel Node/"
chmod 0644 "$csr"
echo "$csr"
