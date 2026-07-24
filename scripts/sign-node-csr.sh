#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
usage() {
  echo "Usage: $0 NODE_ID CSR [--service NAME]... [--site SITE_ID]... [--install-local]" >&2
  exit 2
}
[[ $# -ge 2 ]] || usage
node_id="$1"; csr="$2"; shift 2
[[ $node_id =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || usage
services=(); sites=(); install_local=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --service) [[ $# -ge 2 ]] || usage; services+=("$2"); shift 2 ;;
    --site) [[ $# -ge 2 ]] || usage; sites+=("$2"); shift 2 ;;
    --install-local) install_local=1; shift ;;
    *) usage ;;
  esac
done
[[ ${#services[@]} -gt 0 ]] || services=(wordpress nginx sshd)
[[ -s $csr && ! -L $csr ]] || { echo "CSR missing or invalid: $csr" >&2; exit 1; }
pki=/etc/argent-sentinel/pki
ca_key="$pki/ca.key"; ca_cert="$pki/ca.crt"
[[ -s $ca_key && -s $ca_cert ]] || { echo "Initialize the Sentinel CA first." >&2; exit 1; }
subject="$(openssl req -in "$csr" -noout -subject -nameopt RFC2253)"
SUBJECT="$subject" NODE_ID="$node_id" python3 <<'PY'
import os, sys
parts = [part.strip() for part in os.environ['SUBJECT'].removeprefix('subject=').split(',')]
cns = [part[3:] for part in parts if part.startswith('CN=')]
if cns != [os.environ['NODE_ID']]:
    print(f"CSR must contain exactly CN={os.environ['NODE_ID']}: {os.environ['SUBJECT']}", file=sys.stderr)
    raise SystemExit(1)
PY
out_dir="/var/lib/argent-sentinel/enrollment/$node_id"
install -d -o root -g root -m 0700 "$out_dir"
ext="$out_dir/client.ext"
cat > "$ext" <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:$node_id
EXT
openssl x509 -req -sha384 -days 825 -in "$csr" \
  -CA "$ca_cert" -CAkey "$ca_key" -CAcreateserial \
  -out "$out_dir/node.crt" -extfile "$ext"
install -m 0644 "$ca_cert" "$out_dir/ca.crt"
NODES_DIR=/etc/argent-sentinel/nodes.d NODE_ID="$node_id" \
SERVICES_JSON="$(printf '%s\n' "${services[@]}" | python3 -c 'import json,sys; print(json.dumps([x.strip() for x in sys.stdin if x.strip()]))')" \
SITES_JSON="$(printf '%s\n' "${sites[@]}" | python3 -c 'import json,sys; print(json.dumps([x.strip() for x in sys.stdin if x.strip()]))')" \
python3 <<'PY'
import json, os
from pathlib import Path
root=Path(os.environ['NODES_DIR']); root.mkdir(parents=True,exist_ok=True)
path=root/(os.environ['NODE_ID']+'.json')
data={'node_id':os.environ['NODE_ID'],'enabled':True,
      'services':json.loads(os.environ['SERVICES_JSON']),
      'site_ids':json.loads(os.environ['SITES_JSON'])}
tmp=path.with_suffix('.json.tmp'); tmp.write_text(json.dumps(data,indent=2,sort_keys=True)+'\n'); tmp.chmod(0o640); tmp.replace(path)
PY
if [[ $install_local -eq 1 ]]; then
  install -o root -g root -m 0644 "$out_dir/node.crt" "$pki/node.crt"
  if [[ $(readlink -f "$ca_cert") != $(readlink -m "$pki/ca.crt") ]]; then
    install -o root -g root -m 0644 "$ca_cert" "$pki/ca.crt"
  fi
  echo "Installed local client certificate. Existing $pki/node.key was preserved."
fi
echo "Signed certificate: $out_dir/node.crt"
echo "Enrollment record: /etc/argent-sentinel/nodes.d/$node_id.json"
