#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
usage(){ echo "Usage: $0 --node NODE --fqdn FQDN [--destination-ip IP] [--sshd] [--ssh-only] [--enable]" >&2; exit 2; }
node=""; fqdn=""; dest=""; sshd=0; ssh_only=0; enable=0
while [[ $# -gt 0 ]]; do
 case "$1" in
  --node) node="$2"; shift 2;; --fqdn) fqdn="$2"; shift 2;;
  --destination-ip) dest="$2"; shift 2;; --sshd) sshd=1; shift;;
  --ssh-only) ssh_only=1; shift;; --enable) enable=1; shift;; *) usage;;
 esac
done
[[ -n $node && -n $fqdn ]] || usage
CONFIG=/etc/argent-sentinel/agent.json NODE="$node" FQDN="$fqdn" DEST="$dest" \
SSHD="$sshd" SSH_ONLY="$ssh_only" ENABLE="$enable" python3 <<'PY'
import ipaddress,json,os
from pathlib import Path
p=Path(os.environ['CONFIG']); c=json.loads(p.read_text())
c['node']={'id':os.environ['NODE'],'fqdn':os.environ['FQDN']}
c['central_url']='https://sentinel.argentwolf.org/'
c['enabled']=os.environ['ENABLE']=='1'
s=c.setdefault('sshd',{}); s['enabled']=os.environ['SSHD']=='1'
if os.environ['DEST']:
    s['destination_ip']=str(ipaddress.ip_address(os.environ['DEST']))
if os.environ['SSH_ONLY']=='1':
    c['wordpress_globs']=[]; c['abuse_context_globs']=[]
t=p.with_suffix('.json.tmp'); t.write_text(json.dumps(c,indent=2,sort_keys=True)+'\n'); t.chmod(0o600); t.replace(p)
PY
/usr/bin/argent-sentinel-agent --config /etc/argent-sentinel/agent.json validate-config
systemctl enable --now argent-sentinel-agent.timer
