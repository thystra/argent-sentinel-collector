#!/usr/bin/env bash
set -euo pipefail
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
usage(){ cat >&2 <<USAGE
Usage: $0 --mode test|production [--recipient EMAIL] --apply
  test: redirects new reports to --recipient and leaves legacy cron active
  production: uses RDAP recipients and disables legacy nginx-abuse cron entries
USAGE
exit 2; }
mode=""; recipient=""; apply=0
while [[ $# -gt 0 ]]; do
 case "$1" in --mode) mode="$2"; shift 2;; --recipient) recipient="$2"; shift 2;; --apply) apply=1; shift;; *) usage;; esac
done
[[ $mode == test || $mode == production ]] || usage
[[ $apply -eq 1 ]] || { echo "Refusing to change the system without --apply." >&2; exit 2; }
if [[ $mode == test && ! $recipient =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]; then
  echo "Test mode requires a valid --recipient." >&2; exit 2
fi
config=/etc/argent-sentinel/collector.json
[[ -s $config ]] || { echo "Missing $config" >&2; exit 1; }
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup=/var/backups/argent-sentinel/cutover-$stamp
install -d -o root -g root -m 0700 "$backup"
cp -a "$config" "$backup/collector.json"
crontab -l -u root > "$backup/root.crontab" 2>/dev/null || :
[[ -d /etc/cron.d ]] && cp -a /etc/cron.d "$backup/cron.d"
/usr/bin/argent-sentinel --config "$config" legacy-import
cutoff=$(date -u +%Y-%m-%dT%H:%M:%SZ)
CONFIG="$config" MODE="$mode" RECIPIENT="$recipient" CUTOFF="$cutoff" python3 <<'PY'
import json,os,re
from pathlib import Path
p=Path(os.environ['CONFIG']); c=json.loads(p.read_text())
r=c.setdefault('abuse_reporting',{})
r['enabled']=True; r['report_not_before_utc']=os.environ['CUTOFF']
if os.environ['MODE']=='test':
    r['test_mode']=True; r['recipient_override']=os.environ['RECIPIENT']; r['max_reports_per_run']=1
else:
    r['test_mode']=False; r['recipient_override']=''
    r['max_reports_per_run']=3
    r['max_reports_per_recipient_per_day']=10
for key in ('from','operator_contact','message_id_domain'):
    if not str(r.get(key,'')).strip(): raise SystemExit(f'abuse_reporting.{key} must be configured before cutover')
c.setdefault('abuse_context',{})['enabled']=True
legacy=c.setdefault('legacy_reporting',{})
legacy['suppress_matching_markers']=True
t=p.with_suffix('.json.tmp'); t.write_text(json.dumps(c,indent=2,sort_keys=True)+'\n'); t.chmod(0o600); t.replace(p)
PY
if ! /usr/bin/argent-sentinel --config "$config" validate-config; then
  cp -a "$backup/collector.json" "$config"
  echo "Validation failed; configuration restored." >&2; exit 1
fi
if [[ $mode == production ]]; then
  if crontab -l -u root >/tmp/argent-sentinel-cron.$$ 2>/dev/null; then
    awk '/nginx-abuse-(draft|send)-reports\.py/ {print "# ARGENT-SENTINEL-DISABLED " $0; next} {print}' \
      /tmp/argent-sentinel-cron.$$ | crontab -u root -
    rm -f /tmp/argent-sentinel-cron.$$
  fi
  while IFS= read -r -d '' file; do
    if grep -Eq 'nginx-abuse-(draft|send)-reports\.py' "$file"; then
      sed -E -i 's@^([^#].*nginx-abuse-(draft|send)-reports\.py.*)$@# ARGENT-SENTINEL-DISABLED \1@' "$file"
    fi
  done < <(find /etc/cron.d -maxdepth 1 -type f -print0 2>/dev/null)
fi
systemctl restart argent-sentinel-collector.timer
systemctl start argent-sentinel-collector.service
cat <<OUT
Argent Sentinel reporting cutover complete.
Mode: $mode
Cutoff: $cutoff
Backup: $backup
Legacy cron disabled: $([[ $mode == production ]] && echo yes || echo no)
OUT
