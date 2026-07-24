#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    echo "Run this installer as root." >&2
    exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(cd -- "${script_dir}/.." && pwd)"
collector_source="${source_dir}/src/collector.py"
collector_target="/usr/local/libexec/argent-sentinel/collector.py"
config_path="/etc/argent-sentinel/collector.json"
stamp="$(date +%Y%m%d-%H%M%S)"
backup_dir="/var/backups/argent-sentinel/v0.3.0-${stamp}"
timer_unit="argent-sentinel-collector.timer"
service_unit="argent-sentinel-collector.service"

timer_was_active=0
systemctl is-active --quiet "${timer_unit}" && timer_was_active=1 || true
restore_timer() {
    [[ ${timer_was_active} -eq 1 ]] && systemctl start "${timer_unit}" >/dev/null 2>&1 || true
}
trap restore_timer EXIT

systemctl stop "${timer_unit}" >/dev/null 2>&1 || true
systemctl stop "${service_unit}" >/dev/null 2>&1 || true

python3 -m py_compile "${collector_source}"
python3 "${source_dir}/tests/test_collector.py"
python3 "${source_dir}/tests/test_reporting_guardrails.py"
python3 "${source_dir}/tests/test_network_context.py"
bash -n "${source_dir}/scripts/onboard-wordpress-site.sh" "${source_dir}/scripts/stage-abuse-context-log.sh"

[[ -f ${config_path} ]] || { echo "Collector configuration does not exist: ${config_path}" >&2; exit 1; }
install -d -o root -g root -m 0700 "${backup_dir}"
[[ -f ${collector_target} ]] && cp -a "${collector_target}" "${backup_dir}/collector.py"
cp -a "${config_path}" "${backup_dir}/collector.json"
install -o root -g root -m 0755 "${collector_source}" "${collector_target}"

CONFIG_PATH="${config_path}" python3 <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["CONFIG_PATH"])
config = json.loads(path.read_text(encoding="utf-8"))
config.setdefault("node", {
    "id": "nidhoggur",
    "fqdn": "nidhoggur.argentwolf.org",
    "central_url": "https://sentinel.argentwolf.org/",
})
config.setdefault("abuse_context", {
    "enabled": False,
    "incoming_globs": [
        "/var/lib/argent-sentinel/drop/nginx/*/incoming/*.jsonl",
        "/var/lib/argent-sentinel/drop/nginx/*/incoming/*.json",
    ],
    "processing_dir": "/var/lib/argent-sentinel/collector/abuse-context-processing",
    "archive_dir": "/var/lib/argent-sentinel/collector/abuse-context-archive",
    "rejected_dir": "/var/lib/argent-sentinel/collector/abuse-context-rejected",
    "max_file_bytes": 20 * 1024 * 1024,
    "max_line_bytes": 64 * 1024,
    "fallback_correlation_seconds": 2,
})
config.setdefault("network_reporting", {
    "enabled": True,
    "include_context_min_hostile_ips": 2,
    "max_tuple_evidence": 20,
    "automatic_cidr_blocking": False,
    "automatic_network_email": False,
})
enrichment = config.setdefault("enrichment", {})
agent = str(enrichment.get("user_agent", ""))
if agent.startswith("Argent-Sentinel/0.2."):
    enrichment["user_agent"] = "Argent-Sentinel/0.3.0 (+self-hosted security abuse reporting)"

temporary = path.with_suffix(path.suffix + ".tmp")
temporary.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
temporary.chmod(0o600)
temporary.replace(path)
PY

chown root:root "${config_path}"
chmod 0600 "${config_path}"
install -d -o root -g sentinel -m 2770 /var/lib/argent-sentinel/drop/nginx/abuse-context/incoming

"${collector_target}" --config "${config_path}" validate-config
"${collector_target}" --config "${config_path}" status >/dev/null

echo "Installed Argent Sentinel collector v0.3.0."
echo "Backup: ${backup_dir}"
echo "abuse_context remains disabled until its Nginx log staging path has been verified."
echo "Automatic CIDR blocking and automatic network-level email remain disabled by design."
