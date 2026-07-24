#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run this installer as root." >&2
    exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_dir="$(cd -- "${script_dir}/.." && pwd)"
collector_source="${source_dir}/src/collector.py"
collector_target="/usr/local/libexec/argent-sentinel/collector.py"
config_path="/etc/argent-sentinel/collector.json"
timer_unit="argent-sentinel-collector.timer"
service_unit="argent-sentinel-collector.service"
stamp="$(date +%Y%m%d-%H%M%S)"
backup_dir="/var/backups/argent-sentinel/v0.2.2-${stamp}"

timer_was_active=0
if systemctl is-active --quiet "${timer_unit}"; then
    timer_was_active=1
fi

restore_timer() {
    if [[ ${timer_was_active} -eq 1 ]]; then
        systemctl start "${timer_unit}" >/dev/null 2>&1 || true
    fi
}
trap restore_timer EXIT

systemctl stop "${timer_unit}" >/dev/null 2>&1 || true
systemctl stop "${service_unit}" >/dev/null 2>&1 || true

python3 -m py_compile "${collector_source}"
python3 "${source_dir}/tests/test_collector.py"
python3 "${source_dir}/tests/test_reporting_guardrails.py"

install -d -o root -g root -m 0700 "${backup_dir}"
if [[ -f ${collector_target} ]]; then
    cp -a "${collector_target}" "${backup_dir}/collector.py"
fi
if [[ -f ${config_path} ]]; then
    cp -a "${config_path}" "${backup_dir}/collector.json"
else
    echo "Collector configuration does not exist: ${config_path}" >&2
    exit 1
fi

install -o root -g root -m 0755 "${collector_source}" "${collector_target}"

CONFIG_PATH="${config_path}" python3 <<'PY'
import json
import os
from pathlib import Path

path = Path(os.environ["CONFIG_PATH"])
config = json.loads(path.read_text(encoding="utf-8"))
reporting = config.setdefault("abuse_reporting", {})
defaults = {
    "enabled": False,
    "test_mode": False,
    "from": "",
    "admin_copy": "",
    "recipient_override": "",
    "sendmail_path": "/usr/sbin/sendmail",
    "send_timeout_seconds": 30,
    "subject_prefix": "[Argent Sentinel]",
    "message_id_domain": "argentwolf.org",
    "operator_contact": "",
    "max_evidence_uuids": 20,
    "max_reports_per_run": 3,
    "max_report_age_hours": 24,
    "recipient_cooldown_minutes": 15,
    "max_reports_per_recipient_per_day": 10,
    "report_not_before_utc": "",
    "retry_backoff_minutes": 60,
}
for key, value in defaults.items():
    reporting.setdefault(key, value)

enrichment = config.setdefault("enrichment", {})
user_agent = str(enrichment.get("user_agent", ""))
if user_agent.startswith("Argent-Sentinel/0.2.1"):
    enrichment["user_agent"] = user_agent.replace(
        "Argent-Sentinel/0.2.1",
        "Argent-Sentinel/0.2.2",
        1,
    )

temporary = path.with_suffix(path.suffix + ".tmp")
temporary.write_text(json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
temporary.chmod(0o600)
temporary.replace(path)
PY

chown root:root "${config_path}"
chmod 0600 "${config_path}"

"${collector_target}" --config "${config_path}" validate-config
"${collector_target}" --config "${config_path}" status >/dev/null

echo "Installed Argent Sentinel collector reporting guardrails."
echo "Backup: ${backup_dir}"
echo "Abuse reporting was not enabled or otherwise activated by this installer."
