#!/usr/bin/env python3
# Source: /home/alan/src/argent-sentinel-collector/src/report_batcher.py
# Installed: /usr/lib/argent-sentinel/report_batcher.py
"""Hourly CIDR-level provider abuse-report batching for Argent Sentinel."""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import ipaddress
import json
import logging
import sqlite3
import subprocess
from collections import defaultdict
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Mapping, Sequence

from collector import (
    APP_VERSION,
    Collector,
    CollectorError,
    candidate_network,
    clean_optional,
    configure_logging,
    load_config,
    process_lock,
    utc_now,
)

from reporting_view import (
    atomic_write_state,
    bounded_report_networks,
    next_hourly_run,
    utc_text as reporting_utc_text,
)
from review_queue import (
    close_no_contact_review,
    open_no_contact_review,
    reopen_contact_refreshed_review,
)
LOG = logging.getLogger("argent-sentinel-report-batch")
REPORTABLE_STATES = ("pending", "failed", "deferred", "disabled", "no-contact")


def report_family(rule_id: str) -> str:
    if rule_id.startswith("sshd-"):
        return "sshd"
    if rule_id.startswith("nginx-"):
        return "web"
    return "wordpress"


def activity_name(family: str) -> str:
    return {
        "sshd": "OpenSSH authentication attacks",
        "web": "web exploit scanning",
        "wordpress": "WordPress credential attacks",
    }.get(family, "hostile activity")


def chunked(
    values: Sequence[dict[str, Any]],
    size: int,
) -> list[list[dict[str, Any]]]:
    return [
        list(values[index : index + size])
        for index in range(0, len(values), size)
    ]


def report_networks(
    source_ip: str,
    enrichment: Mapping[str, Any],
    incident: Mapping[str, Any],
    grouping: Mapping[str, Any],
) -> dict[str, Any]:
    return bounded_report_networks(
        source_ip,
        incident.get("registered_cidr") or enrichment.get("network_cidr"),
        incident.get("network_cidr"),
        grouping,
    )

def ban_only_reason(
    source_ip: str,
    asn: Any,
    user_agents: Sequence[str],
    policy: Mapping[str, Any],
) -> str | None:
    """Return a provider-email suppression reason, without changing enforcement."""

    try:
        address = ipaddress.ip_address(source_ip)
    except ValueError:
        return None

    configured_asns = {
        int(value)
        for value in policy.get("asns", [])
        if str(value).strip().isdigit()
    }
    try:
        normalized_asn = int(asn) if asn not in (None, "") else None
    except (TypeError, ValueError):
        normalized_asn = None
    if normalized_asn is not None and normalized_asn in configured_asns:
        return f"ban-only reporting policy matched AS{normalized_asn}"

    for value in policy.get("cidrs", []):
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError:
            continue
        if address in network:
            return f"ban-only reporting policy matched {network}"

    # User-Agent-only suppression is deliberately off by default because the
    # header is attacker controlled. It is available for an operator-approved
    # provider crawler that cannot be reliably identified by ownership data.
    if bool(policy.get("allow_user_agent_only", False)):
        tokens = [
            str(value).strip().lower()
            for value in policy.get("user_agent_tokens", [])
            if str(value).strip()
        ]
        for agent in user_agents:
            lowered = agent.lower()
            for token in tokens:
                if token in lowered:
                    return (
                        "ban-only reporting policy matched User-Agent token "
                        f"{token!r}"
                    )
    return None


def _incident_user_agents(
    collector: Collector,
    incident_uuid: str,
) -> list[str]:
    agents: list[str] = []
    rows = [
        *collector.db.incident_evidence(incident_uuid),
        *collector.db.incident_network_evidence(
            incident_uuid,
            int(collector.config["network_reporting"]["max_tuple_evidence"]),
        ),
    ]
    for row in rows:
        try:
            value = str(row["user_agent"] or "").strip()
        except (IndexError, KeyError):
            value = ""
        if value and value not in agents:
            agents.append(value)
    return agents


def _record_terminal(
    collector: Collector,
    incident_uuid: str,
    status: str,
    detail: str,
    *,
    recipients: Sequence[str] = (),
    message_id: str | None = None,
    attempted_epoch: int | None = None,
) -> None:
    now_epoch = int(
        attempted_epoch
        if attempted_epoch is not None
        else utc_now().timestamp()
    )
    update: dict[str, Any] = {
        "report_status": status,
        "report_detail": detail,
        "report_recipient": ", ".join(recipients),
        "report_message_id": message_id,
    }
    if status == "sent":
        update["report_sent_epoch"] = now_epoch
        update["next_report_after_epoch"] = 0
    elif status == "failed":
        update["next_report_after_epoch"] = collector.report_retry_epoch(
            now_epoch
        )
    else:
        update["next_report_after_epoch"] = 0
    collector.db.update_incident(incident_uuid, **update)
    collector.db.record_report_attempt(
        incident_uuid,
        recipients,
        status,
        detail,
        test_mode=bool(
            collector.config["abuse_reporting"].get("test_mode")
        ),
        message_id=message_id,
        attempted_epoch=now_epoch,
    )


def _fallback_enrichment(
    incident: Mapping[str, Any],
    detail: str,
) -> dict[str, Any]:
    source_ip = str(incident["source_ip"])
    return {
        "network_cidr": (
            incident.get("registered_cidr")
            or incident.get("network_cidr")
            or candidate_network(source_ip)
        ),
        "network_name": None,
        "asn": incident.get("asn"),
        "asn_holder": incident.get("asn_holder"),
        "abuse_emails": [],
        "network_class": incident.get("network_class") or "unknown",
        "_test_enrichment_error": detail,
    }


def ensure_no_contact_enforcement(
    collector: Collector,
    incident_uuid: str,
    detail: str,
    *,
    now_epoch: int,
    test_mode: bool,
) -> dict[str, Any]:
    """Verify/apply the local IP decision and close a no-contact review."""

    incident = collector.db.incident(incident_uuid)
    decision_status, decision_detail = collector.apply_decision(incident)
    collector.db.update_incident(
        incident_uuid,
        decision_status=decision_status,
        decision_detail=decision_detail,
    )
    attempted_detail = (
        f"{detail}; local decision status={decision_status}: "
        f"{decision_detail}"
    )
    if decision_status in {"applied", "existing"}:
        collector.db.update_incident(
            incident_uuid,
            report_status="no-contact",
            report_detail=attempted_detail,
            next_report_after_epoch=0,
        )
        collector.db.record_report_attempt(
            incident_uuid,
            [],
            "no-contact",
            attempted_detail,
            test_mode=test_mode,
            attempted_epoch=now_epoch,
        )
        result = close_no_contact_review(
            collector.db.conn,
            incident_uuid,
            decision_status=decision_status,
            decision_detail=decision_detail,
            report_detail=attempted_detail,
            now_epoch=now_epoch,
        )
        result["decision_status"] = decision_status
        return result
    retry_epoch = collector.report_retry_epoch(now_epoch)
    open_no_contact_review(
        collector.db.conn,
        incident_uuid,
        decision_status=decision_status,
        decision_detail=decision_detail,
        report_detail=attempted_detail,
        retry_epoch=retry_epoch,
        now_epoch=now_epoch,
    )
    collector.db.record_report_attempt(
        incident_uuid,
        [],
        "no-contact",
        attempted_detail,
        test_mode=test_mode,
        attempted_epoch=now_epoch,
    )
    return {
        "status": "open",
        "incident_uuid": incident_uuid,
        "decision_status": decision_status,
        "retry_epoch": retry_epoch,
    }

def prepare_candidates(
    collector: Collector,
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    batching = collector.config["report_batching"]
    reporting = collector.config["abuse_reporting"]
    now_epoch = int(utc_now().timestamp())
    cutoff_epoch = now_epoch - int(batching["grace_minutes"]) * 60
    max_candidates = int(batching["max_candidate_incidents"])
    marks = ",".join("?" for _ in REPORTABLE_STATES)
    rows = list(
        collector.db.conn.execute(
            f"""SELECT * FROM incidents
                WHERE report_status IN ({marks})
                  AND NOT (
                      report_status = 'no-contact'
                      AND COALESCE(review_status, 'open') = 'closed'
                      AND COALESCE(review_disposition, '')
                          != 'contact-refresh-requested'
                  )
                  AND COALESCE(next_report_after_epoch, 0) <= ?
                  AND last_seen_epoch <= ?
                ORDER BY last_seen_epoch ASC, created_at ASC
                LIMIT ?""",
            (*REPORTABLE_STATES, now_epoch, cutoff_epoch, max_candidates),
        )
    )
    result: list[dict[str, Any]] = []
    stats = {
        "eligible": len(rows),
        "suppressed": 0,
        "failed": 0,
        "no_contact": 0,
        "auto_closed_no_contact": 0,
        "contact_refreshed": 0,
    }
    for original in rows:
        incident_uuid = str(original["incident_uuid"])
        incident = collector.db.incident(incident_uuid)
        review_disposition = str(
            incident["review_disposition"] or ""
        )
        refresh_only = review_disposition == "contact-refresh-requested"
        test_mode = bool(reporting.get("test_mode"))
        if not refresh_only:
            gate = collector.report_time_gate(incident)
            if gate is not None:
                status, detail = gate
                policy_override = (
                    review_disposition == "credential-spray-approved"
                    and (
                        "production review" in str(detail).lower()
                        or "persistent wordpress" in str(detail).lower()
                    )
                )
                if not policy_override:
                    _record_terminal(collector, incident_uuid, status, detail)
                    stats["suppressed"] += 1
                    continue
            protection, protection_detail = collector.source_protection_status(
                str(incident["source_ip"])
            )
            if protection == "protected" and not test_mode:
                _record_terminal(
                    collector,
                    incident_uuid,
                    "suppressed",
                    protection_detail,
                )
                stats["suppressed"] += 1
                continue
            if protection == "error" and not test_mode:
                _record_terminal(
                    collector,
                    incident_uuid,
                    "failed",
                    f"Abuse report withheld: {protection_detail}",
                )
                stats["failed"] += 1
                continue
        try:
            enrichment = collector.enrich(str(incident["source_ip"]))
        except Exception as exc:
            detail = f"Enrichment failed before hourly abuse report: {exc}"
            if test_mode:
                enrichment = _fallback_enrichment(dict(incident), detail)
            else:
                _record_terminal(
                    collector,
                    incident_uuid,
                    "failed",
                    detail,
                )
                stats["failed"] += 1
                continue
        collector.db.update_incident(
            incident_uuid,
            registered_cidr=enrichment.get("network_cidr"),
            asn=enrichment.get("asn"),
            asn_holder=enrichment.get("asn_holder"),
            network_class=enrichment.get("network_class", "unknown"),
        )
        incident = collector.db.incident(incident_uuid)
        incident_dict = dict(incident)
        agents = _incident_user_agents(collector, incident_uuid)
        if not refresh_only:
            suppression = ban_only_reason(
                str(incident["source_ip"]),
                incident["asn"] or enrichment.get("asn"),
                agents,
                batching.get("ban_only", {}),
            )
            if suppression is not None:
                detail = (
                    f"{suppression}; local IP enforcement remains active; "
                    "provider email suppressed"
                )
                _record_terminal(
                    collector,
                    incident_uuid,
                    "suppressed",
                    detail,
                )
                stats["suppressed"] += 1
                continue
        recipients = collector.report_recipients(enrichment)
        if refresh_only and recipients:
            detail = (
                "Credential-spray contact refresh found usable recipient(s): "
                + ", ".join(recipients)
            )
            reopen_contact_refreshed_review(
                collector.db.conn,
                incident_uuid,
                recipients=list(recipients),
                now_epoch=now_epoch,
            )
            collector.db.record_report_attempt(
                incident_uuid,
                recipients,
                "contact-refreshed",
                detail,
                test_mode=test_mode,
                attempted_epoch=now_epoch,
            )
            stats["contact_refreshed"] += 1
            stats["suppressed"] += 1
            continue
        if not recipients:
            detail = "No RDAP abuse email was found"
            outcome = ensure_no_contact_enforcement(
                collector,
                incident_uuid,
                detail,
                now_epoch=now_epoch,
                test_mode=test_mode,
            )
            if outcome.get("status") == "closed":
                stats["auto_closed_no_contact"] += 1
            stats["no_contact"] += 1
            continue
        networks = report_networks(
            str(incident["source_ip"]),
            enrichment,
            incident_dict,
            batching["grouping"],
        )
        result.append(
            {
                "incident": incident_dict,
                "enrichment": dict(enrichment),
                "recipients": tuple(recipients),
                **networks,
                "family": report_family(str(incident["rule_id"])),
                "user_agents": agents,
            }
        )
    return result, stats

def group_candidates(
    candidates: Sequence[dict[str, Any]],
) -> dict[tuple[Any, ...], list[dict[str, Any]]]:
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for item in candidates:
        key = (
            item["batch_cidr"],
            item["family"],
            tuple(item["recipients"]),
        )
        grouped[key].append(item)
    return dict(grouped)

def _materialize_xarf(
    collector: Collector,
    candidate: Mapping[str, Any],
    generated: dt.datetime,
) -> tuple[dict[str, Any], list[str], list[str]]:
    incident = candidate["incident"]
    incident_uuid = str(incident["incident_uuid"])
    evidence = collector.db.incident_evidence(incident_uuid)
    sites = collector.db.incident_sites(incident_uuid)
    network_evidence = collector.db.incident_network_evidence(
        incident_uuid,
        int(collector.config["network_reporting"]["max_tuple_evidence"]),
    )
    hosts = collector._report_target_hosts(evidence, network_evidence)
    observed_destinations = [
        collector._report_value(row, "destination_ip")
        for row in [*network_evidence, *evidence]
        if collector._report_value(row, "destination_ip")
    ]
    resolution, public_targets = collector._resolve_public_targets(
        hosts,
        observed_destinations,
    )
    connections = collector._report_connections(
        incident,
        evidence,
        network_evidence,
        resolution,
        public_targets,
    )
    evidence_lines = [
        collector._normalized_evidence_line(item)
        for item in connections
    ]
    xarf = collector._xarf_attachment(
        incident,
        candidate["enrichment"],
        activity_name(str(candidate["family"])),
        connections,
        hosts or sites,
        generated,
        evidence_lines,
        public_targets,
    )
    xarf["batch_network"] = str(candidate["batch_cidr"])
    xarf["registered_network"] = candidate.get("registered_cidr")
    xarf["network_grouping_basis"] = candidate.get("grouping_basis")
    return xarf, evidence_lines, hosts or sites

def send_batch(
    collector: Collector,
    batch_cidr: str,
    family: str,
    recipients: Sequence[str],
    candidates: Sequence[dict[str, Any]],
) -> tuple[str, str, str | None]:
    settings = collector.config["abuse_reporting"]
    if not settings.get("enabled"):
        return "disabled", "Abuse reporting disabled in configuration", None
    if not recipients:
        return "no-contact", "No valid abuse-report recipient was supplied", None
    test_mode = bool(settings.get("test_mode"))
    generated = utc_now()
    message = EmailMessage()
    message["From"] = str(settings["from"])
    message["To"] = ", ".join(recipients)
    if not test_mode and str(settings.get("admin_copy", "")).strip():
        message["Bcc"] = str(settings["admin_copy"]).strip()
    message["Date"] = email.utils.format_datetime(generated)
    message_id = email.utils.make_msgid(
        domain=str(settings["message_id_domain"])
    )
    message["Message-ID"] = message_id
    unique_sources = sorted(
        {str(item["incident"]["source_ip"]) for item in candidates},
        key=ipaddress.ip_address,
    )
    registered_allocations = sorted(
        {
            str(item["registered_cidr"])
            for item in candidates
            if item.get("registered_cidr")
        }
    )
    broad_registered = any(
        bool(item.get("broad_registered_allocation"))
        for item in candidates
    )
    family_name = activity_name(family)
    test_label = " TEST" if test_mode else ""
    message["Subject"] = (
        f"{settings['subject_prefix']}{test_label} Hourly CIDR batch: "
        f"{family_name} from {batch_cidr} "
        f"({len(unique_sources)} source IPs)"
    )
    earliest = min(str(item["incident"]["first_seen"]) for item in candidates)
    latest = max(str(item["incident"]["last_seen"]) for item in candidates)
    event_count = sum(
        int(item["incident"]["event_count"]) for item in candidates
    )
    all_sites: set[str] = set()
    body: list[str] = []
    if test_mode:
        body.extend(
            [
                "*** TEST MODE ***",
                "This batch was sent only to the configured recipient override.",
                "*** TEST MODE ***",
                "",
            ]
        )
    body.extend(
        [
            "Hello,",
            "",
            "This hourly report aggregates independently qualifying Argent "
            "Sentinel incidents within one bounded evidence prefix.",
            "",
            f"Batch CIDR: {batch_cidr}",
            "Registered allocation(s): "
            + (
                ", ".join(registered_allocations)
                if registered_allocations
                else "unavailable"
            ),
            f"Activity: {family_name}",
            f"Source IPs: {len(unique_sources)}",
            f"Incidents: {len(candidates)}",
            f"Matched events: {event_count}",
            f"Observed timeframe (UTC): {earliest} through {latest}",
        ]
    )
    if broad_registered:
        body.extend(
            [
                "Scope note: ownership data returned a broader registered "
                "allocation; this report is intentionally bounded to the "
                "evidence prefix shown above.",
            ]
        )
    body.extend(["", "Per-source summary:"])
    materialized: list[tuple[dict[str, Any], list[str], list[str]]] = []
    for number, item in enumerate(candidates, 1):
        incident = item["incident"]
        xarf, evidence_lines, sites = _materialize_xarf(
            collector,
            item,
            generated,
        )
        materialized.append((xarf, evidence_lines, sites))
        all_sites.update(sites)
        body.append(
            f"  {number:>3}. {incident['source_ip']} "
            f"rule={incident['rule_id']} events={incident['event_count']} "
            f"first={incident['first_seen']} last={incident['last_seen']} "
            f"sites={','.join(sites) or 'unknown'}"
        )
        for line in evidence_lines[:3]:
            body.append(f"       evidence: {line}")
    body.extend(
        [
            "",
            "Affected site(s): "
            + (", ".join(sorted(all_sites)) or "unknown"),
            "",
            "Please investigate the responsible systems or customers and take "
            "appropriate action.",
            "",
            "No passwords, cookies, email addresses, or targeted usernames are "
            "included.",
        ]
    )
    attach_xarf = bool(settings.get("attach_xarf", True))
    if attach_xarf:
        body.append(
            "Machine-readable XARF JSON documents are attached, one per incident."
        )
    operator_contact = clean_optional(settings.get("operator_contact"), 254)
    if operator_contact:
        body.append(f"Operator contact: {operator_contact}")
    message.set_content("\n".join(body) + "\n")
    if attach_xarf:
        single = len(materialized) == 1
        for number, (xarf, _lines, _sites) in enumerate(materialized, 1):
            incident_uuid = str(
                candidates[number - 1]["incident"]["incident_uuid"]
            )
            filename = (
                "xarf.json"
                if single
                else f"xarf-{number:03d}-{incident_uuid[:8]}.json"
            )
            message.add_attachment(
                json.dumps(
                    xarf,
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=False,
                ).encode("utf-8"),
                maintype="application",
                subtype="json",
                filename=filename,
            )
    try:
        result = subprocess.run(
            [str(settings["sendmail_path"]), "-t", "-oi"],
            input=message.as_bytes(),
            capture_output=True,
            timeout=int(settings["send_timeout_seconds"]),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "failed", f"sendmail failed: {exc}", message_id
    if result.returncode != 0:
        detail = (
            clean_optional(
                result.stderr.decode("utf-8", "replace"),
                1000,
            )
            or f"sendmail exited {result.returncode}"
        )
        return "failed", detail, message_id
    return (
        "sent",
        f"Hourly CIDR batch sent to {', '.join(recipients)}; "
        f"batch_cidr={batch_cidr}; "
        f"registered_cidrs={','.join(registered_allocations) or 'unavailable'}; "
        f"incidents={len(candidates)}; sources={len(unique_sources)}",
        message_id,
    )

def run_report_batches(collector: Collector) -> dict[str, Any]:
    batching = collector.config["report_batching"]
    if not batching.get("enabled"):
        return {
            "status": "disabled",
            "detail": "report_batching.enabled is false",
            "messages_sent": 0,
        }
    if not collector.config["abuse_reporting"].get("enabled"):
        return {
            "status": "disabled",
            "detail": "abuse_reporting.enabled is false",
            "messages_sent": 0,
        }
    candidates, preparation_stats = prepare_candidates(collector)
    groups = group_candidates(candidates)
    max_incidents = int(batching["max_incidents_per_message"])
    max_messages = int(batching["max_messages_per_run"])
    messages_sent = 0
    messages_failed = 0
    deferred = 0
    handled_incidents = 0
    group_summaries: list[dict[str, Any]] = []
    for (batch_cidr, family, recipients), grouped in sorted(
        groups.items(),
        key=lambda item: (item[0][0], item[0][1], item[0][2]),
    ):
        group_summaries.append(
            {
                "batch_cidr": batch_cidr,
                "registered_allocations": sorted(
                    {
                        str(item["registered_cidr"])
                        for item in grouped
                        if item.get("registered_cidr")
                    }
                ),
                "broad_registered_allocation": any(
                    bool(item.get("broad_registered_allocation"))
                    for item in grouped
                ),
                "family": family,
                "recipients": list(recipients),
                "incidents": len(grouped),
                "sources": len(
                    {
                        str(item["incident"]["source_ip"])
                        for item in grouped
                    }
                ),
            }
        )
        for batch in chunked(grouped, max_incidents):
            if messages_sent + messages_failed >= max_messages:
                break
            recipient_gate = collector.report_recipient_gate(recipients)
            if recipient_gate is not None:
                status, detail, next_epoch = recipient_gate
                for item in batch:
                    incident_uuid = str(item["incident"]["incident_uuid"])
                    collector.db.update_incident(
                        incident_uuid,
                        report_status=status,
                        report_detail=detail,
                        report_recipient=", ".join(recipients),
                        next_report_after_epoch=next_epoch,
                    )
                    collector.db.record_report_attempt(
                        incident_uuid,
                        recipients,
                        status,
                        detail,
                        test_mode=bool(
                            collector.config["abuse_reporting"].get(
                                "test_mode"
                            )
                        ),
                    )
                deferred += len(batch)
                continue
            status, detail, message_id = send_batch(
                collector,
                str(batch_cidr),
                str(family),
                recipients,
                batch,
            )
            attempted_epoch = int(utc_now().timestamp())
            for item in batch:
                _record_terminal(
                    collector,
                    str(item["incident"]["incident_uuid"]),
                    status,
                    detail,
                    recipients=recipients,
                    message_id=message_id,
                    attempted_epoch=attempted_epoch,
                )
            handled_incidents += len(batch)
            if status == "sent":
                messages_sent += 1
            else:
                messages_failed += 1
        if messages_sent + messages_failed >= max_messages:
            break
    return {
        "status": "ok",
        "messages_sent": messages_sent,
        "messages_failed": messages_failed,
        "incidents_handled": handled_incidents,
        "incidents_deferred": deferred,
        "groups": len(groups),
        "group_summaries": group_summaries,
        "preparation": preparation_stats,
    }

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Send queued Argent Sentinel CIDR abuse-report batches"
    )
    parser.add_argument(
        "--config",
        default="/etc/argent-sentinel/collector.json",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    configure_logging(args.verbose)
    try:
        config = load_config(Path(args.config))
        with process_lock(Path(config["lock_file"])):
            collector = Collector(config)
            try:
                result = run_report_batches(collector)
                result["version"] = APP_VERSION
                result["generated_at"] = reporting_utc_text()
                result["next_scheduled_at"] = next_hourly_run()
                result["counts"] = collector.db.counts()
                atomic_write_state(
                    Path(str(config["report_batching"]["state_file"])),
                    result,
                )
                print(json.dumps(result, indent=2, sort_keys=True))
            finally:
                collector.close()
        return 0
    except (CollectorError, sqlite3.Error, OSError, ValueError) as exc:
        LOG.error("%s", exc)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())

# EOF: /home/alan/src/argent-sentinel-collector/src/report_batcher.py
