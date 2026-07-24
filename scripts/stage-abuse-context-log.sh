#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ $# -eq 1 ]] || { echo "Usage: stage-abuse-context-log.sh ROTATED_JSONL" >&2; exit 2; }
source_file="$1"
[[ -f $source_file && ! -L $source_file ]] || { echo "Input must be a regular non-symlink file." >&2; exit 2; }
[[ -s $source_file ]] || exit 0
incoming="/var/lib/argent-sentinel/drop/nginx/abuse-context/incoming"
install -d -o root -g sentinel -m 2770 "$incoming"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
temporary="$incoming/.abuse-context-${stamp}-$$.jsonl.tmp"
final="$incoming/abuse-context-${stamp}-$$.jsonl"
install -o root -g sentinel -m 0640 "$source_file" "$temporary"
mv -T "$temporary" "$final"
printf '%s\n' "$final"
