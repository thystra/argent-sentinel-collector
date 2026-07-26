#!/usr/bin/env bash
set -euo pipefail

usage() {
cat <<'EOF'
Usage:
  sudo argent-sentinel-onboard-wordpress \
    --wordpress-path PATH \
    --site-id ID \
    --node-id ID \
    --php-user USER \
    [--plugin-zip ZIP] \
    [--wp-cli PATH] \
    [--open-basedir-mode prompt|append|warn|ignore] \
    [--restart-php-fpm]

Creates the protected WordPress event drop, checks the matching PHP-FPM pool,
optionally appends the drop path to a pool-level open_basedir setting, and
configures the connector through WP-CLI.

open_basedir modes:
  prompt  Offer to append in an interactive terminal; otherwise warn.
  append  Append automatically after backup and PHP-FPM validation.
  warn    Print the exact required change without modifying configuration.
  ignore  Skip open_basedir inspection.
EOF
}

trim() {
    local value=${1-}
    value=${value#"${value%%[![:space:]]*}"}
    value=${value%"${value##*[![:space:]]}"}
    printf '%s' "$value"
}

open_basedir_contains() {
    local configured=${1-}
    local required=${2-}
    local entry normalized_required normalized_entry
    normalized_required=${required%/}
    IFS=':' read -r -a entries <<< "$configured"
    for entry in "${entries[@]}"; do
        entry=$(trim "$entry")
        [[ -n $entry ]] || continue
        [[ $entry != "." ]] || entry=$PWD
        normalized_entry=${entry%/}
        if [[ $normalized_required == "$normalized_entry" || $normalized_required == "$normalized_entry/"* ]]; then
            return 0
        fi
    done
    return 1
}

find_php_fpm_pools() {
    local php_user=$1
    local php_root=${2:-/etc/php}
    local pool
    shopt -s nullglob
    for pool in "$php_root"/*/fpm/pool.d/*.conf; do
        if awk -F= -v expected="$php_user" '
            /^[[:space:]]*[;#]/ { next }
            /^[[:space:]]*user[[:space:]]*=/ {
                value=$0
                sub(/^[^=]*=/, "", value)
                sub(/[;#].*$/, "", value)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
                if (value == expected) found=1
            }
            END { exit(found ? 0 : 1) }
        ' "$pool"; then
            printf '%s\n' "$pool"
        fi
    done
    shopt -u nullglob
}

read_pool_open_basedir() {
    local pool=$1
    python3 - "$pool" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
pattern = re.compile(
    r'^\s*php_(?:admin_)?value\[open_basedir\]\s*=\s*(.*?)\s*$'
)
last = ""
for raw in path.read_text(encoding="utf-8").splitlines():
    stripped = raw.lstrip()
    if not stripped or stripped.startswith((";", "#")):
        continue
    match = pattern.match(raw)
    if match:
        value = match.group(1)
        if ";" in value:
            value = value.split(";", 1)[0].rstrip()
        last = value
print(last)
PY
}

append_pool_open_basedir() {
    local pool=$1
    local drop=$2
    local backup_root=${3:-/var/backups/argent-sentinel/php-fpm}
    local timestamp version backup
    timestamp=$(date -u +%Y%m%dT%H%M%SZ)
    version=$(awk -F/ '{for (i=1; i<=NF; i++) if ($i=="php") {print $(i+1); exit}}' <<< "$pool")
    [[ -n $version ]] || version=unknown
    mkdir -p "$backup_root/$version"
    chmod 0750 "$backup_root" "$backup_root/$version" 2>/dev/null || true
    backup="$backup_root/$version/$(basename "$pool").${timestamp}.bak"
    cp -a -- "$pool" "$backup"

    python3 - "$pool" "$drop" <<'PY'
from pathlib import Path
import os
import re
import stat
import sys
import tempfile

path = Path(sys.argv[1])
drop = sys.argv[2].rstrip("/")
text = path.read_text(encoding="utf-8")
lines = text.splitlines(keepends=True)
pattern = re.compile(
    r'^(\s*php_(?:admin_)?value\[open_basedir\]\s*=\s*)(.*?)(\r?\n)?$'
)
matches = []
for index, raw in enumerate(lines):
    stripped = raw.lstrip()
    if not stripped or stripped.startswith((";", "#")):
        continue
    match = pattern.match(raw)
    if match:
        matches.append((index, match))

if not matches:
    raise SystemExit("No active pool-level open_basedir line was found")

index, match = matches[-1]
value = match.group(2).strip()
comment = ""
if ";" in value:
    value, comment = value.split(";", 1)
    value = value.rstrip()
    comment = " ;" + comment
entries = [item.strip().rstrip("/") for item in value.split(":") if item.strip()]
if not any(drop == item or drop.startswith(item + "/") for item in entries):
    value = value.rstrip(":") + ":" + drop
newline = match.group(3) or ""
lines[index] = match.group(1) + value + comment + newline

st = path.stat()
fd, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.writelines(lines)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, stat.S_IMODE(st.st_mode))
    try:
        os.chown(temporary, st.st_uid, st.st_gid)
    except PermissionError:
        pass
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
    printf '%s\n' "$backup"
}

php_version_for_pool() {
    local pool=$1
    awk -F/ '{for (i=1; i<=NF; i++) if ($i=="php") {print $(i+1); exit}}' <<< "$pool"
}

validate_php_fpm_version() {
    local version=$1
    local binary="php-fpm${version}"
    if ! command -v "$binary" >/dev/null 2>&1; then
        echo "WARNING: Cannot validate PHP-FPM configuration; $binary was not found." >&2
        return 0
    fi
    "$binary" -t
}

inspect_open_basedir() {
    local php_user=$1
    local drop=$2
    local mode=$3
    local restart=$4
    local php_root=${ARGENT_SENTINEL_PHP_ETC_ROOT:-/etc/php}
    local backup_root=${ARGENT_SENTINEL_BACKUP_ROOT:-/var/backups/argent-sentinel/php-fpm}
    local pool value answer backup version service
    local -a pools=()
    local -a restart_services=()

    [[ $mode != ignore ]] || return 0
    mapfile -t pools < <(find_php_fpm_pools "$php_user" "$php_root")

    if (( ${#pools[@]} == 0 )); then
        cat >&2 <<EOF
WARNING: No PHP-FPM pool with user '$php_user' was found under:
  $php_root/*/fpm/pool.d/*.conf
The WordPress status page must show that its effective open_basedir permits:
  $drop
EOF
        return 0
    fi

    for pool in "${pools[@]}"; do
        value=$(read_pool_open_basedir "$pool")
        if [[ -z $value ]]; then
            cat <<EOF
PHP-FPM pool has no active pool-level open_basedir restriction:
  $pool
No edit was made. If the pool inherits a global restriction, add:
  $drop
EOF
            continue
        fi
        if open_basedir_contains "$value" "$drop"; then
            printf 'PHP-FPM open_basedir already permits the drop path:\n  %s\n' "$pool"
            continue
        fi

        cat >&2 <<EOF
WARNING: PHP-FPM open_basedir does not permit the Argent Sentinel drop path.

Pool:
  $pool
Current value:
  $value
Required additional entry:
  $drop
EOF

        case "$mode" in
            append)
                answer=y
                ;;
            warn)
                answer=n
                ;;
            prompt)
                if [[ -t 0 ]]; then
                    read -r -p "Append the required path to this pool now? [y/N] " answer
                else
                    answer=n
                    echo "Non-interactive session: leaving PHP-FPM configuration unchanged." >&2
                fi
                ;;
            *)
                echo "Unsupported open_basedir mode: $mode" >&2
                return 2
                ;;
        esac

        if [[ $answer =~ ^[Yy]([Ee][Ss])?$ ]]; then
            backup=$(append_pool_open_basedir "$pool" "$drop" "$backup_root")
            version=$(php_version_for_pool "$pool")
            if ! validate_php_fpm_version "$version"; then
                cp -a -- "$backup" "$pool"
                echo "PHP-FPM validation failed; restored $backup" >&2
                return 1
            fi
            printf 'Updated PHP-FPM pool; backup: %s\n' "$backup"
            service="php${version}-fpm"
            restart_services+=("$service")
        else
            cat >&2 <<EOF
No change made. Append ':$drop' to the active open_basedir value in:
  $pool
Then validate and restart the matching PHP-FPM service.
EOF
        fi
    done

    if (( ${#restart_services[@]} > 0 )); then
        mapfile -t restart_services < <(
            printf '%s\n' "${restart_services[@]}" | awk '!seen[$0]++'
        )
        for service in "${restart_services[@]}"; do
            if [[ $restart == 1 ]]; then
                systemctl restart "$service"
                printf 'Restarted %s.\n' "$service"
            else
                printf 'Restart required: systemctl restart %s\n' "$service"
            fi
        done
    fi
}

main() {
    local wordpress_path="" site_id="" node_id="" php_user=""
    local plugin_zip="" wp_cli="wp" open_basedir_mode="prompt"
    local restart_php_fpm=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --wordpress-path)
                [[ $# -ge 2 ]] || { echo "--wordpress-path requires a value" >&2; exit 2; }
                wordpress_path="$2"
                shift 2
                ;;
            --site-id)
                [[ $# -ge 2 ]] || { echo "--site-id requires a value" >&2; exit 2; }
                site_id="$2"
                shift 2
                ;;
            --node-id)
                [[ $# -ge 2 ]] || { echo "--node-id requires a value" >&2; exit 2; }
                node_id="$2"
                shift 2
                ;;
            --php-user)
                [[ $# -ge 2 ]] || { echo "--php-user requires a value" >&2; exit 2; }
                php_user="$2"
                shift 2
                ;;
            --plugin-zip)
                [[ $# -ge 2 ]] || { echo "--plugin-zip requires a value" >&2; exit 2; }
                plugin_zip="$2"
                shift 2
                ;;
            --wp-cli)
                [[ $# -ge 2 ]] || { echo "--wp-cli requires a value" >&2; exit 2; }
                wp_cli="$2"
                shift 2
                ;;
            --open-basedir-mode)
                [[ $# -ge 2 ]] || { echo "--open-basedir-mode requires a value" >&2; exit 2; }
                open_basedir_mode="$2"
                shift 2
                ;;
            --restart-php-fpm)
                restart_php_fpm=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown argument: $1" >&2
                usage >&2
                exit 2
                ;;
        esac
    done

    [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }

    [[ -n $wordpress_path && -n $site_id && -n $node_id && -n $php_user ]] || { usage >&2; exit 2; }
    [[ $site_id =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || { echo "Unsafe site ID: $site_id" >&2; exit 2; }
    [[ $open_basedir_mode =~ ^(prompt|append|warn|ignore)$ ]] || { echo "Invalid --open-basedir-mode: $open_basedir_mode" >&2; exit 2; }
    id "$php_user" >/dev/null 2>&1 || { echo "Unknown PHP-FPM user: $php_user" >&2; exit 2; }
    [[ -f "$wordpress_path/wp-config.php" ]] || { echo "No wp-config.php under $wordpress_path" >&2; exit 2; }
    command -v "$wp_cli" >/dev/null 2>&1 || { echo "WP-CLI not found: $wp_cli" >&2; exit 2; }

    getent group sentinel >/dev/null || groupadd --system sentinel
    usermod -a -G sentinel "$php_user"

    local base="/var/lib/argent-sentinel/drop/wordpress"
    local site_dir="${base}/${site_id}"
    local drop="${site_dir}/incoming"
    install -d -o root -g sentinel -m 0750 "$base"
    install -d -o root -g sentinel -m 0750 "$site_dir"
    install -d -o root -g sentinel -m 2770 "$drop"

    inspect_open_basedir "$php_user" "$drop" "$open_basedir_mode" "$restart_php_fpm"

    local -a wp=(sudo -u "$php_user" -- "$wp_cli" --path="$wordpress_path")
    if [[ -n $plugin_zip ]]; then
        [[ -f $plugin_zip ]] || { echo "Plugin ZIP not found: $plugin_zip" >&2; exit 2; }
        "${wp[@]}" plugin install "$plugin_zip" --force --activate
    else
        "${wp[@]}" plugin activate argent-sentinel-wordpress >/dev/null 2>&1 || true
    fi

    if ! "${wp[@]}" help argent-sentinel setup >/dev/null 2>&1; then
        echo "The installed plugin does not register 'wp argent-sentinel setup'." >&2
        echo "Available command help follows:" >&2
        "${wp[@]}" help argent-sentinel >&2 || true
        exit 3
    fi

    "${wp[@]}" argent-sentinel setup \
        --site-id="$site_id" \
        --source-host="$node_id" \
        --drop-directory="$drop" \
        --format=json
    "${wp[@]}" argent-sentinel status --format=json
    "${wp[@]}" argent-sentinel export --format=json

    echo
    printf 'Provisioned %s on node %s.\n' "$site_id" "$node_id"
    printf 'Drop directory: %s\n' "$drop"
    if [[ $restart_php_fpm == 0 ]]; then
        echo "Restart the matching PHP-FPM pool so its new group membership and configuration take effect."
    fi
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
