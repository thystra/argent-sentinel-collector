#!/usr/bin/env bash
set -euo pipefail

usage() {
cat <<'EOF'
Usage: sudo onboard-wordpress-site.sh --wordpress-path PATH --site-id ID --node-id ID --php-user USER [--plugin-zip ZIP] [--wp-cli PATH]

Creates the local immutable drop directory and configures Argent Sentinel through
WP-CLI options. It does not edit wp-config.php and does not contact a central server.
EOF
}

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
wordpress_path=""; site_id=""; node_id=""; php_user=""; plugin_zip=""; wp_cli="wp"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --wordpress-path) wordpress_path="$2"; shift 2 ;;
        --site-id) site_id="$2"; shift 2 ;;
        --node-id) node_id="$2"; shift 2 ;;
        --php-user) php_user="$2"; shift 2 ;;
        --plugin-zip) plugin_zip="$2"; shift 2 ;;
        --wp-cli) wp_cli="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done
[[ -n $wordpress_path && -n $site_id && -n $node_id && -n $php_user ]] || { usage >&2; exit 2; }
[[ $site_id =~ ^[a-z0-9][a-z0-9._-]{0,127}$ ]] || { echo "Unsafe site ID: $site_id" >&2; exit 2; }
id "$php_user" >/dev/null 2>&1 || { echo "Unknown PHP-FPM user: $php_user" >&2; exit 2; }
[[ -f "$wordpress_path/wp-config.php" ]] || { echo "No wp-config.php under $wordpress_path" >&2; exit 2; }
command -v "$wp_cli" >/dev/null 2>&1 || { echo "WP-CLI not found: $wp_cli" >&2; exit 2; }

getent group sentinel >/dev/null || groupadd --system sentinel
usermod -a -G sentinel "$php_user"
drop="/var/lib/argent-sentinel/drop/wordpress/${site_id}/incoming"
install -d -o root -g sentinel -m 2770 "$drop"

wp=(sudo -u "$php_user" -- "$wp_cli" --path="$wordpress_path")
if [[ -n $plugin_zip ]]; then
    [[ -f $plugin_zip ]] || { echo "Plugin ZIP not found: $plugin_zip" >&2; exit 2; }
    "${wp[@]}" plugin install "$plugin_zip" --force --activate
else
    "${wp[@]}" plugin activate argent-sentinel-wordpress >/dev/null 2>&1 || true
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
echo "Restart the matching PHP-FPM pool so its new sentinel group membership takes effect."
