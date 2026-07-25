#!/bin/sh
set -eu

USER_NAME=${1:-admin}
PASSWORD_FILE=/etc/nginx/argent-sentinel-dashboard.htpasswd
EXAMPLE=/usr/share/argent-sentinel/nginx-sentinel-dashboard.conf.example

case "$USER_NAME" in
    *[!A-Za-z0-9._-]*|'')
        echo "Invalid username: $USER_NAME" >&2
        exit 2
        ;;
esac

if [ ! -t 0 ]; then
    echo "Run interactively so the dashboard password is not exposed." >&2
    exit 2
fi

trap 'stty echo 2>/dev/null || true' EXIT INT TERM
printf 'Password for %s: ' "$USER_NAME" >&2
stty -echo
IFS= read -r PASSWORD
stty echo
printf '\nRepeat password: ' >&2
stty -echo
IFS= read -r PASSWORD2
stty echo
printf '\n' >&2

if [ "$PASSWORD" != "$PASSWORD2" ]; then
    echo "Passwords do not match." >&2
    exit 1
fi
if [ "${#PASSWORD}" -lt 12 ]; then
    echo "Use a password of at least 12 characters." >&2
    exit 1
fi

HASH=$(printf '%s' "$PASSWORD" | openssl passwd -6 -stdin)
unset PASSWORD PASSWORD2
install -d -o root -g www-data -m 0750 /etc/nginx
umask 0077
TMP=$(mktemp)
trap 'stty echo 2>/dev/null || true; rm -f "$TMP"' EXIT INT TERM
printf '%s:%s\n' "$USER_NAME" "$HASH" > "$TMP"
install -o root -g www-data -m 0640 "$TMP" "$PASSWORD_FILE"

echo "Created $PASSWORD_FILE"
echo "Review the combined Nginx configuration:"
echo "  $EXAMPLE"
echo "It changes ssl_verify_client from 'on' to 'optional' at server scope,"
echo "then explicitly requires SUCCESS only for /v1/ingest."
