#!/bin/sh
set -eu

MAP_SOURCE=/usr/share/argent-sentinel/nginx-crawler-map.conf.example
SNIPPET_SOURCE=/usr/share/argent-sentinel/nginx-crawler-enforcement.conf.example
MAP_TARGET=/etc/nginx/conf.d/argent-sentinel-crawler-map.conf
SNIPPET_TARGET=/etc/nginx/snippets/argent-sentinel-crawler-enforcement.conf

install -d -o root -g root -m 0755 /etc/nginx/conf.d /etc/nginx/snippets
install -o root -g root -m 0644 "$MAP_SOURCE" "$MAP_TARGET"
install -o root -g root -m 0644 "$SNIPPET_SOURCE" "$SNIPPET_TARGET"

if [ "$#" -eq 0 ]; then
    echo "Installed the crawler map and enforcement snippet."
    echo "To activate blocking, rerun with one or more files from"
    echo "/etc/nginx/sites-available as arguments."
    exit 0
fi

BACKUP=$(mktemp -d /var/backups/argent-sentinel/crawler-policy.XXXXXX)
trap 'rm -rf "$BACKUP"' EXIT INT TERM
CHANGED=""

for FILE in "$@"; do
    case "$FILE" in
        /etc/nginx/sites-available/*|/etc/nginx/conf.d/*)
            ;;
        *)
            echo "Refusing to edit unexpected path: $FILE" >&2
            exit 2
            ;;
    esac
    [ -f "$FILE" ] || {
        echo "Not a regular file: $FILE" >&2
        exit 2
    }
    if grep -q 'argent-sentinel-crawler-enforcement.conf' "$FILE"; then
        echo "Already configured: $FILE"
        continue
    fi
    cp -a "$FILE" "$BACKUP/$(basename "$FILE")"
    python3 - "$FILE" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
pattern = re.compile(r"(?m)^(?P<indent>[ \t]*)server[ \t]*\{[ \t]*$")
matches = list(pattern.finditer(text))
if not matches:
    raise SystemExit(f"No server block found in {path}")
parts = []
position = 0
for match in matches:
    parts.append(text[position:match.end()])
    indent = match.group("indent") + "    "
    parts.append(
        "\n"
        + indent
        + "include /etc/nginx/snippets/"
        + "argent-sentinel-crawler-enforcement.conf;"
    )
    position = match.end()
parts.append(text[position:])
path.write_text("".join(parts), encoding="utf-8")
PY
    CHANGED="$CHANGED $FILE"
done

if ! nginx -t; then
    echo "Nginx validation failed; restoring edited files." >&2
    for FILE in $CHANGED; do
        cp -a "$BACKUP/$(basename "$FILE")" "$FILE"
    done
    nginx -t || true
    exit 1
fi

systemctl reload nginx
echo "Meta-ExternalAgent now returns 403 in the edited server blocks."
echo "FacebookExternalHit remains allowed."
