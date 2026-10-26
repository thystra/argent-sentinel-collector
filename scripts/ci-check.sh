#!/usr/bin/env bash
# scripts/ci-check.sh
# Argent Sentinel repository validation used by Forgejo Actions and locally on
# fafnir. Builds nothing that is installed; touches no host configuration.
#
#   scripts/ci-check.sh            # lint + full unit test suite
#   scripts/ci-check.sh --packages # also build .debs into a temporary directory
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

build_packages=0
for argument in "$@"; do
    case "$argument" in
        --packages) build_packages=1 ;;
        *) echo "unknown argument: $argument" >&2; exit 2 ;;
    esac
done

python="${PYTHON:-python3}"
export PYTHONDONTWRITEBYTECODE=1
"$python" --version

echo "== whitespace (git diff --check over the tracked tree)"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git diff --check "$(git hash-object -t tree /dev/null)" HEAD
fi

echo "== MANIFEST.sha256"
sha256sum --check --quiet MANIFEST.sha256

echo "== shell syntax"
for script in scripts/*.sh; do
    bash -n "$script"
done
for script in packaging/deb/*; do
    [ -f "$script" ] && sh -n "$script"
done

echo "== Python syntax"
# Compile into a throwaway location so no __pycache__ lands in the checkout.
"$python" - <<'PY'
import pathlib, py_compile, sys, tempfile
failed = 0
with tempfile.TemporaryDirectory() as tmp:
    for index, path in enumerate(sorted(pathlib.Path(".").glob("**/*.py"))):
        if "dist" in path.parts:
            continue
        try:
            py_compile.compile(str(path), cfile=f"{tmp}/{index}.pyc", doraise=True)
        except py_compile.PyCompileError as error:
            failed += 1
            print(error, file=sys.stderr)
sys.exit(1 if failed else 0)
PY

echo "== JSON examples"
for example in config/*.json.example config/*/*.json.example; do
    [ -f "$example" ] || continue
    "$python" -m json.tool "$example" >/dev/null
done

echo "== unit tests"
failures=0
for test in tests/test_*.py; do
    if "$python" "$test" >"${TMPDIR:-/tmp}/argent-sentinel-ci-$(basename "$test").log" 2>&1; then
        echo "ok   $test"
    else
        echo "FAIL $test"
        cat "${TMPDIR:-/tmp}/argent-sentinel-ci-$(basename "$test").log"
        failures=$((failures + 1))
    fi
done
if [ "$failures" -ne 0 ]; then
    echo "$failures test file(s) failed" >&2
    exit 1
fi

if [ "$build_packages" -eq 1 ]; then
    echo "== Debian package build (build-only, nothing installed)"
    output="$(mktemp -d)"
    trap 'rm -rf "$output"' EXIT
    "$python" packaging/build_debs.py --skip-tests --revision 1 --output-dir "$output"
    (cd "$output" && sha256sum --check SHA256SUMS)
    for package in "$output"/*.deb; do
        dpkg-deb --contents "$package" >/dev/null
    done
fi

echo "== all checks passed"
# EOF scripts/ci-check.sh
