# Repository workflow

Argent Sentinel source, tests, Debian packaging and documentation belong in the
repository. Live configuration, SQLite state, logs, queues, certificates and
private keys remain outside Git.

Keep these runtime paths untracked:

- `/etc/argent-sentinel/`
- `/var/lib/argent-sentinel/`
- `/var/backups/argent-sentinel/`
- `/run/argent-sentinel/`
- Nginx logs, mail queues, generated reports and PKI private keys

Run the complete validation suite before committing a release:

```bash
python3 -m py_compile src/collector.py src/agent.py src/server_api.py packaging/build_debs.py
python3 tests/test_collector.py
python3 tests/test_reporting_guardrails.py
python3 tests/test_network_context.py
python3 tests/test_v040.py
python3 tests/test_packaging.py
find scripts -type f -name '*.sh' -print0 | xargs -0 -n1 bash -n
./scripts/build-debs.sh
```

For v0.4.0, commit and tag after reviewing the patch and built packages:

```bash
git add -A
git commit -m "Add remote transport, SSH reporting, and reporting cutover"
git tag -a v0.4.0 -m "Argent Sentinel v0.4.0"
```
