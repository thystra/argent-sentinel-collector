<!-- Source: /home/alan/src/argent-sentinel-collector/AGENTS-PROFILE.md -->
# Alan’s Cross-Project Agent and Operator Preferences

This file contains reusable personal workflow preferences and general host
context. Project-specific architecture, deployment state, paths, and TODO
handoffs remain in each project’s `AGENTS.md`.

Do not store passwords, private keys, certificate contents, API tokens, or
other secrets here.

## Communication and architecture

- Be helpful and conversational. Use dialogue to explore architecture,
  alternatives, risks, and operational consequences.
- Explain the rationale and principles behind recommendations, including
  tradeoffs and considerations Alan may not yet have raised.
- Clearly distinguish verified facts, assumptions, proposed design, and
  production state.
- Do not claim that a patch, package, or deployment succeeded until the
  corresponding output supports that conclusion.

## Commands and host identification

- Before every command block, state the exact computer where it runs:
  `fafnir`, `nidhoggur`, `heimdall`, `hermod`, or another explicitly named
  host.
- Commands should be complete and directly copy-pasteable.
- When a root shell is expected, say so. On `nidhoggur`, Alan often uses
  `sudo -i`; therefore user-owned paths must use `/home/alan/...`, not `~/...`.
- Never confuse a ChatGPT sandbox path such as `/mnt/data/...` with a path on
  one of Alan’s computers.
- When asking Alan to edit a file, always give its full absolute path and the
  host where it exists.

## Generated files and patches

- Prefer versioned applicator/patch scripts that operate against the specified
  checkout or deployment directory.
- Put backups outside the repository working tree.
- Validate syntax, run the relevant focused and full tests, run
  `git diff --check`, and clean package output before release builds.
- Include complete review and release commands:
  `git status`, `git diff`, `git add`, `git commit`, `git push`, and an
  annotated version tag where appropriate.
- When the file format permits comments:
  - place a comment near the top containing the full source path and filename;
  - finish with a commented `EOF` marker containing that path.
- Do not add comments to formats that prohibit them, such as strict JSON.
- Preserve local work and stop on unexpected anchors rather than guessing.

## General host and network layout

### `fafnir`

- Alan’s desktop and normal development workstation.
- Normal user: `alan`.
- Source checkouts are generally below `/home/alan/src/`.
- Browser downloads are in `/home/alan/Downloads/`.
- Build and test here before production deployment.

### `nidhoggur`

- Primary Ubuntu production server and current central Argent Sentinel node.
- Hostname: `nidhoggur.argentwolf.org`.
- Known LAN addresses include `192.168.1.25` and `192.168.1.29`; verify before
  relying on a specific address.
- Runs major self-hosted services, including web, mail, WordPress, Nextcloud,
  and central security/reporting workloads.
- Production changes should be explicit, reversible, and followed by service,
  log, and path verification.
- root login via ssh is not permitted; login commands should use alan@ instead

### `heimdall`

- LAN controller and VPN-related host.
- Hostname: `heimdall.argentwolf.org`.
- Known LAN address: `192.168.1.149`; verify before relying on it.
- May operate as a remote Argent Sentinel node rather than the central server.

### `hermod`

- DigitalOcean VPS and remote/public infrastructure host.
- Hostname: `hermod.argentwolf.org`.
- Treat as a separate remote node with explicit transport and enrollment
  configuration.

## General infrastructure conventions

- Publicly routed residential IPv6 may be used on the LAN; ULA ranges alone
  are not a complete local-network allowlist.
- Stable service names are preferred over embedding a particular current
  server hostname in clients.
- Use restricted service accounts, mTLS, narrowly scoped SSH/rsync, and
  explicit drop directories instead of broad shared permissions.
- Keep sanitization and presentation tiers separate from raw security data.
- Project-specific host paths, package versions, and service behavior belong
  in that project’s `AGENTS.md`.

<!-- EOF: /home/alan/src/argent-sentinel-collector/AGENTS-PROFILE.md -->
