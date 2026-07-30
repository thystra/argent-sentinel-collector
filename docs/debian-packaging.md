# Debian packages

Argent Sentinel builds four architecture-independent packages:

- `argent-sentinel-common`: collector, remote-agent and central-API engines,
  command-line interfaces, examples and documentation.
- `argent-sentinel-agent`: node transport timer, WordPress/Nginx staging helpers,
  OpenSSH journald collection, node CSR creation and agent configuration.
- `argent-sentinel-server`: central ingestion API, scheduled policy collector,
  private node CA/signing helpers and legacy-reporting cutover tooling.
- `argent-sentinel`: metapackage for a combined agent/server host such as
  Nidhoggur.

## Build

On Ubuntu 24.04 or later:

```bash
sudo apt install build-essential python3
./scripts/build-debs.sh
```

Packages and `SHA256SUMS` are written to `dist/deb/`. The build uses
`dpkg-deb` directly, normalizes ownership and timestamps, and can be made
reproducible by setting `SOURCE_DATE_EPOCH`.

## Upgrade the combined central host

Supply all four local package files to APT in one command so exact-version
package dependencies resolve without an external repository:

```bash
sudo apt install \
  ./dist/deb/argent-sentinel-common_0.5.4.0-1_all.deb \
  ./dist/deb/argent-sentinel-agent_0.5.4.0-1_all.deb \
  ./dist/deb/argent-sentinel-server_0.5.4.0-1_all.deb \
  ./dist/deb/argent-sentinel_0.5.4.0-1_all.deb
```

Existing `/etc/argent-sentinel/collector.json` and SQLite state are preserved.
A consistent SQLite backup is placed under `/var/backups/argent-sentinel/`
during server package configuration. Package installation does not enable
provider email reporting, Nginx `abuse_context` classification, or remote node
delivery in an unconfigured agent.

The server package also installs these disabled-by-configuration components:

```text
argent-sentinel-api.service
argent-sentinel-collector.timer
```

The agent package installs:

```text
argent-sentinel-agent.timer
```

The timer may be enabled while `agent.json` has `enabled: false`; in that state
the agent exits successfully without submitting data.

## Agent-only hosts

Install only `common` and `agent`:

```bash
sudo apt install \
  ./dist/deb/argent-sentinel-common_0.5.4.0-1_all.deb \
  ./dist/deb/argent-sentinel-agent_0.5.4.0-1_all.deb
```

Enroll the node with a certificate signed by the dedicated Argent Sentinel CA,
then configure its stable endpoint:

```bash
sudo argent-sentinel-create-node-csr hermod
sudo argent-sentinel-configure-agent \
  --node hermod \
  --fqdn hermod.argentwolf.org \
  --destination-ip PUBLIC_DESTINATION_IP \
  --sshd --enable
```

Do not enable the agent until `node.crt` and `node.key` are present and the
corresponding node authorization exists on the central server. The default
`ca_file` is the operating system CA bundle used to validate the public HTTPS
certificate for `sentinel.argentwolf.org`; the dedicated Sentinel node CA stays
on the central server for client-certificate validation.


## Dynamic local-address protection in 0.5.4.0

The agent package uses Debconf when installed for the first time or when an
upgrade finds no `local_address_protection` object in the preserved agent
configuration. Discovery is embedded in the package `config` script because
Debconf preconfiguration runs before the new package payload is unpacked.

The prompt shows current qualifying public IPv6 addresses, virtualization, the
candidate LAN prefix, and a recommendation. KVM/VPS/cloud/uncertain nodes are
recommended for `host` mode. Physical router-advertised or dynamic environments
may be recommended for `lan-prefix`, but a second prompt requires explicit
confirmation that the operator owns or controls the entire displayed prefix.
The remaining choices are `manual` and `off`.

For an unattended install:

```bash
sudo env DEBIAN_FRONTEND=noninteractive apt-get install \
  ./argent-sentinel-common_0.5.4.0-1_all.deb \
  ./argent-sentinel-agent_0.5.4.0-1_all.deb
```

Sentinel records unconfirmed `host` mode. It never silently broadens protection
to an interface prefix. Reopen the prompt later with:

```bash
sudo dpkg-reconfigure argent-sentinel-agent
```

Ordinary upgrades preserve an existing selection and do not prompt again.

## Removal and retained data

Removing packages stops their units but preserves configuration, SQLite state,
spools, reports and PKI material. Purging removes package-created configuration
where safe, but deliberately does not delete the private Sentinel CA or node
private keys. Remove those manually only after confirming they are no longer
needed.

## 0.5.1.1-2 upgrade serialization

The server package stops the collector timer before configuration and database
migration. It allows an active oneshot collector up to 30 seconds to finish,
then stops the service if necessary. Successful package configuration restores
the packaged timer through the normal enable/restart block.

The configuration migrator adds only missing `report_batching.state_file` and
`report_batching.grouping` keys to preserved collector configurations. Existing
operator values remain authoritative. The preserved dashboard-snapshot
configuration receives only wholly absent top-level reporting paths.
