# Remote transport and service identity

Argent Sentinel 0.4 uses `https://sentinel.argentwolf.org/v1/ingest` as the
stable service identity. WordPress connectors remain network-unaware: they write
immutable local files, and the host agent transports those files.

## Trust boundary

Nginx terminates TLS and requires a client certificate signed by the dedicated
Argent Sentinel node CA. It overwrites the forwarded certificate verification and full client-subject
headers. The API extracts one conservative CN from the standard Nginx
`$ssl_client_s_dn` value and uses it as the node identity. The API listens only on a Unix socket and authorizes
the certificate CN against `/etc/argent-sentinel/nodes.d/NODE.json`.

Each transport envelope contains a UUID and SHA-256 digest. Replays with the same
content are acknowledged as duplicates; reuse of a UUID with different content
is rejected.

## Server setup

1. Install the combined package.
2. Run `sudo argent-sentinel-init-ca` once.
3. Install and adapt `/usr/share/argent-sentinel/nginx-sentinel.conf.example`.
4. Ensure the public TLS certificate contains `sentinel.argentwolf.org`.
5. Enable the Nginx virtual host and test `nginx -t`.
6. Start `argent-sentinel-api.service`.

For Nidhoggur, a local `/etc/hosts` or split-DNS entry may resolve
`sentinel.argentwolf.org` to loopback or the LAN address. TLS still uses the
service hostname.

## Node enrollment

On the node:

```bash
sudo argent-sentinel-create-node-csr hermod
```

Copy `node.csr` to the server, then sign and authorize it:

```bash
sudo argent-sentinel-sign-node-csr hermod /path/to/node.csr \
  --service wordpress --service nginx --service sshd \
  --site example-org
```

Return `node.crt` from `/var/lib/argent-sentinel/enrollment/hermod/` to the
node and install it as `/etc/argent-sentinel/pki/node.crt`; keep `node.key` only
on the node. The exported `ca.crt` is useful for inspection, but it authenticates
node certificates to the central Nginx service. By default the agent verifies
the public `sentinel.argentwolf.org` server certificate through
`/etc/ssl/certs/ca-certificates.crt`. Configure a different `ca_file` only when
the HTTPS service itself uses a private server-certificate CA.

Enable the agent only after the certificate and configuration validate.
