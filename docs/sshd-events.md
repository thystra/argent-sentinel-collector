# OpenSSH authentication events

The v0.4 node agent reads `ssh.service` from systemd-journald using a durable
cursor. It accepts only high-confidence OpenSSH messages of the form
`Failed password/publickey/... for ... from IP port PORT`.

The exported event contains source IP and port, configured destination IP and
port, TCP/SSH protocol, timestamps, authentication method, and an HMAC-SHA256
account token. Targeted usernames are never exported or written to the central
database. Standalone `Invalid user` and PAM companion lines are ignored to avoid
double-counting one authentication attempt.

Default reportable thresholds are:

- eight failures against at least three account tokens within 120 seconds; or
- twelve failures against one account token within 120 seconds.

Configure the server's public destination IP so provider reports contain a
complete network tuple:

```bash
sudo argent-sentinel-configure-agent \
  --node nidhoggur \
  --fqdn nidhoggur.argentwolf.org \
  --destination-ip PUBLIC_SERVER_IP \
  --sshd --ssh-only --enable
```

`--ssh-only` is recommended on the combined central host so the existing local
WordPress and Nginx collector paths do not race the agent unnecessarily.
