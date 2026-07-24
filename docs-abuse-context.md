# Nginx abuse_context ingestion

Collector v0.3.0 accepts newline-delimited JSON staged under:

```text
/var/lib/argent-sentinel/drop/nginx/abuse-context/incoming/
```

The importer is disabled by default. It supports both the normalized field names
and common Nginx aliases such as `remote_addr`, `remote_port`, `server_addr`,
`server_port`, `server_protocol`, `ssl_protocol`, `request_method`,
`request_uri`, `status`, and `http_user_agent`.

Recommended Nginx format:

```nginx
log_format abuse_context escape=json
  '{"occurred_at":"$time_iso8601",'
  '"request_id":"$request_id",'
  '"source_ip":"$remote_addr",'
  '"source_port":"$remote_port",'
  '"destination_ip":"$server_addr",'
  '"destination_port":"$server_port",'
  '"transport_protocol":"TCP",'
  '"application_protocol":"$server_protocol",'
  '"tls_protocol":"$ssl_protocol",'
  '"host":"$host",'
  '"server_name":"$server_name",'
  '"request_method":"$request_method",'
  '"request_uri":"$uri",'
  '"http_status":$status,'
  '"user_agent":"$http_user_agent"}';
```

For the matching PHP location, pass the same server-generated ID over FastCGI:

```nginx
fastcgi_param ARGENT_SENTINEL_REQUEST_ID $request_id;
```

Do not point Nginx's active file directly at the collector incoming directory.
Rotate or close the file first, then stage the completed file atomically with:

```bash
sudo ./scripts/stage-abuse-context-log.sh /path/to/rotated-abuse-context.jsonl
```

After validating the format and staging process, enable ingestion:

```bash
sudo jq '.abuse_context.enabled = true' /etc/argent-sentinel/collector.json \
  > /etc/argent-sentinel/collector.json.new
sudo install -o root -g root -m 0600 \
  /etc/argent-sentinel/collector.json.new /etc/argent-sentinel/collector.json
sudo /usr/local/libexec/argent-sentinel/collector.py \
  --config /etc/argent-sentinel/collector.json validate-config
```

Exact correlation uses request ID plus source IP. Events without a request ID can
fall back to source IP, request path, and a bounded timestamp window; reports
identify that weaker method as `timestamp-path`.
