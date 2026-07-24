# Nginx `abuse_context` ingestion

Argent Sentinel accepts newline-delimited JSON staged under
`/var/lib/argent-sentinel/drop/nginx/abuse-context/incoming/`. The collector
supports normalized names and common Nginx aliases.

Recommended format:

```nginx
log_format abuse_context escape=json
  '{"occurred_at":"$time_iso8601",'
  '"request_id":"$request_id",'
  '"source_host":"nidhoggur",'
  '"source_ip":"$remote_addr",'
  '"source_port":"$remote_port",'
  '"destination_ip":"$server_addr",'
  '"destination_port":"$server_port",'
  '"transport_protocol":"TCP",'
  '"application_protocol":"$server_protocol",'
  '"tls_protocol":"$ssl_protocol",'
  '"host":"$host",'
  '"server_name":"$server_name",'
  '"remote_user":"$remote_user",'
  '"request_method":"$request_method",'
  '"request_uri":"$request_uri",'
  '"http_status":$status,'
  '"user_agent":"$http_user_agent"}';
```

Pass the same Nginx-generated request ID to WordPress PHP-FPM:

```nginx
fastcgi_param ARGENT_SENTINEL_REQUEST_ID $request_id;
```

Do not point Nginx's active log directly at an incoming directory. Stage a
completed or rotated JSONL file with:

```bash
sudo argent-sentinel-stage-abuse-context /var/log/nginx/abuse_context.log.1
```

v0.4 uses these observations both as exact network-tuple evidence and as an
independent hostile web-probe source.
