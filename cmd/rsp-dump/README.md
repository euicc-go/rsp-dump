# RSP Dump for Local Service

## Configuration file

```json
{
  "listen": "localhost:33000",
  "cert_file": "rsp.example.com.pem",
  "key_file": "rsp.example.com-key.pem",
  "host_template": "%s.rsp.example.com",
  "smtp_host": "[DATA EXPAND]",
  "smtp_username": "[DATA EXPAND]",
  "smtp_password": "[DATA EXPAND]",
  "smtp_headers": {
    "From": [
      "[DATA EXPAND]"
    ]
  }
}
```

more see [types.go](types.go)

## Systemd Service

```ini
[Unit]
Description = RSP Dump
After = network.target

[Service]
Type = simple
ExecStart = /opt/rsp-dump/rsp-dump
WorkingDirectory = /opt/rsp-dump
Restart = always
RestartSec = 10

[Install]
WantedBy = multi-user.target
```
