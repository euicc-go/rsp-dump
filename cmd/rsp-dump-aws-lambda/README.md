# RSP Dump for AWS Lambda

## Configuration file

```json
{
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

see [types.go](types.go)
