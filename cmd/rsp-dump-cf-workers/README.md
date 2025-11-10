# RSP Dump using KV on Cloudflare Workers

## Environment Variables

| Variable       | Description                          | Default                              |
| -------------- | ------------------------------------ | ------------------------------------ |
| `HOMEPAGE`     | Homepage link                        | `https://septs.blog/posts/rsp-dump/` |
| `HOST_PATTERN` | Regexp for matching issuer from host | `^(?P<issuer>[a-f0-9]{6,40})\.rsp\.` |
| `RSP_REGISTRY` | JSON registry for issuers            | Content of `rsp-registry.json`       |
| `KV_NAMESPACE` | Cloudflare Workers KV namespace ID   | `rsp-dump`                           |

## Usage

```sh
./lpac profile download -s rsp.example.com -m <matching-id>
```

The `<matching-id>` is used as the key to store the report in KV.

### KV Routes

Cloudflare Workers exposes the following routes to interact with the KV store:

| Route | Method | Description             | Query Parameters   |
| ----- | ------ | ----------------------- | ----------------   |
| `/kv` | GET    | Retrieve a stored entry | `id=<matching-id>` |
| `/kv` | DELETE | Delete a stored entry   | `id=<matching-id>` |

## Notes

* `RSP_REGISTRY` should be a valid JSON string.
* Ensure the domain is bound and the TLS mode is set to `Off` / `Flexible` / `Full`.
* The matching ID should be a unique identifier (can be a UUID or custom string).

