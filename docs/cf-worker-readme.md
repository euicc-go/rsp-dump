# RSP Dump using KV on Cloudflare Workers

## Environment Variables

[registry]: https://github.com/CursedHardware/gsma-rsp-certificates/raw/main/registry.csv

| Variable       | Description                          | Default                              |
| -------------- | ------------------------------------ | ------------------------------------ |
| `HOMEPAGE`     | Homepage link                        | `https://septs.blog/posts/rsp-dump/` |
| `HOST_PATTERN` | Regexp for matching issuer from host | `^(?P<issuer>[a-f0-9]{6,40})\.rsp\.` |
| `KV_NAMESPACE` | Cloudflare Workers KV namespace ID   | `rsp-dump`                           |
| `SMDP`         | Directly specify the issuer host     | `null`                               |
| `RSP_REGISTRY` | JSON registry for issuers            |[`rsp-registry.json`][registry] from [`process_registry_content`](../scripts/setup.py)|

## Usage

```sh
./lpac profile download -s rsp.example.com -m <matching-id>
```

The `<matching-id>` is used as the key to store the report in KV.

### Deploy

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/euicc-go/rsp-dump.git)

### KV Routes

Cloudflare Workers exposes the following routes to interact with the KV store:

| Route | Method | Description             | Query Parameters   |
| ----- | ------ | ----------------------- | ------------------ |
| `/kv` | GET    | Retrieve a stored entry | `id=<matching-id>` |
| `/kv` | DELETE | Delete a stored entry   | `id=<matching-id>` |

## Notes

* `RSP_REGISTRY` should be a valid JSON string.
* Ensure the domain is bound and the TLS mode is set to `Off` / `Flexible` / `Full`.
* If `matching-id` is not provided, **EID** will be used **automatically**
* The `matching-id` should be a unique identifier (can be a UUID or custom string).