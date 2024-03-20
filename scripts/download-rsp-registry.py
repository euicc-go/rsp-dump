#!/usr/bin/python3
import csv
import json
from collections import defaultdict

import requests

REGISTRY_TABLE_URL = "https://github.com/CursedHardware/gsma-rsp-certificates/raw/main/registry.csv"
EXCLUDE_ADDRESSES = {
    "rsp.simhub.cn",
    "rsp.esim.whty.com.cn",
    "rsp.esim.me:8083",
    "www.esimtest.chinattl.cn",
}


def main():
    response = requests.get(REGISTRY_TABLE_URL)
    response.raise_for_status()
    issuers = defaultdict(set)
    rows = list(csv.DictReader(response.text.splitlines()))
    for row in rows:
        issuers[row["issuer"]].add(row["smdp_address"])
        issuers[row["issuer"]] -= EXCLUDE_ADDRESSES
    sorted_issuers: dict[str, list[str]] = {
        issuer: sorted(issuers[issuer])
        for issuer in sorted(issuers.keys())
        if len(issuers[issuer]) > 0
    }
    with open("rsp-registry.json", "w") as fp:
        fp.write(json.dumps(sorted_issuers, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
