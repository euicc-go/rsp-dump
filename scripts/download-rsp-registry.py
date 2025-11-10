#!/usr/bin/env python3
import csv
import json
import argparse
from collections import defaultdict
from urllib.request import urlopen

REGISTRY_TABLE_URL = "https://github.com/CursedHardware/gsma-rsp-certificates/raw/main/registry.csv"
EXCLUDE_ADDRESSES = {
    "rsp.simhub.cn",
    "rsp.esim.whty.com.cn",
    "rsp.esim.me:8083",
    "www.esimtest.chinattl.cn",
    "smdp-plus-0.eu.cd.rsp.kigen.com",
}


def main():
    parser = argparse.ArgumentParser(description="Fetch registry.csv and build rsp-registry.json")
    parser.add_argument(
        "-o", "--output", default="rsp-registry.json", help="Output JSON file path"
    )
    parser.add_argument(
        "-u", "--url", default=REGISTRY_TABLE_URL, help="CSV registry URL"
    )

    args = parser.parse_args()

    with urlopen(args.url) as resp:
        data = resp.read().decode("utf-8")

    issuers = defaultdict(set)
    rows = list(csv.DictReader(data.splitlines()))

    for row in rows:
        issuers[row["issuer"]].add(row["smdp_address"])
        issuers[row["issuer"]] -= EXCLUDE_ADDRESSES

    sorted_issuers = {
        issuer: sorted(issuers[issuer])
        for issuer in sorted(issuers.keys())
        if len(issuers[issuer]) > 0
    }

    with open(args.output, "w", encoding="utf-8") as fp:
        json.dump(sorted_issuers, fp, sort_keys=True, indent=2)


if __name__ == "__main__":
    main()