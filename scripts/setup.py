import csv
import json
from collections import defaultdict
from scripts.utils import Manager, TaskType


def setup_rsp_registry(manager: Manager):
    tasks = [
        {
            "type": TaskType.single_content_multiple_files,
            "url": "https://github.com/CursedHardware/gsma-rsp-certificates/raw/main/registry.csv",
            "target_files": [
                "./cmd/rsp-dump-cf-workers/rsp-registry.json",
                "./rsp-registry.json",
            ],
            "processor": process_registry_content,
        }
    ]

    manager.batch_process(tasks)


def process_registry_content(csv_content: str) -> str:
    EXCLUDE_ADDRESSES = {
        "rsp.simhub.cn",
        "rsp.esim.whty.com.cn",
        "rsp.esim.me:8083",
        "www.esimtest.chinattl.cn",
        "smdp-plus-0.eu.cd.rsp.kigen.com",
    }

    issuers = defaultdict(set)
    rows = list(csv.DictReader(csv_content.splitlines()))

    for row in rows:
        addr = row.get("smdp_address")
        issuer = row.get("issuer")
        if not addr or not issuer:
            continue
        if addr not in EXCLUDE_ADDRESSES:
            issuers[issuer].add(addr)

    sorted_issuers = {issuer: sorted(addrs) for issuer, addrs in issuers.items() if addrs}

    return json.dumps(sorted_issuers, sort_keys=True, indent=2)


def setup_certificate_dir(manager: Manager):
    CERTIFICATE_ITEMS = [
        {
            "name": "CERT_S_SM_DP_TLS_NIST",
            "url": "https://gitea.osmocom.org/sim-card/pysim/raw/branch/master/smdpp-data/certs/DPtls/CERT_S_SM_DP_TLS_NIST.pem",
        },
        {
            "name": "SK_S_SM_DP_TLS_NIST",
            "url": "https://gitea.osmocom.org/sim-card/pysim/raw/branch/master/smdpp-data/certs/DPtls/SK_S_SM_DP_TLS_NIST.pem",
        },
    ]

    tasks = [
        {
            "type": TaskType.multiple_contents_multiple_files,
            "items": CERTIFICATE_ITEMS,
            "target_patterns": [
                "./cmd/rsp-dump/certificate/{name}.pem",
                "./cmd/rsp-dump-aws-lambda/certificate/{name}.pem",
            ],
        }
    ]

    manager.batch_process(tasks)


def setup(worker: bool = True):
    manager = Manager()
    setup_rsp_registry(manager)
    if not worker:
        setup_certificate_dir(manager)


if __name__ == "__main__":
    print("Start")
    import sys

    setup(len(sys.argv) == 2 and sys.argv[1] == "worker")
