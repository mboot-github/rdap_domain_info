#!/usr/bin/env python3

import json
import logging
import pathlib
import sys

# local modules
import iana_rdap_domain
import rdap_domain_converter

logger = logging.getLogger()


def getAllRdapServers():
    XXX = []
    ia = iana_rdap_domain.IanaRdapDomain()
    for item in ia.database["services"]:
        server = item[1][0].split("/")[2]
        if server not in XXX:
            XXX.append(server)
    return XXX


def get_domains():
    if len(sys.argv) == 1:
        #  print(f"Usage: {sys.argv[0]} domain-names")
        zz = getAllRdapServers()
        for server in zz:
            a = server.split(".")
            s = ".".join(a[-2:])
            print(f"{s}")
        sys.exit(0)
    return sys.argv[1:]


def xmain():
    domains = get_domains()
    for domain in domains:
        rdc = rdap_domain_converter.RdapDomainConverter(
            domain,
            ssl_verify=False,
            timeout=30,
        )
        rdc.get_response()
        rdc.parse_data()
        print(json.dumps(rdc.result, indent=2))

        pathlib.Path(f"tmp/{domain}.json").write_text(
            json.dumps(
                rdc.data,
                indent=2,
            ),
            encoding="utf8",
        )


xmain()
