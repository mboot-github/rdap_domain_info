#!/usr/bin/env python3

"""
Get the country of the holder of a domaine name.
Note that RFC 6350 (vCard) says that the country must be a full name,
but most RDAP servers use instead an ISO 3166 two-letter code
(which is certainly better).
.is is an exception.
"""

import json
import logging
import urllib

import requests
import urllib3

# Local module
import iana_rdap_domain

logger = logging.getLogger(__name__)


class RdapDomainConverter:
    domain: str  # the requted domain
    timeout: int = 10
    ssl_verify: bool

    data: dict  # the raw rdap data
    result: dict  # result data
    servers: list
    server: str

    def __init__(
        self,
        domain: str,
        *,
        ssl_verify: bool = True,
        timeout: int = 10,
    ) -> None:
        self.domain = domain
        self.ssl_verify = ssl_verify
        self.timeout = timeout

        self.data = {}
        self.result = {}

        self.ia = iana_rdap_domain.IanaRdapDomain(ssl_verify=self.ssl_verify)
        self.set_server()
        self.set_default_result()

    def set_default_result(self):
        self.result: dict = {
            "server": "",
            "data": False,
            "request": self.domain,
            "domain": "",
            "status": [],
            "nameserver": [],
            "events": {},
            "registrar": {},
            "registrant": {},
        }

    def set_server(self) -> None:
        self.servers = self.ia.find(self.domain)
        if self.servers:
            # Donuts RDAP server balks when there are two slashes and reply 404
            server = self.servers[0]
            server = server.removesuffix("/")
            self.server = server
        else:
            logger.warning(f"no server found for {self.domain}")
            self.server = None

    def get_response(self) -> bool:
        if not self.server:
            return False

        msg: str
        try:
            qd = urllib.parse.quote(self.domain)
            url = f"{self.server}/domain/{qd}"
            if url.startswith("http://"):
                url = url.replace("http://", "https://")
                logger.error(f"switch url to use https instead of http: {url}")

            response = requests.get(
                url,
                timeout=self.timeout,
                verify=self.ssl_verify,
            )
        except ConnectionRefusedError:
            return False
        except requests.exceptions.ConnectionError:
            return False
        except requests.exceptions.Timeout:
            return False
        except urllib3.exceptions.ReadTimeoutError:
            return False
        except urllib3.exceptions.MaxRetryError:
            return False

        except Exception as e:
            msg = f"request.get: {e}"
            logger.exception(msg)
            return False

        try:
            status = response.status_code
            content = response.content

            if status in {400, 403, 404, 503}:
                return False

            if status != 200:
                z = f"Invalid RDAP return code: {status} for domain:"
                if content:
                    msg = f"{z} {self.server}/{self.domain} {content.decode()}"
                else:
                    msg = f"{z} {self.server}/{self.domain}"
                logger.error(msg)
                return False
        except Exception as e:
            msg = f"get response: {e}"
            logger.exception(msg)
            return False

        if not content:
            return False

        if content[0] == ord("<"):  # html
            return False

        try:
            self.data = json.loads(content)
            k: str = "entities"

            if k not in self.data:
                msg = f"No {k} in the RDAP response"
                logger.warning(msg)
                return False
                # RFC 9083 does not really mandate to have the "entities" member.
                # But everyone has one.
                # For nic.id, it is empty.

        except Exception as e:
            msg = f"decode content: {content[0]} {e} {content[0:10]}"
            logger.exception(msg)
            return False

        return True

    def get_role_names(self):
        result = []
        for entity in self.data["entities"]:
            k = "roles"
            if entity[k]:
                if isinstance(entity[k], str):
                    role = entity[k]
                    if role not in result:
                        result.append(role)
                    continue

                for role in entity[k]:
                    if role not in result:
                        result.append(role)
        return sorted(result)

    def get_role_start(self, name: str) -> dict:
        for entity in self.data["entities"]:
            if name in entity["roles"]:
                return entity
        return {}

    def get_role_info(self, data):
        result = {}
        k = "entities"
        if k in data:
            z = data[k]
            for entity in z:
                vcard = self.get_vcard(entity)
                for role in entity["roles"]:
                    result[role] = vcard

        return result

    def get_roledata(self, name: str, data):
        r = {}
        self.result[name] = r

        info = self.get_role_info(data)
        if len(info) != 0:
            r["roles"] = info
        r["vcard"] = self.get_vcard(data)

    def vcard_adr(self, data):
        """
        7 fields
        "Mail Stop 3",   // post office box (not recommended for use)
        "Suite 3000",    // apartment or suite (not recommended for use)
        "123 Maple Ave", // street address
        "Quebec",        // locality or city name
        "QC",            // region (can be either a code or full name)
        "G1V 2M2",       // postal code
        "Canada"         // full country name
        """
        names = [
            "po_box",
            "suite",
            "street",  # can be list
            "locality",
            "region",
            "postal code",
            "country",
        ]
        if isinstance(data, list):
            if len(data) == 7:
                rr = dict(zip(names, data, strict=True))
                rrr = {}
                for k, v in rr.items():
                    if v:
                        if isinstance(v, str):
                            rrr[k] = v
                        if isinstance(v, list):
                            rrr[k] = "; ".join(v)
                            if rrr[k] == "; ; ":  # remove empty items
                                rrr[k] = ""
                return rrr
        return data

    def fix_if_adr(self, what, value):
        if isinstance(value, list):  # fix adr items
            if what == "adr" and len(value) == 7:
                return self.vcard_adr(value)
        return value

    def flatten_props_if(self, props):
        try:
            v = list(props.values())
            if isinstance(v, str):
                return v

            # print(v, file=sys.stderr)
            if len(v) == 1:
                k = v[0]
                if isinstance(k, str):
                    return k
                if len(k) == 1:
                    return k[0]

            return ",".join(v)

        except Exception as e:
            msg = f"{self.domain} {props}::{e}"
            logger.warning(msg)

        return props

    def do_vcard_item(self, item, result):
        # https://rdap.rcode3.com/protocol/jcard_and_vcard.html
        if len(item) != 4:
            msg = f"{self.domain} item len != 4: {item}"
            logger.warning(msg)
            item.append("")

        (what, props, itype, value) = (item[0], item[1], item[2], item[3])

        if what == "version":  # the version currently brings no value
            return

        if not value:  # ignore items without any value
            return

        if what == "fn":  # expand fn to someting meaningfull
            what = "full_name"

        value = self.fix_if_adr(what, value)

        if len(props) == 1:
            if what == "adr" and "cc" in props:
                value["country code"] = props["cc"]
                props = ""
            else:
                props = self.flatten_props_if(props)

        if itype not in {"text", "uri"}:  # text and uri types are self evident
            if len(props):
                result[f"{what} ({props})"] = f"{value} ({itype})"
            else:
                result[what] = f"{value} ({itype})"
        elif len(props):
            result[f"{what} ({props})"] = value
        else:
            result[what] = value

    def do_vcard(self, data):
        result = {}
        for item in data:
            self.do_vcard_item(item, result)

        return result

    def get_vcard(self, data):
        k = "vcardArray"
        if k in data:
            return self.do_vcard(data[k][1])

        return {}

    def do_redacted(self):
        k = "redacted"
        if k not in self.data:
            return

        r = {}
        self.result[k] = r
        for item in self.data[k]:
            if "name" not in item:
                return
            if "type" not in item["name"]:
                return

            name = item["name"]["type"]

            method = ""
            if "method" in item:
                method = item["method"]

            reason = ""
            if "reason" in item:
                if "description" in item["reason"]:
                    reason = item["reason"]["description"]

            if reason:
                r[name.lower()] = f"{method}: {reason}"
            else:
                r[name.lower()] = f"{method}"

        if len(r) == 0:
            del self.result[k]

    def parse_data(self):
        if not self.server:
            self.result["server"] = ""
            return
        self.result["server"] = self.server

        if self.data == {}:
            self.result["data"] = False
            return
        self.result["data"] = True

        if "secureDNS" in self.data:
            self.result["secureDNS"] = self.data["secureDNS"]["delegationSigned"]

        k = "ldhName"
        if k in self.data:
            self.result["domain"] = self.data[k]

        k = "status"
        if k in self.data:
            for status in self.data[k]:
                self.result[k].append(status)

        k = "events"
        if k in self.data:
            for event in self.data[k]:
                self.result[k][event["eventAction"]] = event["eventDate"]

        k = "nameservers"
        if k in self.data:
            for nameserver in self.data[k]:
                self.result[nameserver["objectClassName"]].append(nameserver["ldhName"])

        ll = self.get_role_names()
        for k in ll:
            self.get_roledata(k, self.get_role_start(k))

        # additional data under registrar
        rr = self.get_role_start("registrar")
        k = "publicIds"
        if k in rr:
            for item in rr[k]:
                self.result["registrar"][item["type"]] = item["identifier"]

        self.do_redacted()
