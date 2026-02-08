#!/usr/bin/env python3

"""
A simple module to get the RDAP server for a given
    domain name,
    IP prefix or
    object,
    from the IANA databases specified in RFC 9224/8521.
"""

import datetime
import fcntl
import json
import logging
import os
import pathlib
import ssl
import sys
import time

import requests

logger = logging.getLogger(__name__)

IANABASES = {
    "domains": "https://data.iana.org/rdap/dns.json",
}

CACHE_BASE = os.environ["HOME"]
MY_DIR = ".iana_rdap_caches"
MAXAGE = 24  # Hours. Used only if the server no longer gives the information.
HTTP_DATE_FORMAT = "%a, %d %b %Y %H:%M:%S %Z"  # Don't touch


# RFC 9111, section 5.2
def parse_cachecontrol(h: str):
    result: dict = {}
    directives: list = h.split(",")

    for directive in directives:
        d = directive.strip()
        if "=" in d:
            key, value = d.split("=")
        else:
            key = d
            value = None

        result[key.lower()] = value
    return result


def parse_expires(h):
    return datetime.datetime.strptime(h, HTTP_DATE_FORMAT)


class IanaRdapDomain:
    def __init__(
        self,
        *,
        category="domains",
        maxage: int = -1,
        cachedir: str = f"{CACHE_BASE}/{MY_DIR}",
        maxtests: int = 3,
        timeout: int = 10,
        ssl_verify: bool = True,
    ) -> None:
        """
        Retrieves the IANA self.database, if not already cached.
        Maxage is in hours.
        The cachedir is a directory (it will be created if not exists).
        """
        self.category = category
        self.maxage = maxage
        self.cachedir = cachedir
        self.cache_valid = False
        self.maxtests = maxtests
        self.timeout = timeout
        self.ssl_verify = ssl_verify
        if ssl_verify is False:
            requests.packages.urllib3.disable_warnings()
        self.prep()
        self.make_exp_file()
        self.load_database()

        # --------------------------------------
        self.description = self.database["description"]
        self.publication = self.database["publication"]
        self.version = self.database["version"]
        self.services = {}

        if self.category != "domains":
            # IP addresses will be complicated, because of the longest prefix rule.
            msg = f"Unsupported category {self.category}"
            raise Exception(msg)

        self.do_domain()
        if not self.cache_valid:
            self.make_cache_from_content()

    def prep(self) -> None:
        if not pathlib.Path(self.cachedir).exists():
            pathlib.Path(self.cachedir).mkdir()
        self.cachefile = str(pathlib.Path(self.cachedir) / (self.category + ".json"))
        self.lockname = self.cachefile + ".lock"
        self.expirationfile = self.cachefile + ".expires"

    def make_exp_file(self) -> None:
        if self.maxage >= 0:
            with pathlib.Path(self.expirationfile).open("w", encoding="utf8"):
                z = datetime.datetime.now() + datetime.timedelta(hours=self.maxage)
                self.expirationtime = time.mktime((z).timetuple())
                times = (self.expirationtime, self.expirationtime)
                os.utime(self.expirationfile, times=times)

    def exp_file_is_recent(self):
        exp_file_exists = pathlib.Path(self.expirationfile).exists()
        exp_file_mtime = datetime.datetime.fromtimestamp(pathlib.Path(self.expirationfile).stat().st_mtime)
        now = datetime.datetime.now()
        return exp_file_exists and exp_file_mtime > now  # in the future returns true

    def load_from_cache(self):
        self.content = pathlib.Path(self.cachefile).read_text(encoding="utf8")
        self.unlock()

        try:
            if self.content:
                self.database = json.loads(self.content)
                self.loaded = True
                self.retrieved = datetime.datetime.fromtimestamp(pathlib.Path(self.cachefile).stat().st_mtime)
                self.cache_valid = True
                return (True, "")
        except json.decoder.JSONDecodeError:
            pathlib.Path(self.cachefile).unlink()  # Delete it without mercy
            return (False, f"Invalid JSON self.content in {self.cachefile}")
        except Exception as e:
            pathlib.Path(self.cachefile).unlink()  # Delete it without mercy
            return (False, f"{self.cachefile} :: {e}")

        pathlib.Path(self.cachefile).unlink()  # Delete it without mercy
        return (False, "")

    def load_from_server(self):
        self.unlock()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            server = IANABASES[self.category]
            response = requests.get(
                server,
                timeout=self.timeout,
                verify=self.ssl_verify,
            )
        except Exception as e:
            msg = f"Excetion at: {self.category} {server}:: {e}"
            logger.error(msg)
            sys.exit(1)

        expirationtime = None
        if "cache-control" in response.headers:
            directives = parse_cachecontrol(response.headers["cache-control"])
            if "max-age" in directives:
                maxage = int(directives["max-age"])
                expirationtime = datetime.datetime.now() + datetime.timedelta(seconds=maxage)

        if not expirationtime:
            if "expires" in response.headers:
                expirationtime = parse_expires(response.headers["expires"])
            else:
                expirationtime = datetime.datetime.now() + datetime.timedelta(hours=MAXAGE)

        self.expirationtime = time.mktime(expirationtime.timetuple())
        s_code = response.status_code
        if s_code != 200:
            time.sleep(2)
            msg = f"Invalid HTTPS return code when trying to get {server}: {s_code}"
            return (False, msg)

        self.loaded = True
        self.retrieved = datetime.datetime.now()
        try:
            self.content = response.content
            self.database = json.loads(self.content)
            with pathlib.Path(self.expirationfile).open("w", encoding="utf8"):
                times = (self.expirationtime, self.expirationtime)
                os.utime(
                    self.expirationfile,
                    times=times,
                )
                return (True, "")
        except json.decoder.JSONDecodeError:
            msg = f"Invalid JSON retrieved from {server}"
            return (False, msg)

    def load_database(self):
        # --------------------------
        self.loaded = False
        tests = 0
        errmsg = "No error"

        while not self.loaded and tests < self.maxtests:
            self.lock()
            if pathlib.Path(self.cachefile).exists() and self.exp_file_is_recent():
                status, errmsg = self.load_from_cache()
            else:
                status, errmsg = self.load_from_server()

            if status is False:
                tests += 1
                continue

        if not self.loaded:
            msg = f"Cannot read IANA database: {errmsg}"
            raise Exception(msg)

    def do_domain(self):
        for service in self.database["services"]:
            for tld in service[0]:
                t = tld.lower()

                if t not in self.services:
                    self.services[t] = []

                for server in service[1]:
                    # server is an URL so case-sensitive.
                    self.services[t].append(server)

    def make_cache_from_content(self):
        self.lock()
        pathlib.Path(self.cachefile).write_bytes(self.content)
        self.unlock()

    def lock(self):
        self.lockhandle = pathlib.Path(self.lockname).open("w", encoding="utf8")  # noqa: SIM115
        fcntl.lockf(self.lockhandle, fcntl.LOCK_EX)

    def unlock(self):
        fcntl.lockf(self.lockhandle, fcntl.LOCK_UN)
        self.lockhandle.close()

    def find(self, identifier):
        """
        Get the RDAP server(s) for a given identifier as an array,
        None if there is none.
        """
        if self.category == "domains":
            domain = identifier
            domain = domain.removesuffix(".")
            labels = domain.lower().split(".")
            tld = labels[len(labels) - 1]
            if tld in self.services:
                return self.services[tld]

            return None

        msg = f"Unsupported category {self.category}"
        raise Exception(msg)


if __name__ == "__main__":
    maxage: int = 1
    rdap = IanaRdapDomain(maxage=maxage)

    print(
        ", ".join(
            [
                f"Database {rdap.description}",
                f"version {rdap.version}",
                f"published on {rdap.publication}",
                f"retrieved on {rdap.retrieved}",
                f"{rdap.services} services",
            ],
        ),
    )
    for domain in sys.argv[1:]:
        print(f"{domain} -> {rdap.find(domain)}")
