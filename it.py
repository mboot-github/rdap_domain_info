#! /usr/bin/env python3

import whoisit

whoisit.bootstrap(allow_insecure_ssl=True)

results = whoisit.domain("nic.work", allow_insecure_ssl=True)
