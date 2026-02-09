# makefile
SHELL := /bin/bash
export SHELL

VENV := ./vtmp/
export VENV

MIN_PYTHON_VERSION := $(shell basename $$( ls /usr/bin/python3.[0-9][0-9] | awk '{print $0; exit}' ) )
export MIN_PYTHON_VERSION

COMMON_VENV := rm -rf $(VENV); \
	$(MIN_PYTHON_VERSION) -m venv $(VENV); \
	source ./$(VENV)/bin/activate;

PIP_INSTALL := pip3 -q \
	--require-virtualenv \
	--disable-pip-version-check \
	--no-color install --no-cache-dir

MYPY_INSTALL := \
	types-requests \
	types-python-dateutil \
	spectra-assure-sdk

PY_FILES := *.py

.PHONEY: clean prep format check mypy run

# =======================================
all: clean prep run

clean:
	rm -f *.[12]
	rm -rf tmp/

prep: format check

format:
	ruff format $(PY_FILES)

check:
	ruff check --fix $(PY_FILES)

mypy:
	$(COMMON_VENV) \
	$(PIP_INSTALL) mypy $(MYPY_INSTALL); \
	mypy \
		--strict \
		--no-incremental \
		$(PY_FILES)

run:
	mkdir -p tmp;
	./whois_domain_rdap.py | sort -u > domains.txt
	for i in `cat domains.txt`; \
	do \
		./whois_domain_rdap.py $$i 2>tmp/$$i.2 >tmp/$$i.1; \
		cat tmp/$$i.2; \
	done
