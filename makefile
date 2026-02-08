# makefile

SHELL := /bin/bash
export SHELL

VENV := ./vtmp/
export VENV

PY_FILES := *.py

MIN_PYTHON_VERSION := $(shell basename $$( ls /usr/bin/python3.[0-9][0-9] | awk '{print $0; exit}' ) )
export MIN_PYTHON_VERSION

PIP_INSTALL := pip3 -q \
	--require-virtualenv \
	--disable-pip-version-check \
	--no-color install --no-cache-dir


LINE_LENGTH := 120
PL_LINTERS := eradicate,mccabe,pycodestyle,pyflakes,pylint


# C0114 Missing module docstring [pylint]
# C0115 Missing class docstring [pylint]
# C0116 Missing function or method docstring [pylint]
# E203 whitespace before ':' [pycodestyle]
#
# W0105 String statement has no effect
# C901 : is to complex

PL_IGNORE := C0114,C0115,C0116,E203

MYPY_INSTALL := \
	types-requests \
	types-python-dateutil \
	spectra-assure-sdk

COMMON_VENV := rm -rf $(VENV); \
	$(MIN_PYTHON_VERSION) -m venv $(VENV); \
	source ./$(VENV)/bin/activate;

.PHONEY: clean prep

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
	mkdir -p tmp; \
	for i in `cat domains.txt | sort -u `; \
	do \
		./whois_domain_rdap.py $$i 2>tmp/$$i.2 >tmp/$$i.1; \
		cat tmp/$$i.2; \
	done
