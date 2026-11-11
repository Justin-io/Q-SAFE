.PHONY: test scan clean

PYTHON ?= python3
PATHS ?= .

test:
	PYTHONPATH=. $(PYTHON) -m unittest discover -s tests -v

scan:
	PYTHONPATH=. $(PYTHON) -m q_safe.cli scan $(PATHS) --json reports/scan.jsonl

clean:
	rm -rf __pycache__ q_safe/__pycache__ tests/__pycache__
