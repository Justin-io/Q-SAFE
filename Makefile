PYTHON ?= python3
.PHONY: help scan monitor test
help:
	@echo "make scan TARGET=./samples | make monitor TARGET=~/Downloads | make test"
scan:
	@test -n "$(TARGET)" || (echo "Set TARGET=path"; exit 2)
	$(PYTHON) qsafe.py scan "$(TARGET)" --json reports/latest.json
monitor:
	@test -n "$(TARGET)" || (echo "Set TARGET=directory"; exit 2)
	$(PYTHON) qsafe.py monitor "$(TARGET)"
test:
	$(PYTHON) -m unittest discover -s tests -v

evaluate:
	@test -n "$(MANIFEST)" || (echo "Set MANIFEST=path/to/manifest.csv"; exit 2)
	$(PYTHON) qsafe_eval.py "$(MANIFEST)" --json reports/evaluation.json
