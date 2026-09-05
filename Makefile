PYTHON ?= python
.DEFAULT_GOAL := test

.PHONY: install lint test lab-up lab-down e2e

install:
	$(PYTHON) -m pip install -e ".[dev]"

lint:
	$(PYTHON) -m ruff check .

test:
	$(PYTHON) -m pytest

lab-up lab-down e2e:
	@$(PYTHON) -c "import sys; print('not implemented'); sys.exit(2)"
