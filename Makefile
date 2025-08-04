.PHONY: install test run clean lint format help

PYTHON := python3
PIP := pip
VENV := venv
SRC := src
TESTS := tests

help:
	@echo "SPDX Compliance Checker - Available commands:"
	@echo "  make install    - Set up virtual environment and install dependencies"
	@echo "  make test       - Run all tests"
	@echo "  make run        - Run checker with negatice example files"
	@echo "  make run2       - Run checker with positive examples files"
	@echo "  make lint       - Run code linting"
	@echo "  make format     - Format code with black"
	@echo "  make clean      - Remove generated files and caches"

install:
	$(PYTHON) -m venv $(VENV)
	./$(VENV)/bin/$(PIP) install -r requirements.txt
	./$(VENV)/bin/$(PIP) install pytest black flake8

test: install
	./$(VENV)/bin/$(PYTHON) -m pytest $(TESTS) -v

run: install
	./$(VENV)/bin/$(PYTHON) $(SRC)/main.py --sbom examples/sbom.json --policy examples/policy.yml -v

run2: install
	./$(VENV)/bin/$(PYTHON) $(SRC)/main.py --sbom examples/clear_sbom.json --policy examples/policy.yml -v

lint: install
	./$(VENV)/bin/flake8 $(SRC) $(TESTS) --max-line-length=100

format: install
	./$(VENV)/bin/black $(SRC) $(TESTS) --line-length=100

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	rm -rf $(VENV) build dist