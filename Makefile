.PHONY: setup test lint typecheck ci clean docs

setup:
	pip install -e ".[dev,all]"
	pre-commit install

test:
	pytest

test-verbose:
	pytest -v --tb=long

lint:
	ruff check src/ tests/
	ruff format --check src/ tests/

format:
	ruff check --fix src/ tests/
	ruff format src/ tests/

typecheck:
	mypy src/

ci: lint typecheck test

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov dist build *.egg-info

docs:
	mkdocs serve

docs-build:
	mkdocs build
