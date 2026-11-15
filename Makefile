PYTHON ?= python3

.PHONY: test test-pytest docs clean-docs

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

test-pytest:
	uv run --group dev pytest

docs:
	uv run --group docs sphinx-build -W -b html docs docs/_build/html

clean-docs:
	rm -rf docs/_build
