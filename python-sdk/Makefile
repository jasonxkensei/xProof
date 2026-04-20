.PHONY: lint test check

lint:
	ruff check xproof/ tests/

test:
	pytest tests/ -m "not integration"

check: lint test
