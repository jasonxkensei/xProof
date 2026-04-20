.PHONY: lint test typecheck check

lint:
	ruff check xproof/ tests/

test:
	pytest tests/ -m "not integration"

typecheck:
	mypy xproof/

check: lint typecheck test
