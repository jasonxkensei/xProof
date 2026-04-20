.PHONY: lint test typecheck check install-hooks

lint:
	ruff check xproof/ tests/

test:
	pytest tests/ -m "not integration"

typecheck:
	mypy xproof/

check: lint typecheck test

install-hooks:
	cd .. && pre-commit install --config python-sdk/.pre-commit-config.yaml
