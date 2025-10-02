.PHONY: format lint test

format:
	black .

lint:
	flake8 .

test:
	pytest