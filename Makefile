.PHONY: install lint test eval eval-dev eval-test dataset

install:
	pip install -e ".[dev]"

lint:
	ruff check .
	ruff format --check .

test:
	pytest -q

eval:  ## replay recorded responses for both splits; free and deterministic
	python -m evals.run --split dev --offline --check
	test ! -f evals/results.json || python -m evals.run --split test --offline --check

eval-dev:  ## live: prompt and guardrail iteration happens here
	python -m evals.run --split dev

eval-test:  ## live: held-out split, run once on a finished version
	python -m evals.run --split test

dataset:  ## re-fetch NVD records for the dev split (the test split is a committed snapshot)
	python -m evals.build_dataset dev
