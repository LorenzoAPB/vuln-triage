.PHONY: install lint test eval eval-live dataset

install:
	pip install -e ".[dev]"

lint:
	ruff check .
	ruff format --check .

test:
	pytest -q

eval:  ## replay recorded responses; free and deterministic
	python -m evals.run --offline --check

eval-live:  ## call the API for any item without a recording, then rewrite evals/results.*
	python -m evals.run

dataset:  ## re-fetch NVD records and rebuild evals/dataset.jsonl
	python -m evals.build_dataset
