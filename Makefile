.PHONY: install lint test eval eval-dev eval-test dataset pool writeups

install:
	pip install -e ".[dev]"

lint:
	ruff check .
	ruff format --check .

test:
	pytest -q

eval:  ## replay recorded responses for both splits; free and deterministic
	python -m evals.run --split dev --offline --check
	python -m evals.run --split test --offline --check
	python -m evals.ablation --check

eval-dev:  ## Batch API (half price, separate quota), then score: iteration happens here
	python -m evals.batch --split dev
	python -m evals.run --split dev --offline

eval-test:  ## held-out split, run once on a finished version
	python -m evals.batch --split test
	python -m evals.run --split test --offline

dataset:  ## re-fetch NVD records for the dev split (the test split is a committed snapshot)
	python -m evals.build_dataset dev

pool:  ## re-fetch the 2022 NVD retrieval pool
	python -m evals.build_pool

writeups:  ## rebuild the Exploit-DB write-up splits (NVD feeds and Exploit-DB files cached in .cache/)
	python -m evals.build_writeups
