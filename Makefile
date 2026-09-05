PY ?= .venv/bin/python

setup:
	python3 -m venv .venv
	.venv/bin/pip install -q -r requirements.txt
	$(PY) scripts/gen_catalog.py
	$(PY) scripts/gen_keys.py

test:
	$(PY) -m pytest -q

redteam:
	$(PY) -m redteam.run

demo:
	./scripts/demo.sh

serve:
	.venv/bin/uvicorn gate.app:app --reload

verify:
	$(PY) -m cli.verify_chain

.PHONY: setup test redteam demo serve verify
