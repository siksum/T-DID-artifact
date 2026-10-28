PY := .venv/bin/python

.PHONY: install monpoly test quick reproduce figures verify
install:
	python3 -m venv .venv
	$(PY) -m pip install -c requirements.lock -e '.[dev,artifact]'
monpoly:
	sh scripts/setup_monpoly.sh
test:
	$(PY) -m pytest
quick:
	$(PY) scripts/reproduce.py
reproduce:
	$(PY) scripts/reproduce.py --full
figures:
	$(PY) scripts/draw_diagrams.py
	$(PY) scripts/plot_results.py
verify:
	$(PY) scripts/verify_manifest.py
