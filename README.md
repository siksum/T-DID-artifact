# T-DID research artifact

An executable artifact for DID/VC threat success conditions, security event logging, and stateful detection.
It contains the engine and **21 rules**, log-model mappings, three comparison monitors, the recorded
**42 product workflows**, static analysis ledgers, and the data/code behind the paper's figures.

## Start here

Tested platform: **Linux x86-64, Python 3.12**. Full comparator replay additionally needs Docker once
to retrieve the pinned MonPoly runtime. Basic T-DID detection and saved-data checks do not need Docker.

```sh
git clone https://github.com/siksum/T-DID-artifact.git
cd T-DID-artifact
make install
make monpoly
make test
make reproduce
```

`make reproduce` checks the dataset manifests, replays the recorded workflows, recomputes input/ablation
tables and the full 30-seed deletion experiment, checks stored cost records, and regenerates Figures 1–4.
The machine-readable result is `results/reproduction.json`. For a shorter check use `make quick`.
These commands replay preserved evidence; they do not deploy new issuer/wallet services.

To run the engine alone:

```sh
python3 -m venv .venv
.venv/bin/pip install -c requirements.lock -e .
.venv/bin/tdid run examples/thr015-replay.jsonl
```

## Artifact map

| Material | Location |
|---|---|
| Engine, 21 rules, field registry, input validation, collectors | [src/tdid](src/tdid) |
| Current JSON schema and rule/field dictionaries | [docs](docs) |
| Core and comparator tests | [tests/tdid_core](tests/tdid_core), [experiments/eval](experiments/eval) |
| OCSF / ECS / OpenTelemetry / CloudEvents mappings | [experiments/eval/mappers](experiments/eval/mappers) |
| PLTL, LTL3, MonPoly encodings and formulas | [experiments/eval/monitors](experiments/eval/monitors) |
| Recorded product evidence, independent oracle fields, verdicts | [datasets](datasets) |
| Taxonomy correspondence and 315 implementation/threat cells | [data/static](data/static) |
| Stored numerical reference results | [data/expected](data/expected) |
| Figure input values and editable outputs | [data/figures](data/figures), [figures](figures) |
| Figure 1–2 / 3–4 code | [draw_diagrams.py](scripts/draw_diagrams.py), [plot_results.py](scripts/plot_results.py) |
| Measured latency, memory, product logging records | [data/measurements](data/measurements) |
| Pinned product patches and measurement drivers | [testbed/tdid](testbed/tdid) |
| Original acquisition / independent oracle source snapshots | [testbed/acquisition](testbed/acquisition) |
| Reproduction commands and paper/table mapping | [docs/REPRODUCING.md](docs/REPRODUCING.md) |
| Publication changes and source identities | [PROVENANCE.json](PROVENANCE.json), [DATA.md](DATA.md) |

## Scope and interpretation

The 21 rules are designed and tested; the recorded product evaluation covers THR-015 and THR-019.
The 315 static combinations are a separate denominator. Of 42 workflows, 39 have known independent
outcomes: nine attacks and 30 non-attacks. T-DID produces 30 correct determinate verdicts and nine
incomplete verdicts on these 39 cases; three workflows with unknown outcomes are excluded from scoring.
An incomplete verdict counts as no alert when calculating attack detection.

Missing fields retain their documented treatment in each comparison monitor. A high detection count
under deletion can include a success conclusion unsupported by the missing evidence; do not interpret
it as universal superiority. Recorded timing values describe the configured replay paths and machine,
not pure algorithm cost or live-service throughput. New timing runs will vary across hosts.

The preliminary ATT&CK workbook (D1) and manuscript drafts are outside this code artifact. Final
correspondence decisions, source versions and code locators are retained as inspectable CSV files.
Host path strings in metadata/logs were normalized for publication; scientific observations and
predicates were preserved. See DATA.md for the transformation and checksum boundary.

## License and citation

The T-DID source, generated data, and original artifact documentation are provided under
[Apache-2.0](LICENSE), subject to upstream notices for patches and external tools in
[THIRD_PARTY.md](THIRD_PARTY.md). External MonPoly/LamaConv binaries are not redistributed.
Use [CITATION.cff](CITATION.cff) for this software release. A journal acceptance or archival DOI is not
asserted by this artifact.
