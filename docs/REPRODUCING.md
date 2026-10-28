# Reproducing the artifact

## Requirements and levels

Python 3.12 on Linux x86-64 is the verified environment. `make install` uses the exact package versions
in requirements.lock. `make monpoly` downloads the official image
`infsec/monpoly@sha256:3d997ba9e927c8359455cea9b8df186dc5dc02b8ae3a7a7153ff60369387503d`,
extracts its native x86-64 runtime and verifies three file hashes. Docker access is required for this
setup step. The published Git history contains none of these downloaded binaries.

1. `make test`: existing engine, collector, mapper, loss, comparator and measurement-harness tests.
2. `make quick`: both dataset manifests; 42 saved-oracle outcomes; static denominators; recorded
   workflow replay and input/ablation/component tables; saved latency/memory and product-cost aggregation;
   current Figures 1–4. Requires MonPoly for the component replay.
3. `make reproduce`: all quick checks plus all 11 deletion probabilities and 30 seeds for Figure 3.
4. A new performance run: separate from reaggregation. On Linux, for example:
   `.venv/bin/python -m experiments.eval.harness.run latency --judges tdid --loads 50 --window 2 --warmup 0.5 --repeats 1 --out results/new-cost`.
   This is a small protocol check, not a replacement for the paper's archived measurements.
5. A new product campaign: install the pinned upstream code and patches described in
   `testbed/tdid/waltid/README.md` and `testbed/tdid/credo/README.md`. Use `TDID_BUILD_ROOT` for the build
   root of `experiments/eval/product_cost.py`. Product dependencies include the documented JDK/Node
   toolchains, not just this Python environment. The release validation replays preserved product
   records; it does not claim a new whole-product campaign.

## Paper evidence map

| Item | Stored source | Recompute |
|---|---|---|
| 21 threats / taxonomy correspondence | data/static/attack_elements.csv, taxonomy_correspondence.csv | reproduce.py static checks; 21 x 4 entries |
| 315 static combinations | implementation_feasibility_315.csv | 22 designable + 142 applicable but missing evidence/truth + 151 not applicable; applicable total 164 |
| 42 / known 39 / determinate 30 / incomplete 9 | workflow_evidence_42.csv and included datasets | verify_saved_truth.py; common.layout; engine replay |
| Input representation results (Table III) | data/expected/fig1.json | experiments.eval.fig1.run |
| Evidence ablation (Table IV) | data/expected/table2.json | experiments.eval.table2.run |
| Producer-record ablation | data/expected/table_component.json | experiments.eval.table_component.run |
| Figure 1 and Figure 2 | scripts/draw_diagrams.py | make figures |
| Figure 3: deletion experiment | data/expected/fig2.json | experiments.eval.fig2.sweep (30 seeds); plot_results.py |
| Figure 4(a) | dense-cost latency_events.jsonl.gz, latency_summary.csv | per-run final verdict, scheduled >= 1 s, linear p95; median of three repeats |
| Figure 4(b) | original-cost/memory.csv | median of three process-tree VmHWM observations at 10,000 proofs |
| Product logging overhead | product-cost raw HTTP/case records | experiments.eval.summarise_product_cost |

The historical module names fig1/fig2/fig3 reflect earlier evaluation numbering; the publication
figure outputs are `figures/Fig1` through `Fig4`. Table numbers here follow the archived manuscript
associated with these source results; contents and descriptive names are the stable identifiers.

## Comparison encodings and Figure 3 interpretation

The PLTL and MonPoly encodings assign false to unavailable atoms; LTL3 also has its own finite-prefix
semantics. The THR-019 initiator-identity condition is structurally unobserved in these records. Its
false encoding explains three determinate comparator errors even at deletion probability zero.
For THR-015, a deleted credential output reference can prevent a past-output match in the comparison
encoding and produce an attack conclusion unsupported by that missing reference. Preserve these
encodings when reproducing the figure; replacing them changes the evaluated configuration.

## Cost interpretation

Scheduled-to-final-verdict latency includes serialization, input checking, pipes and scheduling in
the configured path. Three run-level p95s are summarized by a median. Figure 4(a) enables 21 T-DID
rules; Figure 4(b)'s matched THR-015 memory experiment enables one. The MonPoly value sums the
Python streaming wrapper and MonPoly child process. The PLTL 2,000-runs/s point is retained as
measured; a numerical spike alone does not identify its cause. New runs may differ by host/scheduler.
