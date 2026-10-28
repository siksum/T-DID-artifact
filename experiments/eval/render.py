"""Re-draw every table and figure of the Evaluation from the saved result data only (no experiment, no
T-DID engine, no comparator tools). Edit the drawing code in fig2.py / fig3.py / fig1.py (table) /
table1.py / table2.py and run:

    python -m experiments.eval.render

Reads results/data/{fig1,fig2,table2}.json and data/cost/*.csv, and the packed ground
truth in datasets/*/truth (for the ground-truth row of the input-representation table). Needs numpy and
matplotlib only. Writes table_input.tex, table1.tex, table2.tex, fig2.pdf/png, fig3.pdf/png next to the data.
"""

from __future__ import annotations

import json

from experiments.eval import fig1, fig2, fig3, table1, table2, table_component


def main() -> None:
    out = fig1.OUT
    data = json.loads((out / "data" / "fig1.json").read_text())
    (out / "table_input.tex").write_text(fig1.table(data))
    table1.main()
    table = json.loads((out / "data" / "table2.json").read_text())
    (out / "table2.tex").write_text(table1.PREAMBLE + table2.latex(table))
    comp = json.loads((out / "data" / "table_component.json").read_text())
    (out / "table_component.tex").write_text(table_component.latex(comp))
    fig2.plot(json.loads((out / "data" / "fig2.json").read_text()))
    fig3.main()
    print("re-drawn from saved data:", ", ".join(
        ["table_input.tex", "table1.tex", "table2.tex", "table_component.tex", "fig2.pdf/png", "fig3.pdf/png"]))


if __name__ == "__main__":
    main()
