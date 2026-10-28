"""Supplementary tables: per-request verdict counts (Fig. 1 conditions), per-standard workflow counts, per-run
ablation transitions (Table II), and the 21-row expressibility table."""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "results"
STD = {"ocsf": "OCSF", "ecs": "ECS", "otel": "OTel", "cloudevents": "CloudEvents"}
PROD = {"waltid": "015 walt.id", "credo": "015 Credo TS", "credo-vp": "019 Credo TS + RP"}


def per_request(fig1: dict) -> str:
    conds = ["product_log"] + [f"{s}_{lvl}" for lvl in ("core", "ext") for s in STD] + ["tdid"]
    names = {"product_log": "Product log", "tdid": "T-DID evidence",
             **{f"{s}_{lvl}": f"{STD[s]} {lvl}" for s in STD for lvl in ("core", "ext")}}
    lines = [r"\begin{table}[t]\centering\scriptsize",
             r"\caption{Per-request (per-decision) T-DID verdicts under each input condition: "
             r"succeeded / not\_succeeded / incomplete. THR-015 counts issuer decisions (27 per issuer, "
             r"including the three Credo TS requests whose product result is undetermined); THR-019 counts "
             r"relying-party decisions and provisional request verdicts.}",
             r"\label{tab:s-per-request}",
             r"\begin{tabular}{@{}l" + "c" * len(PROD) + r"@{}}\toprule",
             "Condition & " + " & ".join(PROD.values()) + r" \\ \midrule"]
    for cond in conds:
        cells = []
        for p in PROD:
            c = fig1["per_request"].get(p, {}).get(cond, {})
            cells.append(f"{c.get('succeeded', 0)} / {c.get('not_succeeded', 0)} / {c.get('incomplete', 0)}")
        lines.append(f"{names[cond]} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule\end{tabular}\end{table}", ""]
    return "\n".join(lines)


def per_standard(fig1: dict) -> str:
    lines = [r"\begin{table}[t]\centering\scriptsize",
             r"\caption{Workflow verdicts of T-DID on the T-DID evidence expressed in each generic standard "
             r"and read back (attack / benign / withheld / wrong). Table~\\ref{tab:input-representation} shows the standard with the most "
             r"decided verdicts per level.}", r"\label{tab:s-per-standard}",
             r"\begin{tabular}{@{}llcccc@{}}\toprule",
             r"Threat & Level & OCSF & ECS & OTel & CloudEvents \\ \midrule"]
    for panel, levels in fig1["per_standard"].items():
        for lvl, stds in levels.items():
            cells = [f"{stds[s].get('attack', 0)}/{stds[s].get('no_attack', 0)}/{stds[s].get('withheld', 0)}"
                     f"/{stds[s].get('wrong', 0)}" for s in STD]
            lines.append(f"{panel} & {lvl} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule\end{tabular}\end{table}", ""]
    return "\n".join(lines)


def ablation(table2: dict) -> str:
    cols = [f"{PROD[c['product']]} {'attack' if c['truth'] == 'attack' else 'benign'}" for c in table2["columns"]]
    lines = [r"\begin{table*}[t]\centering\scriptsize",
             r"\caption{Per-run verdict transitions behind Table~II (base verdict $\rightarrow$ verdict after "
             r"removal; attack / no\_attack / withheld).}", r"\label{tab:s-t2}",
             r"\begin{tabular}{@{}l" + "p{2.2cm}" * len(cols) + r"@{}}\toprule",
             "Removed & " + " & ".join(cols) + r" \\ \midrule"]
    for row in table2["rows"]:
        cells = ["; ".join(f"{k.replace('no_attack', 'benign').replace('->', r'$\rightarrow$')} {v}"
                           for k, v in c.items()) for c in row["counts"]]
        lines.append(f"{row['row']} & " + " & ".join(cells).replace("_", r"\_") + r" \\")
    lines += [r"\bottomrule\end{tabular}\end{table*}", ""]
    return "\n".join(lines)


def expressibility() -> str:
    from experiments.eval import mappers
    rows = mappers.threat_expressibility()
    lines = [r"\begin{table*}[t]\centering\scriptsize",
             r"\caption{Fields read by each of the 21 T-DID threat rules and how many survive a round trip "
             r"through each generic standard (core fields / core + defined extension fields). "
             r"\checkmark: every rule-read field survives at the extension level.}",
             r"\label{tab:s-expressibility}",
             r"\begin{tabular}{@{}lc" + "cc" * 4 + r"@{}}\toprule",
             r"Threat & Fields & \multicolumn{2}{c}{OCSF} & \multicolumn{2}{c}{ECS} & "
             r"\multicolumn{2}{c}{OTel} & \multicolumn{2}{c}{CloudEvents} \\",
             r" & & core & ext & core & ext & core & ext & core & ext \\ \midrule"]
    for r in rows:
        cells = [str(r["fields"])]
        for s in STD:
            cells += [str(r[f"{s}_core"]), str(r[f"{s}_ext"]) + (r" \checkmark" if r[f"{s}_all_ext"] else "")]
        lines.append(f"{r['threat']} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule\end{tabular}\end{table*}", ""]
    return "\n".join(lines)


def coverage() -> str:
    data = json.loads((OUT / "data" / "coverage.json").read_text())
    conds = [("native", "Product log"), ("core", "Standard-field mapping"), ("ext", "Standard + extension"),
             ("added", "T-DID evidence")]
    lines = [r"\begin{table}[t]\centering\scriptsize",
             r"\caption{Share of each threat's success conditions settled (true or false) by the records under "
             r"each input condition of Table~\\ref{tab:input-representation} (mean over runs with known ground truth; best standard in "
             r"parentheses), with the runs decided. The share is measured against T-DID's own condition list "
             r"and explains why the middle conditions withhold; correctness is judged in Table~\\ref{tab:input-representation} against ground "
             r"truth. THR-019: at most 5 of 7 conditions are observable by honest components (71.4\%).}",
             r"\label{tab:s-coverage}",
             r"\begin{tabular}{@{}lcccc@{}}\toprule",
             r"Condition & \multicolumn{2}{c}{THR-015} & \multicolumn{2}{c}{THR-019} \\",
             r" & settled & decided & settled & decided \\ \midrule"]
    for key, name in conds:
        cells = []
        for panel in ("THR-015", "THR-019"):
            r = data[panel][key]
            best = "" if key in ("native", "added") else " (" + ", ".join(STD[b] for b in r["best"]) + ")"
            cells += [f"{r['share']:.1f}\\%{best}", f"{r['decided']}/{r['n']}"]
        lines.append(f"{name} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule\end{tabular}\end{table}", ""]
    return "\n".join(lines)


def ranges() -> str:
    """Spread behind the plotted lines of Fig. 2 (30 seeds) and Fig. 3 (5 repeats): min-max."""
    f2 = json.loads((OUT / "data" / "fig2.json").read_text())
    f3 = json.loads((OUT / "data" / "fig3.json").read_text())
    judges = [("pltl", "Two-valued"), ("fo", "First-order"), ("ltl3", "Three-valued"), ("tdid", "T-DID")]
    lines = [r"\begin{table*}[t]\centering\scriptsize",
             r"\caption{Spread behind Fig.~2: mean and min--max over 30 seeds of the wrong and withheld "
             r"verdicts (\% of 39 runs) per evidence-loss ratio.}", r"\label{tab:s-fig2-range}",
             r"\begin{tabular}{@{}l" + "cc" * len(judges) + r"@{}}\toprule",
             "Loss & " + " & ".join(rf"\multicolumn{{2}}{{c}}{{{n}}}" for _, n in judges) + r" \\",
             " & " + " & ".join(["wrong", "withheld"] * len(judges)) + r" \\ \midrule"]
    for i, p in enumerate(f2["ps"]):
        cells = []
        for j, _ in judges:
            for k in ("wrong", "withheld"):
                d = f2[k][j]
                cells.append(f"{d['mean'][i]:.1f} [{d['min'][i]:.1f}, {d['max'][i]:.1f}]")
        lines.append(f"{p:.1f} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule\end{tabular}\end{table*}", ""]
    judges3 = judges + [("tdid_diag", "T-DID diag."), ("echo", "Harness")]
    lines += [r"\begin{table*}[t]\centering\scriptsize",
              r"\caption{Spread behind Fig.~3(b): median and min--max over 5 repeats of the p95 decision "
              r"latency (ms) per offered load.}", r"\label{tab:s-fig3-range}",
              r"\begin{tabular}{@{}l" + "c" * len(judges3) + r"@{}}\toprule",
              "Load (runs/s) & " + " & ".join(n for _, n in judges3) + r" \\ \midrule"]
    loads = sorted({float(x) for j, _ in judges3 for x in f3["p95_s"].get(j, {})})
    for load in loads:
        cells = []
        for j, _ in judges3:
            d = f3["p95_s"].get(j, {}).get(str(load))
            cells.append("--" if d is None else
                         f"{1000 * d['median']:.1f} [{1000 * d['min']:.1f}, {1000 * d['max']:.1f}]")
        lines.append(f"{load:g} & " + " & ".join(cells) + r" \\")
    lines += [r"\bottomrule\end{tabular}\end{table*}", ""]
    return "\n".join(lines)


def main() -> None:
    fig1 = json.loads((OUT / "data" / "fig1.json").read_text())
    table2 = json.loads((OUT / "data" / "table2.json").read_text())
    parts = [per_request(fig1), coverage(), ablation(table2), expressibility(), ranges()]
    (OUT / "supplementary_tables.tex").write_text("\n".join(parts))
    print("wrote", OUT / "supplementary_tables.tex")


if __name__ == "__main__":
    main()
