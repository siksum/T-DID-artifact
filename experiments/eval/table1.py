"""Table I: what each log model and runtime monitor can express or decide (static, from primary sources).

Log-model columns follow the field facts checked against OCSF 1.6.0, ECS 9.1.0, the OpenTelemetry Logs Data
Model and CloudEvents 1.0.2 (copies in docs/eval-handoff/std-sources/) and agree with the round-trip mappings
in experiments/eval/mappers/rules/*.yaml. Monitor columns follow the cited algorithms as implemented in
experiments/eval/monitors/. Product log: walt.id status callbacks and Credo TS SDK events / verifier record.
"""

from __future__ import annotations

from pathlib import Path

OUT = Path(__file__).resolve().parents[2] / "results"
F, P, N, D, V = r"\F", r"\P", r"\N", r"\D", r"$\sim$"
COLS = ["Product log", "OTel", "ECS", "OCSF", "CloudEvents", "Two-valued", "Three-valued", "First-order",
        "T-DID"]
ROWS = [
    # per-check result distinct from the decision: no standard has a per-check outcome; OCSF/ECS can carry
    # one outcome per record (one record per check, joined by correlation); OTel/CE have no outcome field.
    ("Failed check vs.\\ accepted request", [V, N, P, P, N, D, D, D, F]),
    # identity of the exact key proof across requests: no field in any standard (ECS related.hash has no
    # role); propositional monitors need grounding per proof value; MFOTL has data variables.
    ("Same proof seen in an earlier request", [N, N, N, N, N, P, P, F, F]),
    # join of verifier / wallet / relying-party records: OTel TraceId (core), OCSF correlation_uid (core
    # optional), ECS trace.id (extended), CloudEvents traceparent (extension)
    ("Wallet and verifier records linked", [N, F, P, F, P, D, D, D, F]),
    # stating that required evidence is missing: OCSF status_id 0 and ECS event.outcome unknown mark an
    # unknown outcome only; LTL3 '?' means 'not yet decided by the future', not 'evidence missing'
    ("Missing evidence stated as missing", [N, N, P, P, N, N, P, N, F]),
]
VALUES = ["--", "--", "--", "--", "--", "2", "3", "2", "3"]


def latex() -> str:
    lines = [
        r"\begin{table*}[t]",
        r"\centering\scriptsize",
        r"\caption{What each log model and runtime monitor can express or decide for the THR-015 and THR-019 "
        r"success conditions. \F\ standard field or built in; \P\ needs extension fields or preprocessing "
        r"(one record per check, grounding per data value); \N\ not supported; \D\ depends on the input, "
        r"not on the monitor; $\sim$ varies by product. Last row: number of verdict values.}",
        r"\label{tab:capability}",
        r"\begin{tabular}{@{}l ccccc ccc c@{}}\toprule",
        r" & \multicolumn{5}{c}{Log and event models (\S II-C)} & \multicolumn{3}{c}{Runtime monitors (\S II-B)} & \\",
        r"\cmidrule(lr){2-6}\cmidrule(lr){7-9}",
        "Information required by a verdict & " + " & ".join(COLS) + r"\\\midrule",
    ]
    for name, cells in ROWS:
        lines.append(f"{name} & " + " & ".join(cells) + r"\\")
    lines.append("Number of verdict values & " + " & ".join(VALUES) + r"\\\bottomrule")
    lines += [r"\end{tabular}", r"\end{table*}", ""]
    return "\n".join(lines)


PREAMBLE = (r"% requires: \usepackage{wasysym,pifont,booktabs}" "\n"
            r"\providecommand{\F}{$\bullet$}\providecommand{\P}{$\LEFTcircle$}"
            r"\providecommand{\N}{$\circ$}\providecommand{\D}{$\cdot$}"
            r"\providecommand{\Y}{\ding{51}}\providecommand{\X}{\ding{55}}" "\n")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "table1.tex").write_text(PREAMBLE + latex())
    print("wrote", OUT / "table1.tex")


if __name__ == "__main__":
    main()
