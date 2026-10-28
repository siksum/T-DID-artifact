# External monitor runtime

Run `sh scripts/setup_monpoly.sh` from the repository root on Linux x86-64. The script retrieves the
official MonPoly 1.4.3 image by its immutable digest and checks the executable/loader/library hashes.
These downloaded third-party binaries are ignored by Git and are not redistributed in this artifact.

The two LTL3 automata JSON files are retained next to `ltl3.py`; ordinary replay does not need LamaConv.
For automaton regeneration, place LamaConv `rltlconv.jar` here (SHA-256
`161d2346a71aefb9e92cadd9411f3909dd8e599250674834e655bed16d1e7d7e`) and use `ltl3.regenerate`.
Its original acquisition URL is recorded in THIRD_PARTY.md. The JAR is not redistributed here.
