# Upstream software and attribution

The Apache-2.0 license covers original T-DID material. Upstream products, runtimes and dependencies
retain their own terms; downloading them does not relicense them under this repository's license.

| Software | Pinned source / acquisition | Use |
|---|---|---|
| MonPoly 1.4.3 | https://bitbucket.org/monpoly/monpoly/ ; https://hub.docker.com/r/infsec/monpoly/tags | External MFOTL runtime, retrieved by image digest; not redistributed |
| musl / GMP | Libraries in the pinned official MonPoly image | Retrieved with that runtime; not redistributed |
| LamaConv | https://raw.githubusercontent.com/autonomy-and-verification-uol/ROSMonitoring/HEAD/oracle/LamaConvOracle/rltlconv.jar | Optional LTL3 automaton generation; not redistributed; cached automata and formulas are included |
| walt.id identity | https://github.com/walt-id/waltid-identity/tree/f5b5995059c4ab69d6bc73f434c72d1574188963 | Product source retrieved separately; collection patches and driver supplied |
| Credo TS | https://github.com/openwallet-foundation/credo-ts/tree/3c32928107639bc355f82d4ba11c4d91901e11cb | Product source retrieved separately; collection patches and test driver supplied |

Copies of the pinned upstream Apache-2.0 license texts are retained under `licenses/credo` and `licenses/waltid`. Acquisition TypeScript snapshots derive from the upstream Credo test scaffold and retain those terms.

Patch files contain contextual upstream source lines and retain the corresponding upstream terms.
Python runtime/development dependencies and exact versions are listed in requirements.lock.
For upstream product licensing, see the LICENSE files at the pinned source revisions. This artifact
does not redistribute complete products, toolchains, Java archives, OCaml executables or shared libraries.
