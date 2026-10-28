# Preserved acquisition and oracle source

These selected source files are the producers/oracle helpers named by the original packed dataset plans. Each published file matched its recorded SHA-256 before publication. The recorded source IDs in SOURCE_IDENTITIES.json are historical identifiers, not paths in this public repository.

THR-015 contains the client-side Ed25519 outcome oracle, observation hook, paired test and HTTP helpers. THR-019 contains the exact instrumented Credo test and logger sink from the recorded presentation campaign. The TypeScript tests are overlays for the pinned upstream Credo test tree, not standalone Node programs. Upstream product code, original build overlays and the old detector are not bundled.

Use the current src/tdid engine and experiments/eval code to replay the published datasets. The original plans also list historical acquisition orchestrators and analysis scripts not used by the current replay. Re-running the whole acquisition campaign would require reconstructing that historical service/build environment; release validation does not claim that campaign was rerun. The current collection patches and product driver recipes are under ../tdid.
