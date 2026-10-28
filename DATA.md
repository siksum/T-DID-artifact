# Data and publication boundary

## Included evidence

* `datasets/sept2026-thr015`: 15 walt.id and 15 Credo issuance workflows.
* `datasets/sept2026-thr019`: 12 Credo + relying-party presentation workflows.
* `data/static`: final 21-threat correspondence, fixed versions and code locators, 315 static cells,
  the 42-workflow oracle/verdict ledgers, and the preliminary ATT&CK v17 applicability workbook. Candidate and contribution IDs are original record IDs.
* `data/measurements`: the stored dense replay records, process memory samples and paired logging
  on/off product records. Environment files identify the commits and configurations used when measured.

Ground truth is taken from client/oracle records, never from the T-DID verdict. Replaying a saved oracle
does not independently re-verify the credential signatures that were checked in the original product run.
Raw credentials, session secrets and signing keys are not intentionally included; acquisition-time
redactions remain present and the publication scan checks common token/private-key formats.

## Publication transformations

Original engine/rule logic, event facts, commitment references, workflow ordering, truth outcomes and
numeric observations are preserved. Host-specific filesystem prefixes in logs and metadata were
replaced by repository-relative or `build/` paths. Dataset MANIFEST file hashes were updated accordingly.
PROVENANCE.json records the changed files' before/after hashes without publishing private host paths.
Original measurement-source hashes in environment records describe the code actually measured; the
portable publication drivers may have different hashes because paths/output locations changed.

The public workflow ledger omits original private-workspace campaign path columns. Its oracle fields
and outcome columns remain unchanged; dataset-relative paths point to the included evidence.

The ATT&CK v17 applicability workbook is an English edition of the original Korean analysis workbook:
entries, grades and rationales are kept; the applicability label None is written No as in Supplementary
Table S4; IDs and names are corrected to v17 in its Corrections sheet; the grading criteria, threat links
and inspection notes are added. The original Korean workbook, its English working tabs, analyst
assignments and the 660-workflow historical campaign are excluded. No paper DOCX/PDF,
agent notes, private repository history, third-party monitor binary, product binary or whole build tree
is included. Product sources are retrieved at the recorded upstream commits for a fresh service run.

## Integrity

`SHA256SUMS.json` covers the published versioned files, excluding itself and generated results.
`make verify` checks it. Each product dataset also has a MANIFEST with file-level integrity information.
Do not compare publication-normalized log bytes with an old host-path-containing archive as if they were
identical; use the recorded transformation and verify that observation/outcome fields are unchanged.
