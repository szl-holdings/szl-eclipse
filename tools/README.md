# Covenant v2 evidence runner

`covenant_v2_evidence.py` generates fresh local evidence for Khipu STH v2 verification, recall coverage, and exact receipt-chain/Merkle agreement with the independent `szl_crosscheck.covenant` implementation. Historical November 15 evidence remains unchanged and is not recertified by this tool.

## Requirements and invocation

Use Python 3.11 or later, Git, an existing environment containing `cryptography`, and three clean Git worktrees. This is developer evidence tooling; szl-eclipse keeps its standard-library-only runtime dependency profile. No installation into a shared environment is needed. The runner loads selected source roots directly and does not depend on PYTHONPATH.

Supply all six source arguments explicitly:

| Argument | Meaning |
| --- | --- |
| `--khipu-repo` | Khipu worktree root, containing `python/khipu_consensus` |
| `--expected-khipu-commit` | Full lowercase 40-character Git commit |
| `--eclipse-repo` | This worktree root, containing `src/szl_eclipse` and this tool |
| `--expected-eclipse-commit` | Full commit containing the executed tool |
| `--crosscheck-repo` | Crosscheck worktree root, containing `src/szl_crosscheck/covenant.py` |
| `--expected-crosscheck-commit` | Full commit containing the independent comparator |
| `--output` | A new JSON file outside all three source worktrees |

Example, with operator-selected absolute paths and full commits substituted:

```text
python -B tools/covenant_v2_evidence.py --khipu-repo KHIPU --expected-khipu-commit KHIPU_SHA --eclipse-repo ECLIPSE --expected-eclipse-commit ECLIPSE_SHA --crosscheck-repo CROSSCHECK --expected-crosscheck-commit CROSSCHECK_SHA --output NEW_REPORT
```

Exit zero requires PASS. Missing Git, mismatched HEAD, dirty source, missing or changed modules, failed positive controls, blind spots, incomplete control manifests, and unexpected exceptions cannot pass. The output is created exclusively; existing evidence files are never overwritten.

Commit code and tests first, run from clean source worktrees into an external output file, then preserve that report in a separate evidence commit. The report truthfully pins the earlier code commit. To reproduce an archived report, select that pinned code commit in a clean worktree. The later evidence commit is not silently substituted as the executed commit.

## Source identity and report freshness

A dedicated import loader compiles the actual selected source bytes and bypasses cached bytecode. Every loaded module in the three package namespaces is bound to its resolved source file, clean expected Git commit, and committed blob. Source SHA256 values and repository identities must agree before and after the battery. LF/CRLF normalization is permitted only when comparing Git blobs to checked-out Python files; both raw source and committed blob hashes are recorded. Published paths are relative to their verified worktree root.

The report records Python and cryptography versions; those external dependencies and the interpreter are not independently source-pinned. No source pin is a claim of supply-chain attestation.

Add `--check-report SAVED_REPORT --max-report-age-seconds 3600` to rerun the live battery and additionally require a saved report to match the selected current source identities and age policy. Maximum accepted report age is bounded to 24 hours; age equal to the limit and future-dated reports fail. The `evidence_usable` function exposes the same integrity, manifest, source-pin, and freshness checks to callers with an explicit aware current time. These are unkeyed integrity checks, not report authentication or a trusted timestamp service. Reports and expected commit pins must come from a trusted path.

## Declared battery

The battery requires the complete named manifest of 39 directed controls with fixed expected booleans, plus exactly the ten unique Eclipse mutation classes. An omitted, duplicated, renamed, or expectation-flipped control cannot retain PASS merely by recalculating the report digest.

Positive controls require a valid signed STH, valid recall coverage, a three-of-four quorum, valid inclusion proof, age inside the TTL, and agreement between recursive Khipu and iterative Crosscheck roots for 73 tree sizes (0..65, 127..129, 255..257, and 4096).

Negative controls cover hard-deny and missing policy context, timestamp freshness and exact TTL boundary, header edits, signature corruption, insufficient quorum, duplicate signatures and trusted keys, wrong trust roots, signed dissent, missing receipt and empty tree, altered tree/target, inclusion proof corruption/orientation/index/truncation, changed reference chain, and honestly rehashed candidate divergence.

All witness keys are generated in memory for this run. The fixture timestamp and trusted clock are fixed for reproducible boundary tests: timestamp 2026-11-16T00:00:00Z, initial age one second, TTL 300 seconds, explicit trusted hard_deny=False for positive coverage. The report generation timestamp is the actual run time and has its own freshness policy. No private key or synthetic signature is saved in the report.

## Claim boundary

This is a scoped local battery, not exhaustive verification of all Khipu behavior. The independent implementation checks exact chain/Merkle agreement only; signature verification remains Khipu's implementation. All synthetic witnesses run on one host. A three-of-four fixture demonstrates the current library's threshold behavior; it does not settle the separate missing-witness liveness policy.

PASS does not authorize execution, lift a hard deny, prove tenant policy, establish independent witness operators, attest remote deployments, or prove append-only log continuity. Production readiness remains false in the report. Draft Khipu changes are not included unless explicitly selected by their actual commit.

Run `python -m pytest tests -q` for the package and evidence-regression tests. If a Windows machine has an inaccessible shared pytest temporary-directory link, use `--basetemp=.pytest_cache/covenant-v2-tmp` within this worktree. Full cross-repository evidence is generated separately using the explicit source arguments above.
