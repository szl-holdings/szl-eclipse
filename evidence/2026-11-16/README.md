# Covenant v2 source-pinned evidence — 2026-11-16

The accompanying `covenant-v2-source-pinned-report-20261116.json` was generated at **2026-11-16T23:24:23.862863Z** by the committed v2 runner. Its result is **PASS within the declared local test scope**.

## Exact executed source

| Repository | Required and observed code commit |
| --- | --- |
| khipu-consensus | `a5ccc9574dd921dd001bcf4ddd8eef785ccab11c` |
| szl-eclipse | `4ef0c70c4ee2e49185e240b070338fe67a9463ac` |
| szl-crosscheck | `ec7443a5cda273e2fd4728448d9dad37695eec60` |

The Eclipse commit above contains the runner, acceptance fixes, tests and native CI workflow. This report is preserved in a subsequent evidence commit; that later commit is not claimed as the executed code identity. Crosscheck is the separately reviewed candidate [PR32](https://github.com/szl-holdings/szl-crosscheck/pull/32), not labelled here as main. Draft Khipu PR71 is excluded.

All three worktrees were clean. Eleven actual compiled source files were bound to these commits and checked again after execution: four Khipu files, three Eclipse files including the runner, and four Crosscheck files. The report records relative source paths, raw source SHA256, and committed blob SHA256. LF/CRLF normalization accounts for differing raw/committed hashes on Windows.

## Observed validation

| Check | Observed result |
| --- | --- |
| Full Crosscheck package tests | 239 passed |
| Full Eclipse package and evidence-regression tests | 221 passed |
| Declared directed controls | 39/39 passed |
| Eclipse input mutation classes | 10/10 detected, no blind spots |
| Recursive Khipu versus iterative Crosscheck roots | Agreement across 73 tree sizes |
| Live positive controls | Valid STH, valid recall, three-of-four, valid proof, inside-TTL age, exact baseline comparison |
| Rechecking this saved report against current selected sources | PASS, process success |
| Rechecking the earlier report pinned to Eclipse `2ea6850` against the new source pin | ERROR and nonzero exit, as required |

The full manifest is checked by name and expected boolean. Mutation detection is recomputed from typed chain-validity and comparator observations. A claimed caught flag cannot override a CONSISTENT/valid observation. The complete seven-flag claim boundary must remain false. Missing Git, source drift, dirty worktrees, stale report identity, omitted controls, contradictory claims and exceptions cannot qualify as passing evidence.

The report used Windows, Python 3.12.10 and cryptography 50.0.2. The package test run used a worktree-specific pytest temporary directory because the host's shared pytest-current cleanup link denied access. No shared Python environment was changed.

## Reproduction and freshness

Use the instructions in [tools/README.md](../../tools/README.md), selecting clean worktrees at the exact code commits above. Run the tool from the pinned Eclipse worktree and write to a new path outside all source worktrees. Example argument values are the full commits in the table; paths remain operator-selected.

The fixture timestamp/clock are fixed for deterministic policy-boundary tests, with a 300-second TTL and explicit trusted hard_deny=False on valid coverage. Witness keys are synthetic, generated only in memory, and never saved. The report generation timestamp is actual run time. A saved report expires under its caller's age policy (at most 24 hours); this archive remains historical evidence after that point. Generate fresh evidence before relying on current source.

The new PR/manual Linux workflow runs the actual cross-repository battery from sibling checkouts with pinned dependencies and an uploaded report. Local YAML checks passed. A successful hosted workflow run is a separate gate and is not claimed by this Windows report.

## Integrity and limits

- Generated file bytes SHA256: `1cafc5b4dcf67f80e270ae60845b5844139577714e66e49a43bb4682d31dfdf7`.
- Canonical report SHA256 (excluding its own hash field): `5109066a025589a032becb7d16015ced2be2d0558f476fb6690624215d7b0f17`.
- The unkeyed hashes identify contents; they do not authenticate the report.
- Independent Crosscheck scope is exact receipt-chain/Merkle agreement. It is not a second signature verifier.
- All witnesses in this battery are in one local process. No independent operator/host, append-only continuity, deployment attestation, tenant authorization, or production-readiness claim is made.
- Recall coverage does not authorize execution or lift a hard deny. The three-of-four positive fixture does not settle missing-witness liveness policy.
- The November 15 adapter and reports remain byte-for-byte unchanged. Their older evidence is not used to establish the newer wrapper's behavior.
