# Covenant v0.4 step 3 — mutation report over the v0.4 STH verifier (2026-11-15)

## What this is

szl-eclipse mutation evidence for the Memory Covenant v0.4
(spec: szl-holdings/szl-frontier docs/COVENANT_V0_4_COUNTERSIGN_SPEC_2026-11-15.md, section 3):
the standing evidence that the v0.4 witness-countersigned STH verifier detects
tampering (3.1), the szl-crosscheck leg — two independent harnesses consuming
the same receipt bundle (3.2) — and the report pinned to the commits it
verified (3.3).

## Result (measured, not asserted)

- OVERALL: VERIFIED-SENSITIVE
- szl-eclipse fixed ten attack classes: 10/10 caught, no blind spots
  (eclipse_run state VERIFIED-SENSITIVE, receipt eefa1ddf62acc29767bff651bf64bea26a6f49782950c47ed7504aef744224f7)
- Directed battery on the NEW v0.4 surfaces: 14/14 attacks caught
  + golden positive control PASS
- Crosscheck leg: harness A (khipu production tree) and harness B (an
  independent index-recursive reference in the adapter) agree exactly on the
  golden bundle; baseline crosscheck CONSISTENT; no DIVERGENT alarm occurred

## System under test — the composed v0.4 recall adjudication path

1. v0.3 chain verification (szl-eclipse reference verify_chain)
2. khipu_consensus.receipt_tree.ReceiptTree over the chain digests
3. khipu_consensus.sth.verify_sth_receipt (3-of-4, fail-closed; UNKNOWN never PASS)
4. receipt_tree.verify_inclusion for every leaf (orientation-bound)
5. receipt_tree.recall_gate (spec 1.3 hard rule: no countersigned STH, no release)

The fixed ten classes mostly stress the v0.3 chain layer of the composed
path, so the adapter adds a DIRECTED BATTERY against the new surfaces:
sth_root_tamper, witness_signature_flip, quorum_strip_2_of_4 (UNKNOWN —
never PASS), binding_session_swap, tree_size_drift, trusted_key_swap
(UNKNOWN), duplicate_witness_inflate (NO-INFLATION: distinct-witness rule
holds at consensus_count=3), proof_node_swap, proof_orientation_flip,
proof_truncate, index_shift (the orientation binding), leaf_digest_tamper,
missing_sth_receipt (the spec 1.3 hard rule), empty_tree_no_evidence.

## Pinning (spec 3.3)

- khipu-consensus commit a07aa20759cd4f45f772926b3e67377b0d703858
  (branch feat/v0.4-receipt-tree-gate; PRs #66 step 1, #67 step 2)
  - python/khipu_consensus/receipt_tree.py SHA-256 0b04a1568969b77055c0b2d1dbbccc124db086c8191eac0c32c7b48bcd6be6d8
  - python/khipu_consensus/sth.py SHA-256 ac9e88e3a3ae2a4701233a84d47190288584b04e610f1af8bccff8edd916a7cc
- szl-eclipse commit c550abe8e525d507733cf3e2498e3adc8968e98e (version 0.2.2)
- Adapter SHA-256 ee88ea8e0b2b74674f199b7142128897c13ea3bb75d4055b3a8977d2d246eb6e
- Report file SHA-256 fb012099c387dee1ad41b8ed75972a58907a08092dda8a3ee5f4573b06dba1e2
- Report canonical receipt 0b2b977f192c1c0bc8d6706916a6dbfdac73d5bd08c2a5c86cd9cb74a9dc0df8
- Generated 2026-11-15T22:56:50Z on the owner-authorized device BETTERWITHAGE
  (Python 3.12.10, Windows-11-10.0.26200-SP0)

## Reproduce

Requires a khipu-consensus checkout at the pinned commit and a szl-eclipse
checkout (paths are set at the top of the adapter). Run:

    python covenant-v04-mutation-adapter-20261115.py

The run prints OVERALL=VERIFIED-SENSITIVE and writes the receipted report JSON.

## Honesty (binding)

- Witness keys are EPHEMERAL in-process ECDSA-P256 test keys; witnesses are
  estate-operated; the claim is exactly multi-party-witnessed, never trustless
  (spec 1.4). The report pins commits and file digests instead of keys.
- Scope is LOCAL_FIXTURE_VERIFIER_CONTROLS on a deterministic golden bundle —
  not retrieval, model-accuracy, or production-performance measurement.
- rel_tol is not applicable to the covenant bundle agreement: bundle agreement
  is exact digest agreement. The crosscheck comparator honors the eclipse
  callback contract and documents this in the report.
- Adjudication is read-only (spec 4): this evidence proves facts about
  bundles; it never lifts a deny and never authorizes anything.
- The report is pinned to the khipu PR-head commit; if PR #67 is rebased
  before merging, regenerate the report.
- BFT safety/liveness remain Conjectures 2/3; DenyMonotonic (spec step 4,
  lutar-lean) remains unproved; the production HOLD is unchanged.

## Files

- covenant-v04-mutation-report-20261115.json — the receipted report exactly as produced
- covenant-v04-mutation-adapter-20261115.py — the adapter exactly as executed
  (EVIDENCE TOOLING, not package source; the szl-eclipse PyPI package stays
  standard-library only)
