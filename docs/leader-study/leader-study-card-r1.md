# szl-eclipse — Domain Leader Study Card r1 (propose-only)

OUROBOROS pass 1 of 10 - 2026-11-25 - CTO web lane (github_app). Propose-only: never merge without owner GO.

## Domain leaders
- Mutation-testing research lineage: Mike Papadakis, Rene Just et al. (Univ. Luxembourg / Lero / UCD). Canonical audit: Assessing and Improving the Mutation Testing Practice of PIT - Laurent, Ventresque, Papadakis, Henard, Le Traon (arXiv:1601.02351): real-world mutation tools must constrain redundant mutants to community-standard operator sets.
- PIT (industry practice): the de-facto real-world mutation tool whose operator repertoire the audit constrained.

## Moat to absorb (estate-specific)
- Eclipse runs the correct experiment: attack the verifier (tests judged by mutants killed -> verifiers judged by tamper-classes caught).
- Declare attack-class provenance (standard operator analog vs. novel estate class).
- Minimize redundant attack mutants (10 well-chosen classes beat 50 overlapping ones) with documented pruning rationale.
- Per-release verifier kill-card: attack-class x killed/survived/OUT_OF_SCOPE, deterministic SVG.
- Equivalence handling: undetectable-by-scope tampers must be declared OUT_OF_SCOPE in receipts (fail-closed honesty), never silently surviving.

## Recommended upgrades (owner-gated)
1. README 'Lineage' section with the citation set + per-attack-class provenance mapping.
2. Kill-card emission per verifier release via estate-cards weaver.
3. Redundancy pass over the ten classes with pruning rationale.

Sources: arXiv:1601.02351 (https://ar5iv.labs.arxiv.org/html/1601.02351).