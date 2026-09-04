# szl-eclipse

Your verifier catches tampering. **Prove it.**

szl-eclipse is mutation-testing for receipt verifiers: it attacks the verifier
under test with ten classes of doctored receipt chains and reports sensitivity
with a receipt of its own. A verifier that waves everything through scores
1/10 and is named BLIND-SPOT. The estate's reference verifier scores 10/10 —
and that score is recomputed, not asserted.

## The ten attack classes

metric tamper · receipt reorder · prev_hash swap · terminal truncation ·
lane rename · metric-key rename · precision drift · type confusion ·
empty chain · duplicate-lane injection

One honest nuance: mutating a chain without re-hashing always breaks the
chain — that is the receipt design working, not the verifier being clever.
Within-tolerance drift (`ALLOW-ONLY-WITHIN-TOLERANCE`) only applies to
honestly re-hashed chains, and the report says so per row.

## Usage

```bash
pip install -e . pytest && python -m pytest tests/ -q
python -m szl_eclipse.eclipse        # reference self-report
```

Point it at any verifier — yours, ours, the FastAPI planes':

```python
from szl_eclipse import eclipse_run

rep = eclipse_run(verify_fn=my_verify, cross_fn=my_crosscheck)
print(rep["state"], rep["sensitivity"], rep["blind_spots"])
```

## Doctrine

- The harness accepts the verifier as a callable — no privileged reference.
- BLIND-SPOT names what slipped; there is no partial credit.
- The report's receipt is deterministic: same harness, same mutations, same hash.
- Python 3.11+, standard library only.

## License

Apache-2.0 — canonical org text (see LICENSE pointer).
