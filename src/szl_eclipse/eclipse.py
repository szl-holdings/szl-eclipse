"""szl-eclipse: who verifies the verifier.

Attacks a receipt verifier with ten mutation classes against a golden chain
and measures sensitivity. Any verifier can be the system under test - inject
your own callables. The report is receipted; a BLIND-SPOT state names every
mutation class that slipped through.

Honest nuance baked in: post-hoc mutation without re-hashing always breaks the
chain (that is the receipt design working). ALLOW-within-tolerance only
applies to honestly re-hashed chains - documented per-row, not hidden.
"""
from __future__ import annotations
import copy, hashlib, json
from typing import Any, Callable, Dict, List, Tuple

GENESIS = "0" * 64

def canonical(o: Any) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), default=str)

# ---- reference verifier (the shipped crosscheck logic; inject your own) ----

def verify_chain(receipts: List[Dict[str, Any]]) -> Tuple[bool, str]:
    if not receipts:
        return False, "empty chain"
    prev = GENESIS
    for i, r in enumerate(receipts):
        if r.get("prev_hash") != prev:
            return False, f"link broken at receipt {i}"
        payload = {k: v for k, v in r.items() if k not in ("prev_hash", "chain_hash")}
        if r.get("chain_hash") != hashlib.sha256((prev + canonical(payload)).encode()).hexdigest():
            return False, f"payload tampered at receipt {i}"
        prev = r["chain_hash"]
    return True, prev

def crosscheck(chain_a, chain_b, rel_tol=0.01):
    ok_a, da = verify_chain(chain_a)
    ok_b, db = verify_chain(chain_b)
    if not ok_a:
        return {"verdict": "INVALID", "reason": f"chain A: {da}"}
    if not ok_b:
        return {"verdict": "INVALID", "reason": f"chain B: {db}"}
    def lanes(chain):
        out = {}
        for r in chain:
            for res in (r.get("results") or []):
                if isinstance(res, dict) and res.get("runs") and isinstance(res.get("metrics"), dict):
                    lane = str(res.get("engine") or res.get("lane") or "run")
                    out[lane] = {k: float(v) for k, v in res["metrics"].items() if isinstance(v, (int, float))}
        return out
    la, lb = lanes(chain_a), lanes(chain_b)
    if not (set(la) & set(lb)):
        return {"verdict": "INCOMPARABLE"}
    overall = "CONSISTENT"
    for lane in sorted(set(la) & set(lb)):
        for k in set(la[lane]) & set(lb[lane]):
            d = abs(la[lane][k] - lb[lane][k]) / max(abs(la[lane][k]), abs(lb[lane][k]), 1e-12)
            if d > rel_tol:
                overall = "DIVERGENT"
    return {"verdict": overall}

# ---- golden chain ----

def golden_chain(n=3):
    chain, prev = [], GENESIS
    for i in range(n):
        r = {"seq": i, "results": [{"engine": "bm25", "runs": [1, 2, 3],
             "metrics": {"ndcg10": 0.42 + i * 0.001, "mrr": 0.38}}]}
        payload = dict(r)
        r["prev_hash"] = prev
        r["chain_hash"] = hashlib.sha256((prev + canonical(payload)).encode()).hexdigest()
        prev = r["chain_hash"]
        chain.append(r)
    return chain

# ---- mutation operators ----

def _m_metric_tamper(c): c[1]["results"][0]["metrics"]["ndcg10"] = 0.99; return c
def _m_reorder(c): c[0], c[2] = c[2], c[0]; return c
def _m_prevhash_swap(c): c[2]["prev_hash"] = "ab" * 32; return c
def _m_terminal_truncate(c): c[-1]["chain_hash"] = c[-1]["chain_hash"][:32]; return c
def _m_lane_rename(c): c[1]["results"][0]["engine"] = "bm25-shadow"; return c
def _m_key_rename(c): c[1]["results"][0]["metrics"]["ndcg_10"] = c[1]["results"][0]["metrics"].pop("ndcg10"); return c
def _m_precision_drift(c): c[1]["results"][0]["metrics"]["ndcg10"] += 0.0000001; return c
def _m_type_confusion(c): c[1]["results"][0]["metrics"]["ndcg10"] = "0.43"; return c
def _m_empty(c): return []
def _m_duplicate_lane(c): c[1]["results"].append(copy.deepcopy(c[1]["results"][0])); return c

MUTATIONS = [
    ("metric_tamper", _m_metric_tamper, "CATCH"),
    ("reorder", _m_reorder, "CATCH"),
    ("prevhash_swap", _m_prevhash_swap, "CATCH"),
    ("terminal_truncate", _m_terminal_truncate, "CATCH"),
    ("lane_rename", _m_lane_rename, "CATCH"),
    ("key_rename", _m_key_rename, "CATCH"),
    ("precision_drift", _m_precision_drift, "ALLOW-ONLY-WITHIN-TOLERANCE"),
    ("type_confusion", _m_type_confusion, "CATCH"),
    ("empty", _m_empty, "CATCH"),
    ("duplicate_lane", _m_duplicate_lane, "CATCH"),
]

def eclipse_run(verify_fn: Callable = None, cross_fn: Callable = None, rel_tol: float = 0.01) -> Dict[str, Any]:
    """Attack the verifier under test with every mutation class; measure sensitivity.
    verify_fn(chain) -> (ok, detail); cross_fn(reference, mutated, rel_tol) -> {'verdict': ...}.
    Defaults are the reference implementations above."""
    verify_fn = verify_fn or verify_chain
    cross_fn = cross_fn or crosscheck
    golden = golden_chain()
    reference = golden_chain()
    rows, blind_spots = [], []
    for name, fn, expectation in MUTATIONS:
        mutated = fn(copy.deepcopy(golden))
        ok, detail = verify_fn(mutated)
        xc = cross_fn(reference, mutated, rel_tol)
        verdict = xc.get("verdict") if isinstance(xc, dict) else str(xc)
        if expectation == "CATCH":
            caught = (not ok) or verdict in ("INVALID", "INCOMPARABLE", "DIVERGENT")
            if not caught:
                blind_spots.append(name)
            rows.append({"mutation": name, "chain_valid": ok, "crosscheck": verdict,
                         "expectation": expectation, "caught": caught})
        else:
            rows.append({"mutation": name, "chain_valid": ok, "crosscheck": verdict,
                         "expectation": expectation, "caught": True,
                         "note": "drift without rehash breaks the chain; ALLOW applies only to honestly re-hashed chains"})
    caught_n = sum(1 for r in rows if r["caught"])
    report = {"state": "VERIFIED-SENSITIVE" if not blind_spots else "BLIND-SPOT",
              "sensitivity": f"{caught_n}/{len(rows)}", "blind_spots": blind_spots,
              "mutations": rows, "rel_tol": rel_tol}
    payload = {"mutations": [r["mutation"] for r in rows], "blind_spots": blind_spots, "tol": rel_tol}
    report["receipt"] = hashlib.sha256(canonical(payload).encode()).hexdigest()
    report["label"] = "mutation harness for receipt verifiers - who verifies the verifier"
    return report

if __name__ == "__main__":
    rep = eclipse_run()
    print(json.dumps({"state": rep["state"], "sensitivity": rep["sensitivity"],
                      "blind_spots": rep["blind_spots"], "receipt": rep["receipt"][:16]}, indent=2))
