# SPDX-License-Identifier: Apache-2.0
# © 2026 Lutar, Stephen P. — SZL Holdings · ORCID 0009-0001-0110-4173
"""Covenant v0.4 step 3 — szl-eclipse mutation report over the v0.4 verifier.

Spec: szl-frontier docs/COVENANT_V0_4_COUNTERSIGN_SPEC_2026-11-15.md, section 3:
  3.1 szl-eclipse mutation testing over receipt verifiers (ten attack classes)
      is the standing evidence that the STH verifier detects tampering.
  3.2 szl-crosscheck cross-implementation verification: two independent
      harnesses consume the same receipt bundle and must agree on CONSISTENT.
  3.3 No verifier ships without a passing mutation report pinned to its commit.

System under test — the composed v0.4 recall adjudication path:
  v0.3 chain verification (szl-eclipse reference verify_chain)
  -> khipu_consensus.receipt_tree.ReceiptTree over the chain digests
  -> khipu_consensus.sth.verify_sth_receipt (3-of-4, fail-closed)
  -> receipt_tree.verify_inclusion for every leaf (orientation-bound)
  -> receipt_tree.recall_gate (spec 1.3 hard rule)

The fixed ten classes mostly stress the v0.3 chain layer of the composed
path; a DIRECTED BATTERY additionally attacks the NEW v0.4 surfaces the
fixed classes cannot reach directly: verify_sth_receipt (root tamper,
signature flip, quorum strip, binding swap, size drift, trusted-key swap,
duplicate-witness inflation), verify_inclusion (node swap, orientation
flip, truncation, wrong-index claim), and recall_gate (leaf tamper,
missing STH, empty tree).

Honesty (binding):
  * EVIDENCE TOOLING, not package source: requires a khipu-consensus
    checkout and a szl-eclipse checkout on sys.path. The szl-eclipse PyPI
    package stays standard-library only.
  * rel_tol is NOT applicable to the covenant bundle agreement: bundle
    agreement is exact digest agreement. The crosscheck comparator honors
    the eclipse callback contract and documents this in the report.
  * Witness keys here are EPHEMERAL in-process test keys; the report pins
    the khipu/eclipse commits and this adapter's own SHA-256 instead.
  * Adjudication is read-only (spec 4): nothing here lifts a deny or
    authorizes anything. UNKNOWN never PASS; DENY is the default.

Adapter as executed 2026-11-15 (SHA-256 ee88ea8e0b2b74674f199b7142128897c13ea3bb75d4055b3a8977d2d246eb6e)
on the owner-authorized device BETTERWITHAGE; produced
covenant-v04-mutation-report-20261115.json (file SHA-256 fb012099c387dee1ad41b8ed75972a58907a08092dda8a3ee5f4573b06dba1e2).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime, timezone

KHIPU_PYTHON_DIR = r"C:\SZL\repos\khipu-consensus\python"
KHIPU_REPO_DIR = r"C:\SZL\repos\khipu-consensus"
ECLIPSE_REPO_DIR = r"C:\SZL\scratch\szl-eclipse-covenant"
ECLIPSE_SRC_DIR = os.path.join(ECLIPSE_REPO_DIR, "src")
REPORT_PATH = r"C:\SZL\scratch\v04-covenant-eclipse\report.json"

sys.path.insert(0, ECLIPSE_SRC_DIR)
sys.path.insert(0, KHIPU_PYTHON_DIR)

from szl_eclipse import eclipse_run, golden_chain  # noqa: E402
from szl_eclipse.eclipse import verify_chain  # noqa: E402

from khipu_consensus.sth import (  # noqa: E402
    countersign_sth,
    merkle_root,
    verify_sth_receipt,
)
from khipu_consensus.receipt_tree import (  # noqa: E402
    RECALL_DENY,
    RECALL_RELEASE,
    ReceiptTree,
    recall_gate,
    verify_inclusion,
)
from khipu_consensus.witness import Witness, WitnessRegistry  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402

SESSION_ID = "eclipse-covenant-v04"
FIXED_TS = "2026-11-15T00:00:00Z"
THRESHOLD = 3
TARGET_INDEX = 1


def _new_keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    pem_priv = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pem_pub = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return pem_priv, pem_pub


def _registry(keepers=("sentra", "amaru", "a11oy")):
    """4-organ estate-style pool; only keepers hold keys (others abstain honestly)."""
    ws = []
    for organ in ("sentra", "amaru", "a11oy", "killinchu"):
        pem_priv, pem_pub = _new_keypair()
        ws.append(Witness(
            organ=organ, public_key_pem=pem_pub, region="test", org="test",
            private_key_pem=pem_priv if organ in keepers else None,
        ))
    return WitnessRegistry(ws, threshold=THRESHOLD)


def _wrong_trusted():
    """A full-size but WRONG trusted pool: unknown keys must never count."""
    out = {}
    for i in range(4):
        _, pem_pub = _new_keypair()
        out["stranger-" + str(i)] = pem_pub
    return out


REGISTRY = _registry()
TRUSTED = REGISTRY.pubkeys()
WRONG_TRUSTED = _wrong_trusted()
GOLDEN = golden_chain()
GOLDEN_DIGESTS = [r["chain_hash"] for r in GOLDEN]
TREE = ReceiptTree.build(SESSION_ID, GOLDEN_DIGESTS)
SEALED = countersign_sth(TREE.sth(timestamp=FIXED_TS), REGISTRY)
SEALED_DICT = SEALED.to_dict()
TARGET_DIGEST = TREE.leaf(TARGET_INDEX)


# ---- system under test: composed v0.4 recall adjudication over a chain ----

def covenant_verify_fn(chain):
    """verify_fn(chain) -> (bool, detail). True only when the whole composed
    v0.4 path is green: chain links + payload digests, tree root, VERIFIED
    3-of-4 countersigned STH, per-leaf inclusion coverage, recall RELEASE."""
    try:
        ok, detail = verify_chain(chain)
        if not ok:
            return False, detail
        digests = [r.get("chain_hash", "") for r in chain]
        try:
            tree = ReceiptTree.build(SESSION_ID, digests)
        except (ValueError, TypeError) as exc:
            return False, "tree build rejected: " + str(exc)
        verdict = verify_sth_receipt(
            SEALED_DICT,
            TRUSTED,
            threshold=THRESHOLD,
            expected_root=tree.sha256_root_hash,
            expected_session_id=SESSION_ID,
            expected_tree_size=tree.tree_size,
        )
        if not verdict.verified:
            return False, "sth adjudication " + verdict.status + ": " + verdict.reason
        for i in range(tree.tree_size):
            proof = tree.inclusion_proof(i)
            if not verify_inclusion(tree.leaf(i), i, tree.tree_size,
                                   proof, tree.sha256_root_hash):
                return False, "inclusion proof failed at index " + str(i)
        decision = recall_gate(
            tree, SEALED_DICT, TRUSTED, TARGET_INDEX,
            tree.leaf(TARGET_INDEX), threshold=THRESHOLD,
        )
        if decision.status != RECALL_RELEASE:
            return False, "recall gate denied: " + decision.reason
        return True, ("chain intact; " + str(tree.tree_size) + " leaves covered; "
                      "sth " + verdict.status + "; recall RELEASE")
    except Exception as exc:  # fail closed on anything unexpected
        return False, "verifier exception treated as reject: " + type(exc).__name__


# ---- szl-crosscheck leg (spec 3.2): two INDEPENDENT harnesses, one bundle ----

def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _ref_root(leaves):
    """Harness B tree root: independent index-based recursion (no shared code
    with khipu's slice-based recursion or ReceiptTree)."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()

    def sub(lo, hi):
        if hi - lo == 1:
            return hashlib.sha256(b"\x00" + bytes.fromhex(leaves[lo])).hexdigest()
        k = 1
        while (k * 2) < (hi - lo):
            k *= 2
        left = sub(lo, lo + k)
        right = sub(lo + k, hi)
        return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()

    return sub(0, len(leaves))


def _independent_chain_check(chain):
    """Harness B chain check: independently re-derived (double entry)."""
    if not isinstance(chain, (list, tuple)):
        return False, "chain must be a list or tuple"
    if not chain:
        return False, "empty chain"
    prev = "0" * 64
    for i, r in enumerate(chain):
        if not isinstance(r, dict):
            return False, "receipt " + str(i) + " must be an object"
        if r.get("prev_hash") != prev:
            return False, "link broken at receipt " + str(i)
        body = {k: v for k, v in r.items() if k not in ("prev_hash", "chain_hash")}
        try:
            expect = hashlib.sha256((prev + _canonical(body)).encode()).hexdigest()
        except (TypeError, ValueError, RecursionError):
            return False, "noncanonical payload at receipt " + str(i)
        if r.get("chain_hash") != expect:
            return False, "payload tampered at receipt " + str(i)
        prev = r["chain_hash"]
    return True, "chain intact"


def covenant_cross_fn(chain_reference, chain_mutated, rel_tol=0.01):
    """cross_fn(reference, mutated, rel_tol) -> verdict dict.

    Harness A = khipu production tree (merkle_root); harness B = the
    independent reference above. DIVERGENT is a crosscheck alarm (A and B
    disagree — must never occur); INVALID locates tamper; CONSISTENT requires
    exact agreement with the sealed STH root. rel_tol is honored as an
    unused callback argument: bundle agreement is exact digest agreement."""
    del rel_tol, chain_reference
    try:
        ok_b, detail_b = _independent_chain_check(chain_mutated)
        if not ok_b:
            return {"verdict": "INVALID", "reason": "harness B: " + detail_b}
        digests = [r["chain_hash"] for r in chain_mutated]
        if not digests:
            return {"verdict": "INVALID", "reason": "harness B: empty bundle (fail-closed)"}
        root_a = merkle_root(digests)
        root_b = _ref_root(digests)
        if root_a != root_b:
            return {"verdict": "DIVERGENT",
                    "reason": "harness A and harness B computed different roots (crosscheck alarm)"}
        if root_a != SEALED.sha256_root_hash:
            return {"verdict": "INVALID",
                    "reason": "roots agree but mismatch sealed STH root (located): " + root_a[:12]}
        if len(digests) != SEALED.tree_size:
            return {"verdict": "INVALID", "reason": "tree size mismatch with sealed STH"}
        return {"verdict": "CONSISTENT",
                "reason": "harness A and harness B agree; root matches sealed STH: " + root_a[:12]}
    except Exception as exc:
        return {"verdict": "INVALID",
                "reason": "crosscheck exception treated as invalid: " + type(exc).__name__}


# ---- directed battery against the NEW v0.4 surfaces ----

def _row(name, surface, expected, fn, kind="attack"):
    try:
        observed, detail = fn()
        return {"mutation": name, "kind": kind, "surface": surface,
                "expected": expected, "observed": observed,
                "caught": observed == expected, "located": detail}
    except Exception as exc:
        return {"mutation": name, "kind": kind, "surface": surface,
                "expected": expected,
                "observed": "EXCEPTION:" + type(exc).__name__, "caught": False,
                "located": "harness exception treated as not-caught (honest)"}


def _directed_battery():
    rows = []
    proof = TREE.inclusion_proof(TARGET_INDEX)
    root = TREE.sha256_root_hash

    def r_sth_root_tamper():
        d = copy.deepcopy(SEALED_DICT)
        d["sha256_root_hash"] = "ab" * 32
        v = verify_sth_receipt(d, TRUSTED, threshold=THRESHOLD,
                               expected_root=root, expected_session_id=SESSION_ID,
                               expected_tree_size=TREE.tree_size)
        return v.status, v.reason
    rows.append(_row("sth_root_tamper", "verify_sth_receipt", "TAMPERED", r_sth_root_tamper))

    def r_signature_flip():
        d = copy.deepcopy(SEALED_DICT)
        sig = d["signatures"][0]
        raw = bytearray(base64.b64decode(sig["signature"]))
        raw[0] ^= 0xFF
        sig["signature"] = base64.b64encode(bytes(raw)).decode()
        v = verify_sth_receipt(d, TRUSTED, threshold=THRESHOLD,
                               expected_root=root, expected_session_id=SESSION_ID,
                               expected_tree_size=TREE.tree_size)
        return v.status, v.reason
    rows.append(_row("witness_signature_flip", "verify_sth_receipt", "TAMPERED", r_signature_flip))

    def r_quorum_strip():
        d = copy.deepcopy(SEALED_DICT)
        d["signatures"] = [s for s in d["signatures"] if s is not None][:2]
        v = verify_sth_receipt(d, TRUSTED, threshold=THRESHOLD,
                               expected_root=root, expected_session_id=SESSION_ID,
                               expected_tree_size=TREE.tree_size)
        return v.status, v.reason
    rows.append(_row("quorum_strip_2_of_4", "verify_sth_receipt", "UNKNOWN", r_quorum_strip))

    def r_binding_swap():
        d = copy.deepcopy(SEALED_DICT)
        d["session_id"] = "eclipse-covenant-OTHER"
        v = verify_sth_receipt(d, TRUSTED, threshold=THRESHOLD, expected_root=root)
        return v.status, v.reason
    rows.append(_row("binding_session_swap", "verify_sth_receipt", "TAMPERED", r_binding_swap))

    def r_size_drift():
        d = copy.deepcopy(SEALED_DICT)
        d["tree_size"] = TREE.tree_size + 1
        v = verify_sth_receipt(d, TRUSTED, threshold=THRESHOLD,
                               expected_root=root, expected_session_id=SESSION_ID,
                               expected_tree_size=TREE.tree_size)
        return v.status, v.reason
    rows.append(_row("tree_size_drift", "verify_sth_receipt", "TAMPERED", r_size_drift))

    def r_key_swap():
        v = verify_sth_receipt(copy.deepcopy(SEALED_DICT), WRONG_TRUSTED,
                               threshold=THRESHOLD, expected_root=root,
                               expected_session_id=SESSION_ID,
                               expected_tree_size=TREE.tree_size)
        return v.status, v.reason
    rows.append(_row("trusted_key_swap", "verify_sth_receipt", "UNKNOWN", r_key_swap))

    def r_dup_inflate():
        d = copy.deepcopy(SEALED_DICT)
        abstain = [i for i, s in enumerate(d["signatures"]) if s is None]
        if abstain:
            d["signatures"][abstain[0]] = copy.deepcopy(d["signatures"][0])
        v = verify_sth_receipt(d, TRUSTED, threshold=THRESHOLD,
                               expected_root=root, expected_session_id=SESSION_ID,
                               expected_tree_size=TREE.tree_size)
        detail = v.reason + "; consensus_count=" + str(v.consensus_count)
        ok = (v.status == "VERIFIED" and v.consensus_count == THRESHOLD)
        return ("NO-INFLATION" if ok else "INFLATED-OR-OTHER"), detail
    rows.append(_row("duplicate_witness_inflate", "distinct-witness rule", "NO-INFLATION", r_dup_inflate))

    def r_proof_node_swap():
        p = copy.deepcopy(proof)
        p[0]["node"], p[1]["node"] = p[1]["node"], p[0]["node"]
        if p == proof:
            return "NO-OP", "swap produced identical proof (nodes equal) - not a real mutation"
        ok = verify_inclusion(TARGET_DIGEST, TARGET_INDEX, TREE.tree_size, p, root)
        return ("REJECTED" if not ok else "ACCEPTED"), "swapped sibling nodes at depth 0/1"
    rows.append(_row("proof_node_swap", "verify_inclusion", "REJECTED", r_proof_node_swap))

    def r_orientation_flip():
        p = copy.deepcopy(proof)
        p[0]["left"] = not p[0]["left"]
        ok = verify_inclusion(TARGET_DIGEST, TARGET_INDEX, TREE.tree_size, p, root)
        return ("REJECTED" if not ok else "ACCEPTED"), "orientation flag flipped at depth 0"
    rows.append(_row("proof_orientation_flip", "verify_inclusion", "REJECTED", r_orientation_flip))

    def r_proof_truncate():
        p = copy.deepcopy(proof)[:1]
        ok = verify_inclusion(TARGET_DIGEST, TARGET_INDEX, TREE.tree_size, p, root)
        return ("REJECTED" if not ok else "ACCEPTED"), "proof truncated by one node"
    rows.append(_row("proof_truncate", "verify_inclusion", "REJECTED", r_proof_truncate))

    def r_index_shift():
        ok = verify_inclusion(TARGET_DIGEST, TARGET_INDEX + 1, TREE.tree_size,
                              copy.deepcopy(proof), root)
        return ("REJECTED" if not ok else "ACCEPTED"), \
            "proof for index 1 claimed under index 2 (orientation binding)"
    rows.append(_row("index_shift", "verify_inclusion", "REJECTED", r_index_shift))

    def r_leaf_tamper():
        t = ReceiptTree.from_dict(TREE.to_dict())
        t.leaves[TARGET_INDEX] = "ff" * 32
        d = recall_gate(t, copy.deepcopy(SEALED_DICT), TRUSTED, TARGET_INDEX,
                        t.leaves[TARGET_INDEX], threshold=THRESHOLD)
        return d.status, d.reason
    rows.append(_row("leaf_digest_tamper", "recall_gate", RECALL_DENY, r_leaf_tamper))

    def r_no_sth():
        d = recall_gate(TREE, None, TRUSTED, TARGET_INDEX, TARGET_DIGEST,
                        threshold=THRESHOLD)
        return d.status, d.reason
    rows.append(_row("missing_sth_receipt", "recall_gate (spec 1.3 hard rule)",
                     RECALL_DENY, r_no_sth))

    def r_empty_tree():
        empty = ReceiptTree.build(SESSION_ID, [])
        sealed_empty = countersign_sth(empty.sth(timestamp=FIXED_TS), REGISTRY).to_dict()
        d = recall_gate(empty, sealed_empty, TRUSTED, 0, TREE.leaf(0),
                        threshold=THRESHOLD)
        return d.status, d.reason
    rows.append(_row("empty_tree_no_evidence", "recall_gate", RECALL_DENY, r_empty_tree))

    def r_positive_control():
        ok = verify_inclusion(TARGET_DIGEST, TARGET_INDEX, TREE.tree_size,
                              copy.deepcopy(proof), root)
        d = recall_gate(TREE, copy.deepcopy(SEALED_DICT), TRUSTED, TARGET_INDEX,
                        TARGET_DIGEST, threshold=THRESHOLD)
        detail = ("verify_inclusion=" + str(ok) + "; recall=" + d.status
                  + "; " + d.reason)
        if ok and d.status == RECALL_RELEASE:
            return "PASS", detail
        return "FAIL", detail
    rows.append(_row("golden_positive_control", "verify_inclusion+recall_gate",
                     "PASS", r_positive_control, kind="control"))

    return rows


# ---- pinning (spec 3.3) ----

def _git(args, repo_dir):
    try:
        out = subprocess.run(["git", "-C", repo_dir] + args,
                             capture_output=True, text=True, timeout=60)
        return out.stdout.strip()
    except Exception as exc:
        return "unavailable: " + type(exc).__name__


def _file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    eclipse_report = eclipse_run(verify_fn=covenant_verify_fn,
                                 cross_fn=covenant_cross_fn)
    battery_rows = _directed_battery()
    attacks = [r for r in battery_rows if r["kind"] == "attack"]
    controls = [r for r in battery_rows if r["kind"] == "control"]
    attacks_caught = sum(1 for r in attacks if r["caught"])
    controls_ok = all(r["caught"] for r in controls)
    overall = ("VERIFIED-SENSITIVE"
                if (eclipse_report.get("state") == "VERIFIED-SENSITIVE"
                    and attacks_caught == len(attacks) and controls_ok)
                else "BLIND-SPOT")

    adapter_path = os.path.abspath(__file__)
    report = {
        "schema": "szl.eclipse.covenant-v04-mutation-report/v1",
        "spec": {
            "repo": "szl-holdings/szl-frontier",
            "path": "docs/COVENANT_V0_4_COUNTERSIGN_SPEC_2026-11-15.md",
            "file_sha256_git": "47305ea775066c80bd71061e852f4f401f729e13",
            "sections": ["3.1 ten attack classes", "3.2 crosscheck leg",
                          "3.3 report pinned to commits"],
            "step": "v0.4 step 3 (szl-eclipse mutation report + szl-crosscheck leg)",
        },
        "pinning": {
            "khipu_commit": _git(["rev-parse", "HEAD"], KHIPU_REPO_DIR),
            "khipu_branch": _git(["rev-parse", "--abbrev-ref", "HEAD"], KHIPU_REPO_DIR),
            "khipu_receipt_tree_sha256": _file_sha256(
                os.path.join(KHIPU_PYTHON_DIR, "khipu_consensus", "receipt_tree.py")),
            "khipu_sth_sha256": _file_sha256(
                os.path.join(KHIPU_PYTHON_DIR, "khipu_consensus", "sth.py")),
            "khipu_prs": {"step1_sth": 66, "step2_receipt_tree": 67},
            "szl_eclipse_commit": _git(["rev-parse", "HEAD"], ECLIPSE_REPO_DIR),
            "szl_eclipse_version": __import__("szl_eclipse").__version__,
            "adapter_sha256": _file_sha256(adapter_path),
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "device_label": "BETTERWITHAGE (owner-authorized device; parallel lanes untouched)",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "eclipse_run": eclipse_report,
        "crosscheck_leg": {
            "harness_a": "khipu_consensus.sth.merkle_root + ReceiptTree (production v0.4)",
            "harness_b": "independent index-recursive reference in this adapter",
            "agreement": "exact digest agreement; rel_tol not applicable to bundle agreement",
            "note": "DIVERGENT is a crosscheck alarm and must never occur; INVALID locates tamper",
        },
        "directed_battery": {
            "rows": battery_rows,
            "attacks_caught": attacks_caught,
            "attacks_total": len(attacks),
            "controls_ok": controls_ok,
        },
        "honesty": {
            "witness_keys": ("ephemeral in-process ECDSA-P256 test keys; estate-operated "
                              "witnesses; multi-party-witnessed, never trustless"),
            "scope": ("LOCAL_FIXTURE_VERIFIER_CONTROLS - the composed v0.4 recall "
                       "adjudication path on a deterministic golden bundle; not retrieval, "
                       "model-accuracy, or production-performance measurement"),
            "read_only": ("adjudication proves facts about a bundle; never lifts a deny, "
                           "never authorizes (spec 4)"),
            "fail_closed": "UNKNOWN never PASS; DENY is the default",
        },
        "overall": overall,
    }
    report["receipt"] = hashlib.sha256(_canonical(report).encode()).hexdigest()

    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print("ECLIPSE_STATE=" + str(eclipse_report.get("state")))
    print("ECLIPSE_SENSITIVITY=" + str(eclipse_report.get("sensitivity")))
    print("BLIND_SPOTS=" + json.dumps(eclipse_report.get("blind_spots")))
    print("DIRECTED_ATTACKS=" + str(attacks_caught) + "/" + str(len(attacks)))
    print("CONTROLS_OK=" + str(controls_ok))
    print("OVERALL=" + overall)
    print("REPORT_PATH=" + REPORT_PATH)
    print("REPORT_SHA256=" + _file_sha256(REPORT_PATH))
    print("ADAPTER_SHA256=" + report["pinning"]["adapter_sha256"])
    print("KHIPU_COMMIT=" + report["pinning"]["khipu_commit"])
    print("KHIPU_BRANCH=" + report["pinning"]["khipu_branch"])
    print("ECLIPSE_COMMIT=" + report["pinning"]["szl_eclipse_commit"])
    return 0 if overall == "VERIFIED-SENSITIVE" else 1


if __name__ == "__main__":
    sys.exit(main())
