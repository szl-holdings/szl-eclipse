# SPDX-License-Identifier: Apache-2.0
"""Portable, fail-closed Covenant v2 evidence runner. See tools/README.md."""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import platform
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA = "szl.covenant-v2-evidence/v2"
SCOPE = "synthetic local STH v2 verification and exact chain/Merkle crosscheck"
CLAIM_BOUNDARY = {
    "production_ready": False, "execution_authorized": False,
    "policy_authorized": False, "operator_independence_verified": False,
    "append_only_continuity_verified": False,
    "crosscheck_signature_verification": False, "report_authentication": False,
}
SESSION = "covenant-v2-evidence-fixture"
FIXTURE_TS = "2026-11-16T00:00:00Z"
FIXTURE_NOW = datetime(2026, 11, 16, 0, 0, 1, tzinfo=timezone.utc)
TTL = 300
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MUTATION_NAMES = {
    "metric_tamper", "reorder", "prevhash_swap", "terminal_truncate", "lane_rename",
    "key_rename", "precision_drift", "type_confusion", "empty", "duplicate_lane",
}
CONTROL_EXPECTATIONS = {
    **{name: True for name in (
        "valid_sth", "valid_recall", "three_of_four", "age_inside_ttl",
        "proof_positive", "independent_roots",
    )},
    **{name: False for name in (
        "hard_deny", "missing_policy", "boolean_policy_alias", "omitted_policy_context",
        "missing_time", "naive_time", "missing_ttl", "invalid_ttl_bool", "invalid_ttl_zero",
        "ttl_boundary", "future_timestamp", "timestamp_edit", "root_edit", "session_edit",
        "size_edit", "schema_downgrade", "signature_flip", "quorum_strip",
        "duplicate_signature", "duplicate_trusted_key", "wrong_trusted_pool",
        "signed_dissent", "missing_receipt", "empty_tree", "tree_leaf_edit", "wrong_target",
        "wrong_index_bool", "proof_node_edit", "proof_orientation_edit", "proof_truncate",
        "proof_wrong_index", "changed_reference", "rehashed_candidate",
    )},
}


class ProvenanceError(RuntimeError):
    """No passing evidence can be issued without complete source identity."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def git(repo, *args):
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args], check=False,
            capture_output=True, timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProvenanceError("git is unavailable or timed out") from exc
    if result.returncode:
        raise ProvenanceError("git could not verify repository identity")
    return result.stdout


def repository_identity(repo, expected_commit, loaded_files):
    """Require a clean exact commit and bind actual compiled source bytes.

    Git blobs use LF; Windows checkouts may use CRLF. Only this normalization
    is allowed. Both raw source SHA256 and committed blob SHA256 are recorded.
    """
    repo = Path(repo).resolve(strict=True)
    if type(expected_commit) is not str or _HEX40.fullmatch(expected_commit) is None:
        raise ProvenanceError("an explicit full lowercase commit SHA is required")
    actual_root = Path(git(repo, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if actual_root != repo:
        raise ProvenanceError("repository path is not its worktree root")
    actual_commit = git(repo, "rev-parse", "HEAD").decode().strip()
    if actual_commit != expected_commit:
        raise ProvenanceError("repository HEAD does not match the expected commit")
    if git(repo, "status", "--porcelain=v1", "--untracked-files=all").strip():
        raise ProvenanceError("repository worktree is not clean")
    if not loaded_files:
        raise ProvenanceError("no executed source files were identified")
    sources = {}
    for filename, compiled_sha256 in sorted(loaded_files.items()):
        path = Path(filename).resolve(strict=True)
        try:
            relative = path.relative_to(repo).as_posix()
        except ValueError as exc:
            raise ProvenanceError("loaded module is outside its selected repository") from exc
        actual = path.read_bytes()
        if digest(actual) != compiled_sha256:
            raise ProvenanceError("loaded source changed after compilation")
        committed = git(repo, "show", f"{expected_commit}:{relative}")
        if actual.replace(b"\r\n", b"\n") != committed.replace(b"\r\n", b"\n"):
            raise ProvenanceError("loaded source differs from its committed blob")
        sources[relative] = {
            "sha256": compiled_sha256, "git_blob_sha256": digest(committed),
            "source_path": relative, "compiled_origin_verified": True,
        }
    return {"commit": actual_commit, "worktree_clean": True,
            "worktree_root_verified": True, "sources": sources}


class _SourceLoader(importlib.machinery.SourceFileLoader):
    def __init__(self, fullname, path, recorder):
        super().__init__(fullname, path)
        self.recorder = recorder

    def get_code(self, fullname):
        # Read and compile source directly. A stale/supplied pyc cannot execute.
        source = self.get_data(self.path)
        self.recorder[fullname] = {
            "path": str(Path(self.path).resolve()), "sha256": digest(source),
        }
        return self.source_to_code(source, self.path)


class PinnedSources(importlib.abc.MetaPathFinder):
    """Load all three repository namespaces from explicit source roots."""
    def __init__(self, roots):
        self.roots = {name: Path(path).resolve(strict=True) for name, path in roots.items()}
        self.loaded = {}

    def find_spec(self, fullname, path=None, target=None):
        prefix = fullname.split(".")[0]
        if prefix not in self.roots:
            return None
        relative = fullname.split(".")[1:]
        base = self.roots[prefix].joinpath(*relative)
        source = base / "__init__.py" if (base / "__init__.py").is_file() else base.with_suffix(".py")
        if not source.is_file():
            raise ProvenanceError(f"module source is absent: {fullname}")
        loader = _SourceLoader(fullname, str(source), self.loaded)
        return importlib.util.spec_from_file_location(
            fullname, source, loader=loader,
            submodule_search_locations=[str(base)] if source.name == "__init__.py" else None,
        )

    def __enter__(self):
        if any(name.split(".")[0] in self.roots for name in sys.modules):
            raise ProvenanceError("a selected package was imported before source pinning")
        sys.meta_path.insert(0, self)
        return self

    def __exit__(self, *_):
        sys.meta_path.remove(self)

    def files_for(self, prefix):
        files = {}
        for name, identity in self.loaded.items():
            if name.split(".")[0] == prefix:
                module = sys.modules.get(name)
                if module is None or Path(module.__file__).resolve() != Path(identity["path"]):
                    raise ProvenanceError("loaded module origin changed")
                files[identity["path"]] = identity["sha256"]
        return files


def report_digest(report):
    return digest(canonical({k: v for k, v in report.items() if k != "report_sha256"}))


def evidence_usable(report, *, expected_commits, now, max_age_seconds=86400):
    """Check a saved report's age, integrity and caller-selected source pins.

    This is an unkeyed integrity/freshness check, not report authentication.
    The caller must obtain reports and expected commits through a trusted path.
    """
    try:
        if (type(report) is not dict or report.get("schema") != SCHEMA
                or report.get("state") != "PASS"
                or report.get("scope") != SCOPE
                or type(expected_commits) is not dict
                or set(expected_commits) != {"khipu", "eclipse", "crosscheck"}
                or type(max_age_seconds) is not int or not 0 < max_age_seconds <= 86400
                or not isinstance(now, datetime) or now.utcoffset() is None
                or report.get("report_sha256") != report_digest(report)):
            return False
        generated = datetime.fromisoformat(report["generated_utc"].replace("Z", "+00:00"))
        if generated.utcoffset() is None or not 0 <= (now - generated).total_seconds() < max_age_seconds:
            return False
        if set(report["provenance"]) != set(expected_commits):
            return False
        boundary = report["claim_boundary"]
        if (type(boundary) is not dict or set(boundary) != set(CLAIM_BOUNDARY)
                or any(value is not False for value in boundary.values())):
            return False
        for name, expected in expected_commits.items():
            entry = report["provenance"][name]
            if (_HEX40.fullmatch(expected) is None or entry["commit"] != expected
                    or entry["worktree_clean"] is not True
                    or entry["worktree_root_verified"] is not True or not entry["sources"]):
                return False
            for source in entry["sources"].values():
                if (_HEX64.fullmatch(source["sha256"]) is None
                        or _HEX64.fullmatch(source["git_blob_sha256"]) is None
                        or not source["source_path"]
                        or source["compiled_origin_verified"] is not True):
                    return False
        return battery_passed(report["battery"])
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


def mutation_detected(row):
    """Derive detection from typed observations; never trust a caught claim."""
    if type(row) is not dict or type(row.get("chain_valid")) is not bool:
        return False
    verdict = row.get("crosscheck")
    rejected = {"INVALID", "INCOMPARABLE", "DIVERGENT"}
    if type(verdict) is not str or verdict not in rejected | {"CONSISTENT"}:
        return False
    observed_detection = row["chain_valid"] is False or verdict in rejected
    return observed_detection and row.get("caught") is observed_detection


def battery_passed(battery):
    try:
        controls = battery["controls"]
        names = {row["name"] for row in controls}
        return (
            names == set(CONTROL_EXPECTATIONS) and len(names) == len(controls)
            and all(row["state"] == "PASS" and type(row["observed"]) is bool
                    and row["expected"] is CONTROL_EXPECTATIONS[row["name"]]
                    and row["observed"] is row["expected"] for row in controls)
            and battery["eclipse"]["state"] == "VERIFIED-SENSITIVE"
            and battery["eclipse"]["baseline"]["chain_valid"] is True
            and battery["eclipse"]["baseline"]["crosscheck"]["verdict"] == "CONSISTENT"
            and battery["eclipse"]["sensitivity"] == "10/10"
            and len(battery["eclipse"]["mutations"]) == len(MUTATION_NAMES)
            and {row["mutation"] for row in battery["eclipse"]["mutations"]} == MUTATION_NAMES
            and all(mutation_detected(row) for row in battery["eclipse"]["mutations"])
            and battery["eclipse"]["blind_spots"] == []
        )
    except (KeyError, TypeError):
        return False


def record_control(rows, name, expected, operation):
    try:
        observed = operation()
        state = "PASS" if type(observed) is bool and observed is expected else "FAIL"
        rows.append({"name": name, "expected": expected, "observed": observed, "state": state})
    except Exception as exc:
        # An exception is a harness error, never a successful negative control.
        rows.append({"name": name, "expected": expected, "observed": None,
                     "state": "ERROR", "error_type": type(exc).__name__})


def run_battery(sth, tree_module, witness, eclipse, cross):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization

    def registry():
        members = []
        for index in range(4):
            key = ec.generate_private_key(ec.SECP256R1())
            members.append(witness.Witness(
                organ=f"synthetic-{index}", region="single-host-test",
                org="synthetic-fixture",
                public_key_pem=key.public_key().public_bytes(
                    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode(),
                private_key_pem=key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode(),
            ))
        return witness.WitnessRegistry(members, threshold=3)

    pool = registry()
    trusted = pool.pubkeys()
    golden = eclipse.golden_chain()
    tree = tree_module.ReceiptTree.build(SESSION, [row["chain_hash"] for row in golden])
    sealed = sth.countersign_sth(tree.sth(timestamp=FIXTURE_TS), pool).to_dict()
    root = tree.sha256_root_hash

    def verified(receipt=sealed, keys=trusted):
        return sth.verify_sth_receipt(
            receipt, keys, threshold=3, expected_root=root,
            expected_session_id=SESSION, expected_tree_size=tree.tree_size,
        ).verified

    def recall(receipt=sealed, selected_tree=tree, **overrides):
        args = {
            "hard_deny": False, "now": FIXTURE_NOW, "max_age_seconds": TTL,
            "target_index": 1, "target_digest": tree.leaf(1),
        }
        args.update(overrides)
        decision = tree_module.recall_gate(selected_tree, receipt, trusted, **args)
        if decision.execution_authorized is not False or decision.policy_authorized is not False:
            raise AssertionError("coverage decision claimed execution or policy authorization")
        return decision.release

    def verify_chain(chain):
        ok, detail = eclipse.verify_chain(chain)
        if not ok:
            return False, detail
        candidate = tree_module.ReceiptTree.build(SESSION, [row["chain_hash"] for row in chain])
        if not sth.verify_sth_receipt(
            sealed, trusted, expected_root=candidate.sha256_root_hash,
            expected_session_id=SESSION, expected_tree_size=candidate.tree_size,
        ).verified:
            return False, "signed tree does not cover the supplied chain"
        for index in range(candidate.tree_size):
            if not tree_module.verify_inclusion(
                candidate.leaf(index), index, candidate.tree_size,
                candidate.inclusion_proof(index), candidate.sha256_root_hash,
            ):
                return False, "inclusion proof failed"
        return recall(selected_tree=candidate), "live STH v2 coverage and freshness check"

    def compare(reference, candidate, _tolerance):
        try:
            cross.chain_identity(candidate)
        except cross.CovenantInputError as exc:
            return {"verdict": "INVALID", "scope": cross.SCOPE, "reason": str(exc)}
        observed = sth.merkle_root([row["chain_hash"] for row in candidate])
        return cross.crosscheck_covenant(
            reference, candidate, observed_root=observed, expected_root=root,
        )

    controls = []
    add = lambda name, expected, op: record_control(controls, name, expected, op)
    add("valid_sth", True, verified)
    add("valid_recall", True, recall)
    three = copy.deepcopy(sealed)
    three["signatures"][3] = None
    add("three_of_four", True, lambda: recall(receipt=three))
    add("age_inside_ttl", True, lambda: recall(now=FIXTURE_NOW + timedelta(seconds=298)))
    add("hard_deny", False, lambda: recall(hard_deny=True))
    add("missing_policy", False, lambda: recall(hard_deny=None))
    add("boolean_policy_alias", False, lambda: recall(hard_deny=0))
    add("omitted_policy_context", False, lambda: tree_module.recall_gate(
        tree, sealed, trusted, 1, tree.leaf(1)).release)
    add("missing_time", False, lambda: recall(now=None))
    add("naive_time", False, lambda: recall(now=FIXTURE_NOW.replace(tzinfo=None)))
    add("missing_ttl", False, lambda: recall(max_age_seconds=None))
    add("invalid_ttl_bool", False, lambda: recall(max_age_seconds=True))
    add("invalid_ttl_zero", False, lambda: recall(max_age_seconds=0))
    add("ttl_boundary", False, lambda: recall(now=FIXTURE_NOW + timedelta(seconds=299)))
    add("future_timestamp", False, lambda: recall(now=FIXTURE_NOW - timedelta(seconds=2)))
    for name, field, value in [
        ("timestamp_edit", "timestamp", "2026-11-16T00:00:01Z"),
        ("root_edit", "sha256_root_hash", "a" * 64),
        ("session_edit", "session_id", "different-session"),
        ("size_edit", "tree_size", 4),
        ("schema_downgrade", "version", 1),
    ]:
        changed = copy.deepcopy(sealed)
        changed["sth"][field] = value
        add(name, False, lambda changed=changed: verified(changed))
    corrupted = copy.deepcopy(sealed)
    signature = bytearray(base64.b64decode(corrupted["signatures"][0]["signature"]))
    signature[-1] ^= 1
    corrupted["signatures"][0]["signature"] = base64.b64encode(signature).decode()
    add("signature_flip", False, lambda: verified(corrupted))
    stripped = copy.deepcopy(sealed)
    stripped["signatures"] = stripped["signatures"][:2]
    add("quorum_strip", False, lambda: verified(stripped))
    duplicated = copy.deepcopy(sealed)
    duplicated["signatures"] = [copy.deepcopy(sealed["signatures"][0])] * 4
    add("duplicate_signature", False, lambda: verified(duplicated))
    aliases = {name: next(iter(trusted.values())) for name in trusted}
    add("duplicate_trusted_key", False, lambda: verified(keys=aliases))
    wrong = registry().pubkeys()
    add("wrong_trusted_pool", False, lambda: verified(keys=wrong))
    dissent = sth.countersign_sth(
        tree.sth(timestamp=FIXTURE_TS), pool, verdicts={"synthetic-3": "block"},
    ).to_dict()
    add("signed_dissent", False, lambda: verified(dissent))
    add("missing_receipt", False, lambda: recall(receipt=None))
    empty_tree = tree_module.ReceiptTree.build(SESSION, [])
    add("empty_tree", False, lambda: recall(selected_tree=empty_tree))
    changed_tree = copy.deepcopy(tree)
    changed_tree.leaves[0] = "a" * 64
    add("tree_leaf_edit", False, lambda: recall(selected_tree=changed_tree))
    add("wrong_target", False, lambda: recall(target_digest="a" * 64))
    add("wrong_index_bool", False, lambda: recall(target_index=True))
    proof = tree.inclusion_proof(1)

    def proof_valid(path=proof, index=1):
        return tree_module.verify_inclusion(tree.leaf(1), index, tree.tree_size, path, root)

    add("proof_positive", True, proof_valid)
    changed_proof = copy.deepcopy(proof)
    changed_proof[0]["node"] = "a" * 64
    add("proof_node_edit", False, lambda: proof_valid(changed_proof))
    flipped = copy.deepcopy(proof)
    flipped[0]["left"] = not flipped[0]["left"]
    add("proof_orientation_edit", False, lambda: proof_valid(flipped))
    add("proof_truncate", False, lambda: proof_valid(proof[:-1]))
    add("proof_wrong_index", False, lambda: proof_valid(index=0))
    sizes = list(range(66)) + [127, 128, 129, 255, 256, 257, 4096]

    def independent_roots():
        for size in sizes:
            leaves = [digest(str(index).encode()) for index in range(size)]
            if sth.merkle_root(leaves) != cross.merkle_root(leaves):
                return False
        return True

    add("independent_roots", True, independent_roots)
    altered_reference = copy.deepcopy(golden)
    altered_reference[0]["seq"] = 999
    add("changed_reference", False, lambda: compare(altered_reference, golden, 0)["verdict"] == "CONSISTENT")
    rehashed = copy.deepcopy(golden)
    rehashed[1]["results"][0]["metrics"]["ndcg10"] = 0.99
    previous = "0" * 64
    for receipt in rehashed:
        receipt["prev_hash"] = previous
        payload = {key: value for key, value in receipt.items() if key not in ("prev_hash", "chain_hash")}
        receipt["chain_hash"] = digest(previous.encode() + canonical(payload))
        previous = receipt["chain_hash"]
    add("rehashed_candidate", False, lambda: compare(golden, rehashed, 0)["verdict"] == "CONSISTENT")
    return {
        "fixture": {"session_id": SESSION, "timestamp": FIXTURE_TS,
                    "trusted_now": FIXTURE_NOW.isoformat(), "max_age_seconds": TTL,
                    "hard_deny": False, "keys": "ephemeral synthetic in-memory P256",
                    "operators": "one local test process; no operator independence claimed",
                    "merkle_vector_sizes": sizes},
        "controls": controls,
        "eclipse": eclipse.eclipse_run(verify_fn=verify_chain, cross_fn=compare, rel_tol=0),
    }


def execute(args):
    repos = {
        "khipu": (Path(args.khipu_repo), args.expected_khipu_commit, "khipu_consensus"),
        "eclipse": (Path(args.eclipse_repo), args.expected_eclipse_commit, "szl_eclipse"),
        "crosscheck": (Path(args.crosscheck_repo), args.expected_crosscheck_commit, "szl_crosscheck"),
    }
    roots = {
        "khipu_consensus": repos["khipu"][0] / "python" / "khipu_consensus",
        "szl_eclipse": repos["eclipse"][0] / "src" / "szl_eclipse",
        "szl_crosscheck": repos["crosscheck"][0] / "src" / "szl_crosscheck",
    }
    own_path = str(Path(__file__).resolve())
    own_sha = digest(Path(own_path).read_bytes())
    # Reject the wrong or dirty checkout before executing package initializers.
    for name, (path, commit, prefix) in repos.items():
        initializer = roots[prefix] / "__init__.py"
        files = {str(initializer.resolve()): digest(initializer.read_bytes())}
        if name == "eclipse":
            files[own_path] = own_sha
        repository_identity(path, commit, files)
    with PinnedSources(roots) as loaded:
        sth = importlib.import_module("khipu_consensus.sth")
        tree = importlib.import_module("khipu_consensus.receipt_tree")
        witness = importlib.import_module("khipu_consensus.witness")
        eclipse = importlib.import_module("szl_eclipse.eclipse")
        cross = importlib.import_module("szl_crosscheck.covenant")

        def snapshot():
            records = {}
            for name, (path, commit, prefix) in repos.items():
                files = loaded.files_for(prefix)
                if name == "eclipse":
                    files[own_path] = own_sha
                records[name] = repository_identity(path, commit, files)
            return records

        before = snapshot()
        battery = run_battery(sth, tree, witness, eclipse, cross)
        after = snapshot()
        if before != after:
            raise ProvenanceError("executed source provenance changed during the run")
    import cryptography
    report = {
        "schema": SCHEMA, "scope": SCOPE,
        "state": "PASS" if battery_passed(battery) else "FAIL",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "provenance": after, "battery": battery,
        "runtime": {"python": platform.python_version(), "cryptography": cryptography.__version__,
                    "platform": platform.system(),
                    "external_dependencies": "versions recorded; not independently source-pinned"},
        "claim_boundary": dict(CLAIM_BOUNDARY),
    }
    report["report_sha256"] = report_digest(report)
    expected = {name: commit for name, (_, commit, _) in repos.items()}
    if report["state"] == "PASS" and not evidence_usable(
            report, expected_commits=expected, now=datetime.now(timezone.utc)):
        raise ProvenanceError("generated evidence failed its own freshness/identity gate")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("khipu", "eclipse", "crosscheck"):
        parser.add_argument(f"--{name}-repo", required=True)
        parser.add_argument(f"--expected-{name}-commit", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--check-report", help="Check a saved report against the selected current sources")
    parser.add_argument("--max-report-age-seconds", type=int, default=86400)
    args = parser.parse_args(argv)
    # Validate the destination before error-report handling, too.
    output = Path(args.output).resolve()
    for repo in (args.khipu_repo, args.eclipse_repo, args.crosscheck_repo):
        if output.is_relative_to(Path(repo).resolve()):
            print("ERROR: output must be outside selected source worktrees", file=sys.stderr)
            return 2
    try:
        report = execute(args)
        if args.check_report:
            previous = json.loads(Path(args.check_report).read_text(encoding="utf-8"))
            expected = {name: getattr(args, f"expected_{name}_commit")
                        for name in ("khipu", "eclipse", "crosscheck")}
            if not evidence_usable(
                    previous, expected_commits=expected, now=datetime.now(timezone.utc),
                    max_age_seconds=args.max_report_age_seconds,
            ) or previous["provenance"] != report["provenance"]:
                raise ProvenanceError("saved evidence is stale, incomplete or does not match current source")
    except Exception as exc:
        report = {"schema": SCHEMA, "scope": SCOPE, "state": "ERROR",
                  "generated_utc": datetime.now(timezone.utc).isoformat(),
                  "error_type": type(exc).__name__, "reason": str(exc)}
        report["report_sha256"] = report_digest(report)
    # Refuse to overwrite an existing evidence file; every run has a new path.
    try:
        with Path(args.output).open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, indent=2, sort_keys=True, allow_nan=False)
            handle.write("\n")
    except OSError as exc:
        print(f"ERROR: evidence output could not be created: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(json.dumps({"state": report["state"], "output": args.output,
                      "report_sha256": report["report_sha256"]}))
    return 0 if report["state"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
