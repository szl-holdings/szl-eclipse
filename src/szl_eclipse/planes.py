"""Test the native file-based plane contract without translating away mutations.

The positive control must pass before any sensitivity score is produced.
All cases are local fixture controls, not benchmark accuracy measurements.
"""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .eclipse import GENESIS, canonical


def plane_digest(receipt):
    return hashlib.sha256(canonical({k: v for k, v in receipt.items() if k != "hash"}).encode()).hexdigest()


def plane_golden_chain(plane="retrieval"):
    chain, previous = [], GENESIS
    for index in range(3):
        receipt = {"plane": plane, "status": "MEASURED",
                   "machine": {"cpu": "fixture-control", "ram_gb": 1, "gpu": "none"},
                   "measured_at": "2000-01-01T00:00:00Z", "method": "eclipse-native-control-v1",
                   "metrics": {"score": 0.42 + index * 0.001}, "prev_hash": previous}
        receipt["hash"] = plane_digest(receipt)
        previous = receipt["hash"]
        chain.append(receipt)
    return chain


def file_verifier_adapter(verify_paths):
    """Adapt verify(paths)->(errors,measured_paths), preserving exact JSON fields."""
    def verify(chain):
        with TemporaryDirectory(prefix="szl-eclipse-") as directory:
            paths = []
            for index, receipt in enumerate(chain):
                path = Path(directory) / f"{index:03}.json"
                path.write_text(canonical(receipt), encoding="utf-8")
                paths.append(str(path))
            errors, measured = verify_paths(paths)
            if not isinstance(errors, list) or not isinstance(measured, list):
                raise ValueError("native verifier returned the wrong contract")
            expected_paths = [Path(path).resolve() for path in paths]
            try:
                actual_paths = [Path(path).resolve() for path in measured]
                measured_paths_match = (len(actual_paths) == len(expected_paths)
                                        and len(set(actual_paths)) == len(actual_paths)
                                        and set(actual_paths) == set(expected_paths))
            except (TypeError, ValueError, OSError):
                measured_paths_match = False
            def logical_error(error):
                message = str(error)
                for root in (str(Path(directory)), Path(directory).as_posix()):
                    message = message.replace(root, "<native-inputs>")
                return message
            return not errors, {"errors": [logical_error(error) for error in errors],
                                "measured_count": len(measured),
                                "measured_paths_match": measured_paths_match}
    return verify


def _change_metric(chain):
    chain[1]["metrics"]["score"] = 0.99
    return chain


def _reorder(chain):
    chain[0], chain[2] = chain[2], chain[0]
    return chain


def _link(chain):
    chain[2]["prev_hash"] = "ab" * 32
    return chain


def _truncate(chain):
    chain[-1]["hash"] = chain[-1]["hash"][:32]
    return chain


def _plane(chain):
    chain[1]["plane"] = "engine" if chain[1]["plane"] != "engine" else "retrieval"
    return chain


def _key(chain):
    chain[1]["metrics"]["other"] = chain[1]["metrics"].pop("score")
    return chain


def _drift(chain):
    chain[1]["metrics"]["score"] += 0.0000001
    return chain


def _type(chain):
    chain[1]["metrics"]["score"] = "0.43"
    return chain


def _duplicate(chain):
    chain.insert(2, copy.deepcopy(chain[1]))
    return chain


CASES = [("metric_tamper", _change_metric), ("reorder", _reorder),
         ("prevhash_swap", _link), ("terminal_truncate", _truncate),
         ("plane_rename", _plane), ("key_rename", _key),
         ("precision_drift_without_rehash", _drift), ("type_confusion", _type),
         ("empty", lambda chain: []), ("duplicate_receipt", _duplicate)]


def plane_run(verify_paths, source, plane="retrieval"):
    verifier = file_verifier_adapter(verify_paths)
    golden = plane_golden_chain(plane)
    report = {"schema": "szl.eclipse.native-plane.v1", "source": source,
              "scope": "LOCAL_FIXTURE_VERIFIER_CONTROLS", "plane": plane,
              "golden_chain": golden, "mutations": [], "blind_spots": []}
    try:
        valid, detail = verifier(golden)
        report["baseline"] = {"valid": valid, "detail": detail}
        if not valid or detail["measured_count"] != len(golden) or not detail["measured_paths_match"]:
            report.update(state="INVALID-BASELINE", sensitivity=None)
        else:
            for name, mutate in CASES:
                chain = mutate(copy.deepcopy(golden))
                accepted, detail = verifier(chain)
                report["mutations"].append({"mutation": name, "accepted": accepted,
                                             "caught": not accepted, "detail": detail,
                                             "input_hash": hashlib.sha256(canonical(chain).encode()).hexdigest()})
                if accepted:
                    report["blind_spots"].append(name)
            report.update(state="BLIND-SPOT" if report["blind_spots"] else "VERIFIED-SENSITIVE",
                          sensitivity=f"{len(CASES) - len(report['blind_spots'])}/{len(CASES)}")
    except Exception as error:
        report.update(state="ERROR", sensitivity=None, error=f"{type(error).__name__}: {error}")
    report["receipt"] = hashlib.sha256(canonical(report).encode()).hexdigest()
    return report


def load_plane_verifier(path):
    path = Path(path).resolve(strict=True)
    spec = importlib.util.spec_from_file_location("eclipse_local_plane", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.verify, hashlib.sha256(path.read_bytes()).hexdigest()
