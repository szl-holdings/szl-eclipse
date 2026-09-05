import hashlib
import json

from szl_eclipse.eclipse import canonical, eclipse_run
from szl_eclipse.planes import file_verifier_adapter, plane_digest, plane_run


def native_reference(paths):
    errors, measured, previous = [], [], "0" * 64
    if not paths:
        errors.append("empty chain")
    for path in paths:
        with open(path, encoding="utf-8") as stream:
            receipt = json.load(stream)
        if receipt["prev_hash"] != previous or receipt["hash"] != plane_digest(receipt):
            errors.append("invalid chain")
        previous = receipt["hash"]
        if receipt["status"] == "MEASURED":
            measured.append(path)
    return errors, measured


def test_native_positive_control_and_sensitivity():
    report = plane_run(native_reference, {"name": "test-reference"})
    assert report["state"] == "VERIFIED-SENSITIVE"
    assert report["sensitivity"] == "10/10"
    assert report["baseline"]["detail"]["measured_count"] == 3


def test_reject_everything_has_no_sensitivity_score():
    report = plane_run(lambda paths: (["wrong schema"], []), {})
    assert report["state"] == "INVALID-BASELINE"
    assert report["sensitivity"] is None
    assert report["mutations"] == []
    report = eclipse_run(verify_fn=lambda chain: (False, "wrong schema"))
    assert report["state"] == "INVALID-BASELINE"


def test_empty_input_blind_spot_is_not_masked_by_adapter():
    def weak(paths):
        return native_reference(paths) if paths else ([], [])
    report = plane_run(weak, {})
    assert report["sensitivity"] == "9/10"
    assert report["blind_spots"] == ["empty"]


def test_adapter_preserves_malformed_native_fields():
    seen = []
    def inspect(paths):
        with open(paths[0], encoding="utf-8") as stream:
            seen.append(json.load(stream))
        return [], []
    file_verifier_adapter(inspect)([{"hash": "bad", "extra": True}])
    assert seen == [{"hash": "bad", "extra": True}]


def test_report_hash_binds_source_and_every_row():
    report = plane_run(native_reference, {"commit": "abc"})
    receipt = report.pop("receipt")
    assert receipt == hashlib.sha256(canonical(report).encode()).hexdigest()
    assert plane_run(native_reference, {"commit": "def"})["receipt"] != receipt


def test_crashing_verifier_is_error_without_score():
    def crash(paths):
        raise RuntimeError("unexpected")
    report = plane_run(crash, {})
    assert report["state"] == "ERROR"
    assert report["sensitivity"] is None
