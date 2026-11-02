"""A failed or malformed callback is not a successful tamper detection."""
import hashlib

import pytest

from szl_eclipse.eclipse import canonical, eclipse_run


def consistent(*args):
    return {"verdict": "CONSISTENT"}


@pytest.mark.parametrize("bad_result", [(None, "parser failed"), (0, "error"),
                                        ("false", "error"), (), None, True])
@pytest.mark.parametrize("fail_baseline", [True, False])
def test_malformed_verifier_never_earns_a_score(bad_result, fail_baseline):
    calls = 0

    def verifier(chain):
        nonlocal calls
        calls += 1
        return bad_result if fail_baseline or calls > 1 else (True, "baseline")

    report = eclipse_run(verify_fn=verifier, cross_fn=consistent)
    assert report["state"] == "ERROR"
    assert report["sensitivity"] is None
    assert report["phase"] == "verify"


@pytest.mark.parametrize("bad_result", [None, [], {}, {"verdict": "ERROR"},
                                        {"verdict": True},
                                        {"verdict": "CONSISTENT", "value": float("nan")}])
@pytest.mark.parametrize("fail_baseline", [True, False])
def test_malformed_comparator_never_earns_a_score(bad_result, fail_baseline):
    calls = 0

    def comparator(*args):
        nonlocal calls
        calls += 1
        return bad_result if fail_baseline or calls > 1 else consistent()

    report = eclipse_run(cross_fn=comparator)
    assert report["state"] == "ERROR"
    assert report["sensitivity"] is None
    assert report["phase"] == "crosscheck"


@pytest.mark.parametrize("callback", ["verify_fn", "cross_fn"])
@pytest.mark.parametrize("fail_baseline", [True, False])
def test_crashing_callback_has_receipted_error_without_score(callback, fail_baseline):
    calls = 0

    def crash(*args):
        nonlocal calls
        calls += 1
        if fail_baseline or calls > 1:
            raise RuntimeError("private provider context")
        return (True, "baseline") if callback == "verify_fn" else consistent()

    report = eclipse_run(**{callback: crash})
    assert report["state"] == "ERROR"
    assert report["sensitivity"] is None
    assert report["error_type"] == "RuntimeError"
    assert "private provider context" not in canonical(report)
    receipt = report.pop("receipt")
    assert receipt == hashlib.sha256(canonical(report).encode()).hexdigest()


def test_valid_callback_results_still_measure_blind_spots_and_rejections():
    report = eclipse_run(verify_fn=lambda chain: (True, "accepted"), cross_fn=consistent)
    assert report["state"] == "BLIND-SPOT"
    assert report["sensitivity"] == "0/10"
    assert eclipse_run()["sensitivity"] == "10/10"


def test_process_interrupt_is_not_converted_to_an_error_report():
    def interrupted(chain):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        eclipse_run(verify_fn=interrupted)
