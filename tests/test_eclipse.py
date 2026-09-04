"""Every assertion executed green before this file was pushed."""
from szl_eclipse.eclipse import eclipse_run, golden_chain


def test_reference_verifier_is_fully_sensitive():
    rep = eclipse_run()
    assert rep["state"] == "VERIFIED-SENSITIVE"
    assert rep["sensitivity"] == "10/10"
    assert rep["blind_spots"] == []


def test_weak_verifier_is_exposed():
    rep = eclipse_run(verify_fn=lambda chain: (True, "always fine"),
                      cross_fn=lambda a, b, rel_tol=0.01: {"verdict": "CONSISTENT"})
    assert rep["state"] == "BLIND-SPOT"
    assert len(rep["blind_spots"]) >= 9


def test_report_receipt_deterministic():
    assert eclipse_run()["receipt"] == eclipse_run()["receipt"]


def test_every_mutation_row_is_labeled():
    rep = eclipse_run()
    for row in rep["mutations"]:
        assert row["expectation"] in ("CATCH", "ALLOW-ONLY-WITHIN-TOLERANCE")
        assert "chain_valid" in row and "crosscheck" in row


def test_golden_chain_is_valid_and_deterministic():
    a, b = golden_chain(), golden_chain()
    assert a == b
    assert len(a) == 3 and a[-1]["chain_hash"] != a[0]["chain_hash"]
