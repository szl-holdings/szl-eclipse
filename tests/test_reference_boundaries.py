"""The reference verifier returns a decision at malformed input boundaries."""
import copy
import hashlib

import pytest

from szl_eclipse.eclipse import canonical, crosscheck, eclipse_run, golden_chain, verify_chain


def rehash(chain):
    previous = "0" * 64
    for receipt in chain:
        payload = {key: value for key, value in receipt.items()
                   if key not in ("prev_hash", "chain_hash")}
        receipt["prev_hash"] = previous
        previous = hashlib.sha256((previous + canonical(payload)).encode()).hexdigest()
        receipt["chain_hash"] = previous
    return chain


@pytest.mark.parametrize("chain", [None, False, 1, "chain", {}, [None], [False],
                                 [1], ["receipt"], [[]]])
def test_malformed_chain_shape_returns_invalid(chain):
    accepted, reason = verify_chain(chain)
    assert accepted is False
    assert isinstance(reason, str) and reason
    assert crosscheck(chain, golden_chain())["verdict"] == "INVALID"
    assert crosscheck(golden_chain(), chain)["verdict"] == "INVALID"


@pytest.mark.parametrize("payload", [float("nan"), float("inf"), {"not-json"}])
def test_noncanonical_payload_returns_invalid(payload):
    chain = golden_chain()
    chain[0]["extra"] = payload
    assert verify_chain(chain)[0] is False
    assert crosscheck(chain, golden_chain())["verdict"] == "INVALID"


@pytest.mark.parametrize("metrics", [{}, {"unrelated": 0.42}, {"ndcg10": "0.42"}])
def test_no_common_numeric_metric_is_incomparable(metrics):
    left = golden_chain()
    right = copy.deepcopy(left)
    for receipt in right:
        receipt["results"][0]["metrics"] = metrics
    rehash(right)
    assert verify_chain(left)[0] is True
    assert verify_chain(right)[0] is True
    assert crosscheck(left, right)["verdict"] == "INCOMPARABLE"
    assert crosscheck(right, left)["verdict"] == "INCOMPARABLE"


def test_existing_common_metric_comparison_is_preserved():
    left = golden_chain()
    right = copy.deepcopy(left)
    # Existing comparison is over shared numeric metrics; an extra metric alone
    # does not establish divergence or force an exact-schema comparison policy.
    for receipt in right:
        receipt["results"][0]["metrics"] = {"mrr": 0.38, "extra": 7}
    rehash(right)
    assert crosscheck(left, right)["verdict"] == "CONSISTENT"
    right[-1]["results"][0]["metrics"]["mrr"] = 0.9
    rehash(right)
    assert crosscheck(left, right)["verdict"] == "DIVERGENT"


@pytest.mark.parametrize("tolerance", [None, True, False, "0.01", -0.1,
                                     float("nan"), float("inf"), -float("inf"),
                                     10 ** 1000])
def test_invalid_caller_tolerance_is_an_error(tolerance):
    with pytest.raises(ValueError, match="tolerance"):
        crosscheck(golden_chain(), golden_chain(), tolerance)


@pytest.mark.parametrize("results", [1, True, "results", {}, [None], [1], [[]],
                                   [{"runs": True, "metrics": {"mrr": .38}}],
                                   [{"runs": [1], "metrics": 1}]])
def test_malformed_results_are_invalid(results):
    malformed = golden_chain()
    malformed[0]["results"] = results
    rehash(malformed)
    assert verify_chain(malformed)[0] is True  # Structurally valid hash chain.
    assert crosscheck(malformed, golden_chain())["verdict"] == "INVALID"
    assert crosscheck(golden_chain(), malformed)["verdict"] == "INVALID"


def metric_chain(value):
    chain = golden_chain()
    for receipt in chain:
        receipt["results"][0]["metrics"] = {"value": value}
    return rehash(chain)


def test_unrepresentable_numeric_metric_is_invalid():
    oversized = metric_chain(10 ** 1000)
    finite = metric_chain(1)
    assert verify_chain(oversized)[0] is True
    assert crosscheck(oversized, finite)["verdict"] == "INVALID"
    assert crosscheck(finite, oversized)["verdict"] == "INVALID"


@pytest.mark.parametrize("value", [True, False])
def test_boolean_is_not_a_numeric_measurement(value):
    assert crosscheck(metric_chain(value), metric_chain(int(value)))["verdict"] == "INCOMPARABLE"


def test_extreme_finite_metric_difference_stays_finite():
    positive, negative = metric_chain(1e308), metric_chain(-1e308)
    assert crosscheck(positive, negative, 1.99)["verdict"] == "DIVERGENT"
    assert crosscheck(positive, negative, 2.0)["verdict"] == "CONSISTENT"
    assert crosscheck(positive, positive, 0)["verdict"] == "CONSISTENT"


def test_tuple_chains_remain_supported():
    assert verify_chain(tuple(golden_chain()))[0] is True
    assert crosscheck(tuple(golden_chain()), golden_chain())["verdict"] == "CONSISTENT"


@pytest.mark.parametrize("tolerance", [-1, float("nan"), float("inf")])
def test_harness_checks_tolerance_before_calling_custom_verifiers(tolerance):
    def should_not_run(*args):
        pytest.fail("invalid caller tolerance reached a supplied verifier")
    with pytest.raises(ValueError, match="tolerance"):
        eclipse_run(verify_fn=should_not_run, cross_fn=should_not_run, rel_tol=tolerance)


@pytest.mark.parametrize("results", [None, [], [{}], [{"runs": []}], [{"runs": [1]}]])
def test_missing_measurements_are_incomparable(results):
    chain = golden_chain()
    for receipt in chain:
        receipt["results"] = results
    rehash(chain)
    assert crosscheck(chain, golden_chain())["verdict"] == "INCOMPARABLE"
