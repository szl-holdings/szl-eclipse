# SPDX-License-Identifier: Apache-2.0
"""Regression controls for source identity, freshness and honest test outcomes."""
import copy
import importlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import types
from datetime import timedelta

import pytest

TOOL = Path(__file__).resolve().parents[1] / "tools" / "covenant_v2_evidence.py"
spec = importlib.util.spec_from_file_location("covenant_v2_evidence_under_test", TOOL)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


def run_git(repo, *args):
    result = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, check=True,
    )
    return result.stdout.decode().strip()


@pytest.fixture
def committed_source(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init")
    run_git(repo, "config", "core.autocrlf", "false")
    source = repo / "fixture.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    run_git(repo, "add", "fixture.py")
    run_git(repo, "-c", "user.name=Synthetic Fixture", "-c",
            "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false",
            "commit", "-m", "synthetic fixture")
    commit = run_git(repo, "rev-parse", "HEAD")
    return repo, source, commit


def test_clean_commit_binds_actual_source_bytes(committed_source):
    repo, source, commit = committed_source
    sha = evidence.digest(source.read_bytes())
    result = evidence.repository_identity(repo, commit, {str(source): sha})
    assert result["commit"] == commit
    assert result["worktree_clean"] is True
    assert result["sources"]["fixture.py"]["sha256"] == sha
    assert result["sources"]["fixture.py"]["source_path"] == "fixture.py"
    assert str(repo) not in json.dumps(result)


@pytest.mark.parametrize("expected", ["unavailable", "", "a" * 7, "b" * 40, "A" * 40])
def test_missing_or_stale_commit_fails_closed(committed_source, expected):
    repo, source, _ = committed_source
    with pytest.raises(evidence.ProvenanceError):
        evidence.repository_identity(repo, expected, {str(source): evidence.digest(source.read_bytes())})


@pytest.mark.parametrize("mode", ["tracked", "untracked"])
def test_dirty_source_is_never_passing_provenance(committed_source, mode):
    repo, source, commit = committed_source
    if mode == "tracked":
        source.write_text("VALUE = 2\n", encoding="utf-8")
    else:
        (repo / "unexpected.py").write_text("VALUE = 2\n", encoding="utf-8")
    with pytest.raises(evidence.ProvenanceError, match="not clean"):
        evidence.repository_identity(repo, commit, {str(source): evidence.digest(source.read_bytes())})


def test_missing_git_is_an_error(monkeypatch, tmp_path):
    def unavailable(*args, **kwargs):
        raise FileNotFoundError("synthetic missing git")
    monkeypatch.setattr(evidence.subprocess, "run", unavailable)
    with pytest.raises(evidence.ProvenanceError, match="unavailable"):
        evidence.git(tmp_path, "rev-parse", "HEAD")


def test_unsuccessful_git_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(evidence.subprocess, "run", lambda *a, **kw: types.SimpleNamespace(
        returncode=128, stdout=b"", stderr=b"synthetic failure"))
    with pytest.raises(evidence.ProvenanceError, match="could not verify"):
        evidence.git(tmp_path, "rev-parse", "HEAD")


def test_loaded_source_outside_repository_is_rejected(committed_source, tmp_path):
    repo, _, commit = committed_source
    outside = tmp_path / "outside.py"
    outside.write_text("VALUE = 1\n", encoding="utf-8")
    with pytest.raises(evidence.ProvenanceError, match="outside"):
        evidence.repository_identity(repo, commit, {str(outside): evidence.digest(outside.read_bytes())})


def test_changed_compiled_hash_is_rejected(committed_source):
    repo, source, commit = committed_source
    with pytest.raises(evidence.ProvenanceError, match="after compilation"):
        evidence.repository_identity(repo, commit, {str(source): "a" * 64})


def test_blob_comparison_detects_change_even_if_status_claims_clean(committed_source, monkeypatch):
    repo, source, commit = committed_source
    source.write_text("VALUE = 2\n", encoding="utf-8")
    real_git = evidence.git
    monkeypatch.setattr(evidence, "git", lambda repo, *args:
                        b"" if args[0] == "status" else real_git(repo, *args))
    with pytest.raises(evidence.ProvenanceError, match="committed blob"):
        evidence.repository_identity(repo, commit, {str(source): evidence.digest(source.read_bytes())})


def test_source_loader_ignores_stale_bytecode(tmp_path):
    source = tmp_path / "fixture.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    stat = source.stat()
    py_compile.compile(str(source), doraise=True)
    source.write_text("VALUE = 2\n", encoding="utf-8")
    os.utime(source, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    recorded = {}
    loader = evidence._SourceLoader("fixture", str(source), recorded)
    namespace = {}
    exec(loader.get_code("fixture"), namespace)
    assert namespace["VALUE"] == 2
    assert recorded["fixture"]["sha256"] == evidence.digest(source.read_bytes())


def test_preloaded_foreign_package_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "fixture"
    root.mkdir()
    monkeypatch.setitem(sys.modules, "covenant_fixture", types.ModuleType("covenant_fixture"))
    with pytest.raises(evidence.ProvenanceError, match="before source pinning"):
        with evidence.PinnedSources({"covenant_fixture": root}):
            pass


def test_pinned_loader_checks_actual_module_origin(tmp_path):
    package = tmp_path / "fixture"
    package.mkdir()
    (package / "__init__.py").write_text("VALUE = 3\n", encoding="utf-8")
    try:
        with evidence.PinnedSources({"covenant_fixture": package}) as loaded:
            module = importlib.import_module("covenant_fixture")
            assert module.VALUE == 3
            assert str((package / "__init__.py").resolve()) in loaded.files_for("covenant_fixture")
            module.__file__ = str(tmp_path / "foreign.py")
            with pytest.raises(evidence.ProvenanceError, match="origin changed"):
                loaded.files_for("covenant_fixture")
    finally:
        sys.modules.pop("covenant_fixture", None)


def passing_battery():
    return {
        "controls": [
            {"name": name, "expected": expected, "observed": expected, "state": "PASS"}
            for name, expected in evidence.CONTROL_EXPECTATIONS.items()
        ],
        "eclipse": {
            "state": "VERIFIED-SENSITIVE", "sensitivity": "10/10",
            "baseline": {"chain_valid": True, "crosscheck": {"verdict": "CONSISTENT"}},
            "mutations": [{"mutation": name, "caught": True}
                          for name in sorted(evidence.MUTATION_NAMES)], "blind_spots": [],
        },
    }


def saved_report():
    commits = {name: digit * 40 for name, digit in zip(
        ("khipu", "eclipse", "crosscheck"), ("1", "2", "3"))}
    report = {
        "schema": evidence.SCHEMA, "scope": evidence.SCOPE, "state": "PASS",
        "generated_utc": evidence.FIXTURE_NOW.isoformat(),
        "battery": passing_battery(),
        "provenance": {
            name: {"commit": commit, "worktree_clean": True, "worktree_root_verified": True,
                   "sources": {"fixture.py": {"sha256": "a" * 64, "git_blob_sha256": "b" * 64,
                                               "source_path": "fixture.py", "compiled_origin_verified": True}}}
            for name, commit in commits.items()
        },
    }
    report["report_sha256"] = evidence.report_digest(report)
    return report, commits


def usable(report, commits, **kwargs):
    return evidence.evidence_usable(
        report, expected_commits=commits, now=kwargs.pop("now", evidence.FIXTURE_NOW), **kwargs,
    )


def test_fresh_complete_evidence_positive_control():
    report, commits = saved_report()
    assert usable(report, commits)


@pytest.mark.parametrize("seconds", [-1, 86400, 86401])
def test_future_and_expired_report_rejected(seconds):
    report, commits = saved_report()
    assert not usable(report, commits, now=evidence.FIXTURE_NOW + timedelta(seconds=seconds))


@pytest.mark.parametrize("age", [None, True, 0, -1, 86401])
def test_report_age_policy_must_be_explicit_bounded_integer(age):
    report, commits = saved_report()
    assert not usable(report, commits, max_age_seconds=age)


def test_report_requires_aware_time():
    report, commits = saved_report()
    assert not usable(report, commits, now=evidence.FIXTURE_NOW.replace(tzinfo=None))


@pytest.mark.parametrize("mutation", [
    "stale_commit", "missing_source", "dirty", "wrong_hash", "bad_hash",
    "no_origin", "failed_baseline", "missing_control", "blind_spot", "error",
    "boolean_alias", "all_deny", "missing_repository", "changed_expectation",
])
def test_report_rejection_controls(mutation):
    report, commits = saved_report()
    if mutation == "stale_commit":
        commits["khipu"] = "4" * 40
    elif mutation == "missing_source":
        report["provenance"]["khipu"]["sources"] = {}
    elif mutation == "dirty":
        report["provenance"]["eclipse"]["worktree_clean"] = False
    elif mutation == "wrong_hash":
        report["provenance"]["khipu"]["sources"]["fixture.py"]["sha256"] = "c" * 64
        assert not usable(report, commits)
        return
    elif mutation == "bad_hash":
        report["provenance"]["khipu"]["sources"]["fixture.py"]["sha256"] = "unavailable"
    elif mutation == "no_origin":
        report["provenance"]["crosscheck"]["sources"]["fixture.py"]["compiled_origin_verified"] = False
    elif mutation == "failed_baseline":
        report["battery"]["eclipse"]["baseline"]["chain_valid"] = False
    elif mutation == "missing_control":
        report["battery"]["controls"].pop()
    elif mutation == "blind_spot":
        report["battery"]["eclipse"]["mutations"][0]["caught"] = False
    elif mutation == "error":
        report["battery"]["controls"][0]["state"] = "ERROR"
    elif mutation == "boolean_alias":
        report["battery"]["controls"][0]["observed"] = 1
    elif mutation == "all_deny":
        for row in report["battery"]["controls"]:
            row["observed"] = False
    elif mutation == "missing_repository":
        del report["provenance"]["crosscheck"]
    elif mutation == "changed_expectation":
        report["battery"]["controls"][0].update(expected=False, observed=False)
    report["report_sha256"] = evidence.report_digest(report)
    assert not usable(report, commits)


def test_exception_is_error_not_successful_detection():
    rows = []
    evidence.record_control(rows, "synthetic", False, lambda: 1 / 0)
    assert rows[0]["state"] == "ERROR"
    assert rows[0]["observed"] is None


def test_invalid_baseline_does_not_qualify_despite_perfect_mutations():
    battery = passing_battery()
    battery["eclipse"]["baseline"]["crosscheck"]["verdict"] = "INVALID"
    assert not evidence.battery_passed(battery)


def cli_args(tmp_path, output):
    args = []
    for name in ("khipu", "eclipse", "crosscheck"):
        repo = tmp_path / name
        repo.mkdir(exist_ok=True)
        args.extend([f"--{name}-repo", str(repo), f"--expected-{name}-commit", "a" * 40])
    return args + ["--output", str(output)]


def test_cli_provenance_error_cannot_exit_success(tmp_path, monkeypatch):
    def fail(_):
        raise evidence.ProvenanceError("synthetic missing git")
    monkeypatch.setattr(evidence, "execute", fail)
    output = tmp_path / "report.json"
    assert evidence.main(cli_args(tmp_path, output)) == 2
    assert json.loads(output.read_text())["state"] == "ERROR"


def test_cli_refuses_output_inside_source_even_for_error_report(tmp_path, monkeypatch):
    output = tmp_path / "eclipse" / "report.json"
    assert evidence.main(cli_args(tmp_path, output)) == 2
    assert not output.exists()


def test_cli_does_not_overwrite_existing_evidence(tmp_path, monkeypatch):
    report, _ = saved_report()
    monkeypatch.setattr(evidence, "execute", lambda _: report)
    output = tmp_path / "report.json"
    output.write_text("original", encoding="utf-8")
    assert evidence.main(cli_args(tmp_path, output)) == 2
    assert output.read_text() == "original"


@pytest.mark.parametrize("name", sorted(evidence.CONTROL_EXPECTATIONS))
def test_every_control_is_required_unique_and_has_a_fixed_expectation(name):
    for mutation in ("missing", "duplicate", "changed_expectation"):
        report, commits = saved_report()
        rows = report["battery"]["controls"]
        target = next(row for row in rows if row["name"] == name)
        if mutation == "missing":
            rows.remove(target)
        elif mutation == "duplicate":
            rows.append(copy.deepcopy(target))
        else:
            target["expected"] = not target["expected"]
            target["observed"] = target["expected"]
        report["report_sha256"] = evidence.report_digest(report)
        assert not usable(report, commits), (name, mutation)


@pytest.mark.parametrize("name", sorted(evidence.MUTATION_NAMES))
def test_every_eclipse_mutation_is_required_and_unique(name):
    for mutation in ("missing", "duplicate", "renamed"):
        report, commits = saved_report()
        rows = report["battery"]["eclipse"]["mutations"]
        target = next(row for row in rows if row["mutation"] == name)
        if mutation == "missing":
            rows.remove(target)
        elif mutation == "duplicate":
            rows.append(copy.deepcopy(target))
        else:
            target["mutation"] = "unknown"
        report["report_sha256"] = evidence.report_digest(report)
        assert not usable(report, commits), (name, mutation)


@pytest.mark.parametrize("wrong_commit", [False, True])
def test_wrong_or_dirty_checkout_rejected_before_package_code_runs(committed_source, wrong_commit):
    repo, _, commit = committed_source
    package = repo / "python" / "khipu_consensus"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        'raise AssertionError("unverified package initializer executed")\n', encoding="utf-8",
    )
    args = types.SimpleNamespace(**{
        field: value for name in ("khipu", "eclipse", "crosscheck")
        for field, value in (
            (f"{name}_repo", str(repo)),
            (f"expected_{name}_commit", "a" * 40 if wrong_commit else commit),
        )
    })
    with pytest.raises(evidence.ProvenanceError, match="expected commit|not clean"):
        evidence.execute(args)
