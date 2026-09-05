import hashlib
import json
from pathlib import Path

from szl_eclipse.eclipse import canonical


def test_recorded_native_plane_receipts_recompute():
    directory = Path(__file__).resolve().parents[1] / "evidence/2026-09-05"
    paths = sorted(directory.glob("eclipse-native-*-20260905.json"))
    assert len(paths) == 3
    for path in paths:
        report = json.loads(path.read_text(encoding="utf-8"))
        receipt = report.pop("receipt")
        assert hashlib.sha256(canonical(report).encode()).hexdigest() == receipt
        assert report["baseline"]["valid"] is True
        assert report["baseline"]["detail"]["measured_count"] == 3
        assert report["sensitivity"] == "9/10"
        assert report["blind_spots"] == ["empty"]
        assert report["scope"] == "LOCAL_FIXTURE_VERIFIER_CONTROLS"
