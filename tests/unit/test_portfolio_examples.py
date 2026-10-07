from pathlib import Path

from scripts.validate_file import load_and_normalize

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_tracked_sample_matches_data_contract() -> None:
    findings = load_and_normalize(REPO_ROOT / "data" / "samples" / "results.sample.json")

    assert len(findings) == 2
    assert {finding.tenant for finding in findings} == {"Example Tenant"}
