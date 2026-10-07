import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "ci.yml"
ACTION_REFERENCE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
IMMUTABLE_ACTION_REFERENCE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


@pytest.fixture
def workflow() -> str:
    return WORKFLOW_PATH.read_text(encoding="utf-8")


def test_ci_actions_are_pinned_to_commit_shas(workflow: str) -> None:
    references = ACTION_REFERENCE.findall(workflow)

    assert references
    assert all(IMMUTABLE_ACTION_REFERENCE.fullmatch(reference) for reference in references)


def test_ci_uses_least_privilege_checkout(workflow: str) -> None:
    assert re.search(r"(?m)^permissions:\n\s+contents:\s+read\s*$", workflow)
    assert re.search(
        r"(?ms)^\s+- name: Checkout\n"
        r"\s+uses: actions/checkout@[0-9a-f]{40}[^\n]*\n"
        r"\s+with:\n"
        r"\s+persist-credentials:\s+false\s*$",
        workflow,
    )


def test_ci_has_bounded_execution_and_artifact_retention(workflow: str) -> None:
    assert re.search(r"(?m)^\s+timeout-minutes:\s+\d+\s*$", workflow)
    assert re.search(r"(?m)^\s+retention-days:\s+\d+\s*$", workflow)
    assert re.search(r"(?m)^\s+if-no-files-found:\s+error\s*$", workflow)
