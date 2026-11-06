"""Unit tests for the M46 fail-closed merged-application gate."""
import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "m46_merged_app_acceptance.py"
SPEC = importlib.util.spec_from_file_location("m46_merged_app_acceptance", SCRIPT)
M46 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M46)


def test_open_pr_head_or_test_merge_sha_never_counts_as_merged(monkeypatch):
    def fake_gh(*args):
        # The branch head is not in main. The API may expose a synthetic
        # merge candidate for an open PR, but verify_pr_on_main must not check
        # or accept that candidate as the PR's merged integration SHA.
        return {"status": "behind", "ahead_by": 0, "behind_by": 10}

    monkeypatch.setattr(M46, "gh", fake_gh)
    pr = {"merged": False, "base_ref": "main", "merged_at": None,
          "head_sha": "pr-head", "merge_commit_sha": "test-merge-candidate"}
    status = M46.verify_pr_on_main(pr, "main-sha")
    assert status["verified"] is False
    assert status["head_on_main"] is False
    assert status["merge_check"]["status"] == "pr_not_merged"


def test_merged_pr_requires_exact_merge_result_reachable_from_main(monkeypatch):
    def fake_gh(*args):
        endpoint = args[0]
        if "pr-head...main-sha" in endpoint:
            return {"status": "behind", "ahead_by": 0, "behind_by": 8}
        if "merge-result...main-sha" in endpoint:
            # Squash merge: original PR head need not be an ancestor, while
            # GitHub's exact merge-result commit must be reachable from main.
            return {"status": "ahead", "ahead_by": 1, "behind_by": 0}
        raise AssertionError(endpoint)

    monkeypatch.setattr(M46, "gh", fake_gh)
    pr = {"merged": True, "base_ref": "main", "merged_at": "2026-11-06T10:00:00Z",
          "head_sha": "pr-head", "merge_commit_sha": "merge-result"}
    status = M46.verify_pr_on_main(pr, "main-sha")
    assert status["verified"] is True
    assert status["head_on_main"] is False
    assert status["merge_check"]["on_main"] is True


def test_merged_pr_fails_closed_when_merge_result_is_not_reachable(monkeypatch):
    def fake_gh(*args):
        return {"status": "diverged", "ahead_by": 4, "behind_by": 3}

    monkeypatch.setattr(M46, "gh", fake_gh)
    pr = {"merged": True, "base_ref": "main", "merged_at": "2026-11-06T10:00:00Z",
          "head_sha": "pr-head", "merge_commit_sha": "merge-result"}
    status = M46.verify_pr_on_main(pr, "main-sha")
    assert status["verified"] is False
    assert status["merge_check"]["on_main"] is False


def test_only_main_base_is_eligible(monkeypatch):
    monkeypatch.setattr(M46, "gh", lambda *args: {
        "status": "ahead", "ahead_by": 1, "behind_by": 0,
    })
    pr = {"merged": True, "base_ref": "release", "merged_at": "2026-11-06T10:00:00Z",
          "head_sha": "pr-head", "merge_commit_sha": "merge-result"}
    assert M46.verify_pr_on_main(pr, "main-sha")["verified"] is False
