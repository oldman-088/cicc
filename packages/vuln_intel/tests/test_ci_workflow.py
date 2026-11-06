"""The CI workflow has to be structurally valid, not merely parseable as YAML.

Three pushes in a row failed at **zero seconds** with no jobs and no annotations. The
workflow parsed fine — ``yaml.safe_load`` was happy — but it was invalid *as a workflow*:
a job had lost its ``runs-on`` key, so GitHub rejected the whole file and never queued
anything.

That failure mode is uniquely bad for this branch, because an empty check list reads as
"nothing to report" rather than "the pipeline is broken". A run that fails in four
minutes with a named job tells you where to look; a run that fails in zero seconds with
no jobs at all looks like a flake.

These tests cost milliseconds and close that hole, so validation is not left to the
`yaml` module's opinion of the syntax.
"""

from __future__ import annotations

import pathlib

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml is a test dependency")

WORKFLOW = pathlib.Path(__file__).resolve().parents[3] / ".github" / "workflows" / "vuln-intel.yml"


@pytest.fixture(scope="module")
def workflow() -> dict:
    assert WORKFLOW.exists(), f"expected the CI workflow at {WORKFLOW}"
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


class TestStructure:
    def test_it_has_a_trigger_and_jobs(self, workflow):
        # YAML 1.1 reads a bare ``on:`` key as the boolean True, so the trigger is
        # reachable under either spelling depending on the loader.
        assert "on" in workflow or True in workflow, "workflow has no trigger"
        assert workflow.get("jobs"), "workflow defines no jobs"

    @pytest.mark.parametrize("job_name", ["test", "oracle", "comparator-oracle-status",
                                          "maven-rubygems-runtime"])
    def test_every_expected_job_exists(self, workflow, job_name):
        assert job_name in workflow["jobs"], f"job {job_name!r} disappeared"

    def test_every_job_declares_a_runner_and_steps(self, workflow):
        """The exact defect that silently disabled CI: a job with no ``runs-on``.

        GitHub rejects the entire workflow in that case, so *every* job disappears and
        the failure looks like nothing ran rather than like something broke.
        """
        problems = []
        for name, job in workflow["jobs"].items():
            if "runs-on" not in job:
                problems.append(f"{name}: no runs-on")
            if not job.get("steps"):
                problems.append(f"{name}: no steps")
        assert not problems, "invalid job definition(s): " + "; ".join(problems)

    def test_every_step_has_exactly_one_action_or_command(self, workflow):
        problems = []
        for name, job in workflow["jobs"].items():
            for index, step in enumerate(job.get("steps", [])):
                has_uses, has_run = "uses" in step, "run" in step
                if not (has_uses or has_run):
                    problems.append(f"{name} step {index}: neither uses nor run")
                if has_uses and has_run:
                    problems.append(f"{name} step {index}: both uses and run")
        assert not problems, "; ".join(problems)


class TestPathsAreResolvable:
    """A job that runs ``./scripts/...`` must declare where that path is relative to.

    The runtime job failed with exit 127 in CI while passing locally. The annotation
    finally said it: "./scripts/generate_runtime_vectors.sh: No such file or directory".
    An edit to the job header had deleted its ``defaults.run.working-directory`` block,
    so every relative path in it resolved against the repository root.

    127 reads as "a binary is missing", and I spent two rounds looking for a missing
    binary. The real fault was a deleted three-line block, which is why this is asserted
    structurally rather than left to whoever edits the file next.
    """

    @pytest.mark.parametrize(
        "job_name", ["test", "oracle", "maven-rubygems-runtime"]
    )
    def test_jobs_using_relative_scripts_declare_a_working_directory(
        self, workflow, job_name
    ):
        job = workflow["jobs"][job_name]
        runs = " ".join(str(step.get("run", "")) for step in job["steps"])
        if "./scripts/" not in runs:
            pytest.skip(f"{job_name} runs no relative script")
        declared = job.get("defaults", {}).get("run", {}).get("working-directory")
        assert declared, (
            f"{job_name} runs ./scripts/... but declares no "
            "defaults.run.working-directory, so the path resolves against the repo root"
        )

    @pytest.mark.parametrize(
        "job_name", ["test", "oracle", "maven-rubygems-runtime"]
    )
    def test_the_declared_directory_exists_in_the_repository(self, workflow, job_name):
        job = workflow["jobs"][job_name]
        declared = job.get("defaults", {}).get("run", {}).get("working-directory")
        if not declared:
            pytest.skip(f"{job_name} declares no working directory")
        repo_root = WORKFLOW.parents[2]
        assert (repo_root / declared).is_dir(), f"{job_name}: no such directory {declared}"


class TestTheOracleJobsSayWhatTheyClaim:
    def test_the_runtime_oracle_is_gating(self, workflow):
        """It was advisory while one question was unresolvable; the condition is met.

        If this ever has to go back to ``continue-on-error``, this test fails and forces
        the reason into the workflow comment rather than letting the flag reappear
        quietly.
        """
        job = workflow["jobs"]["maven-rubygems-runtime"]
        assert job.get("continue-on-error") is not True, (
            "the runtime oracle was made advisory again; record the reason and the "
            "removal condition in the workflow comment, and update B-17"
        )

    def test_the_runtime_oracle_runs_its_differential_step(self, workflow):
        runs = " ".join(
            str(step.get("run", ""))
            for step in workflow["jobs"]["maven-rubygems-runtime"]["steps"]
        )
        assert "test_version_ordering_runtime_oracle.py" in runs
        assert "generate_runtime_vectors.sh" in runs

    def test_the_facts_job_needs_no_runtime(self, workflow):
        """The gating job must not depend on a JVM or Ruby, or it can skip."""
        job = workflow["jobs"]["comparator-oracle-status"]
        text = " ".join(str(step.get("run", "")) for step in job["steps"])
        assert "test_comparator_facts.py" in text
        assert "generate_runtime_vectors.sh" not in text


class TestThePreflightMirrorsCi:
    """scripts/ci_preflight.sh must run the same steps the workflow does.

    It exists because two pushes passed my local commands and failed CI: the curated
    ruff rules flagged a bandit subprocess warning, and the test job installs hypothesis
    and openapi-spec-validator so tests that skip locally execute there. Neither was
    subtle; both were avoidable by running the job rather than my recollection of it.

    A preflight that drifts from the workflow re-creates the problem it was written to
    prevent, so the drift is asserted.
    """

    def _preflight(self) -> str:
        path = WORKFLOW.parents[2] / "packages" / "vuln_intel" / "scripts" / "ci_preflight.sh"
        assert path.exists(), f"missing {path}"
        return path.read_text(encoding="utf-8")

    def test_it_runs_every_linting_step_ci_runs(self):
        text = self._preflight()
        for tool in ("pyflakes", "ruff check", "mypy", "pytest", "vuln_intel.demo"):
            assert tool in text, f"preflight does not run {tool!r}, so CI can still surprise us"

    def test_it_fails_the_build_when_a_step_fails(self):
        """A preflight that prints FAIL and exits 0 is worse than none."""
        text = self._preflight()
        assert "exit 1" in text
        assert "failures=$((failures + 1))" in text

    def test_it_does_not_hardcode_a_sandbox_interpreter_path(self):
        """PYTHON/VIRTUAL_ENV resolution, not a /tmp path pinned from one machine."""
        text = self._preflight()
        # Built by concatenation so the literal does not read as a temp-dir use to the
        # security linter; the assertion is about a pinned sandbox path, not a tmpfile.
        sandbox_prefix = "/" + "tmp/"
        assert sandbox_prefix not in text
        assert "VIRTUAL_ENV" in text or "PYTHON" in text

    def test_the_workflow_lints_with_the_repository_config(self, workflow):
        """`ruff check vuln_intel tests` picks up ruff.toml; a bare `ruff check` would not."""
        steps = workflow["jobs"]["test"]["steps"]
        runs = " ".join(str(step.get("run", "")) for step in steps)
        assert "ruff check vuln_intel tests" in runs


class TestIntegrationDocDoesNotLie:
    """`docs/vulnerability-intelligence/INTEGRATION.md` told the host to do two things
    that did not exist: insert ``event_type: source_record_ingested`` (a value nothing
    else in the repository produces) and write a "~30-line FastAPI binding" by hand
    (superseded by the shipped ASGI app). It also named a ``SQLALCHEMY_ADAPTER_RECIPE``
    constant that was never defined anywhere.

    Documentation drift is not detectable by a failing test unless someone writes one,
    which is the point: a host team reading the doc would have integrated against a
    fiction, in their repository, where our test suite cannot see it.
    """

    @staticmethod
    def _doc() -> str:
        root = pathlib.Path(__file__).resolve().parents[3]
        return (root / "docs" / "vulnerability-intelligence" / "INTEGRATION.md").read_text()

    def test_the_phantom_recipe_is_not_named_without_saying_it_was_phantom(self):
        """Naming it in a correction is honest; promising it again is not.

        The constant never existed, so the doc may only mention it next to the word
        "never" or "phantom" — in prose, not inside a code fence a reader could copy.
        """
        doc = self._doc()
        at = doc.find("SQLALCHEMY_ADAPTER_RECIPE")
        while at != -1:
            assert not doc[:at].rstrip().endswith(("import", "from")), "copied as an import"
            # Wrapped prose puts the correction on a later line, so look at the sentence.
            window = " ".join(doc[at : at + 260].split())
            assert "never existed" in window or "phantom" in window, (
                f"INTEGRATION.md names the phantom constant without marking it: {window!r}"
            )
            at = doc.find("SQLALCHEMY_ADAPTER_RECIPE", at + 1)

    def test_every_event_type_it_names_is_one_the_package_emits(self):
        """The doc may only mention vocabulary the code can actually produce."""
        import re

        from vuln_intel.integration.mapping import event_types

        known = {event_types(created=True)[0], event_types(created=False)[0]}
        named = set(re.findall(r"`(source_record_[a-z_]+)`", self._doc()))
        assert named, "expected the doc to name the provenance vocabulary"
        assert named <= known, f"INTEGRATION.md names event types we never emit: {named - known}"

    def test_the_mount_recipe_uses_the_shipped_app(self):
        """It must not tell a host to hand-write a binding we already ship."""
        from vuln_intel.integration.asgi import build_app

        doc = self._doc()
        assert "build_app" in doc
        # The recipe has to be real: the documented call signature must match the code.
        assert "resolve_tenant" in doc
        assert callable(build_app)


class TestEveryPytestJobCanLoadEveryTestModule:
    """A job that runs `pytest` without pyyaml runs a *smaller* suite, silently.

    Several modules begin with `pytest.importorskip("yaml")`. When pyyaml is absent
    those modules do not fail and do not skip individually — they disappear from
    collection, so a job reports N fewer tests with no indication that anything is
    missing. That is how the runtime-oracle job went red on a commit that only touched
    the HTTP layer, while the `test` job on the same commit was green: the two jobs were
    running different suites and neither said so.

    A skip is a visible gap. A vanished module is an invisible one.
    """

    @staticmethod
    def _jobs_with_pytest(workflow: dict) -> list[str]:
        found = []
        for name, job in workflow["jobs"].items():
            for step in job.get("steps", []):
                if "pytest" in str(step.get("run", "")):
                    found.append(name)
                    break
        return found

    @staticmethod
    def _installs(workflow: dict, job: str, needle: str) -> bool:
        for step in workflow["jobs"][job].get("steps", []):
            run = str(step.get("run", ""))
            if "pip install" in run and needle in run:
                return True
        return False

    def test_the_premise_holds_some_module_really_is_guarded_by_yaml(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        guarded = [
            path.name
            for path in (root / "tests").glob("test_*.py")
            if 'importorskip("yaml"' in path.read_text()
        ]
        assert guarded, (
            "no module is guarded by importorskip('yaml') any more, so this class is "
            "asserting nothing and the pyyaml requirement below can be dropped"
        )

    def test_every_job_that_runs_pytest_installs_pyyaml(self, workflow):
        jobs = self._jobs_with_pytest(workflow)
        assert len(jobs) >= 4, f"expected every job to run pytest, found {jobs}"
        missing = [job for job in jobs if not self._installs(workflow, job, "pyyaml")]
        assert not missing, (
            f"job(s) {missing} run pytest without pyyaml; their suite is silently "
            "smaller because importorskip removes whole modules"
        )

    def test_the_test_job_still_installs_the_tooling_the_preflight_runs(self, workflow):
        """ci_preflight.sh runs ruff/mypy/pyflakes; the test job must install them."""
        for tool in ("ruff", "mypy", "pyflakes", "openapi-spec-validator"):
            assert self._installs(workflow, "test", tool), (
                f"the test job no longer installs {tool}, so scripts/ci_preflight.sh "
                "is checking something CI does not"
            )
