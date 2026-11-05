"""Oracle tooling: availability probes, versions, and loud skip reporting.

The differential tests in ``test_version_ordering_oracle*.py`` compare this package's
comparators against independent reference implementations.  Three facts make that
easy to get wrong, so this module handles all three in one place:

1. **Absence must be loud.**  A skipped oracle test is not a passing cross-check.  The
   default ``pytest`` summary does not distinguish "the oracle agreed" from "the
   oracle was never consulted", and a green CI badge certainly does not.  Every probe
   here is recorded, and :func:`report` prints a banner naming what ran and what did
   not, so the absence is visible in the CI log rather than inferable from a skip
   count.

2. **Versions must be pinned.**  "Matched the reference implementation" is a claim
   about a specific version of that implementation.  The tool versions are captured
   and asserted against the versions the documented results were produced with, so a
   silent upgrade that changes reference behaviour fails instead of quietly
   redefining the baseline.

3. **Host state must not leak in.**  ``dpkg`` and ``rpm`` are host tools whose
   behaviour can in principle vary by distribution build.  They are treated as
   *optional* oracles: present, they are used and their version is recorded; absent,
   the check is reported as unavailable rather than skipped silently or, worse,
   simulated in Python and called a cross-check.

Nothing here imports a reference implementation at module import time, because the
runtime package must stay dependency-free and this module is imported by tests that
also run in a bare environment.
"""

from __future__ import annotations

import functools
import shutil
import subprocess
import sys
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError

#: Versions the documented cross-check results in ``ORACLE_VALIDATION.md`` were
#: produced with.  ``None`` means "any version is acceptable" for that oracle.
#: These are asserted by ``test_oracle_tooling.py`` when the oracle is present: a
#: version drift is a signal to re-run the audit and update the documented numbers,
#: not something to absorb silently.
EXPECTED_VERSIONS: dict[str, str | None] = {
    "packaging": "26.3",
    "semantic_version": "2.10.0",
    "rpm-vercmp": "0.1.2",
    "dpkg": "1.21.23",
    "rpm": None,  # distribution-dependent; recorded but not pinned
}


@dataclass(frozen=True)
class OracleProbe:
    """The result of looking for one reference implementation."""

    name: str
    #: What this oracle is authoritative for.
    covers: str
    available: bool
    version: str | None
    #: Why it is unavailable, when it is.
    reason: str | None
    #: How to get it, when it is unavailable.
    install: str


def _python_dist(name: str) -> OracleProbe:
    """Probe an importable package, recording its distribution version."""
    covers = {
        "packaging": "PEP 440 (this is the implementation PyPI itself uses)",
        "semantic_version": "SemVer 2.0.0 and Go module versions",
        "rpm-vercmp": "RPM rpmvercmp (pure-Python port; lacks ^ pre-4.14)",
    }[name]
    module = name.replace("-", "_")
    try:
        __import__(module)
    except ImportError:  # any import failure means "not usable"
        return OracleProbe(
            name=name,
            covers=covers,
            available=False,
            version=None,
            reason=f"module {module!r} is not importable",
            install=f"python -m pip install {name}",
        )
    version = None
    try:
        from importlib.metadata import version as dist_version

        version = dist_version(name)
    except PackageNotFoundError:  # metadata absent, version unknown
        version = None
    return OracleProbe(
        name=name,
        covers=covers,
        available=True,
        version=version,
        reason=None,
        install=f"python -m pip install {name}",
    )


def _binary_dist(name: str, version_args: list[str], covers: str) -> OracleProbe:
    """Probe an external binary, recording the first line of its version output."""
    path = shutil.which(name)
    if path is None:
        return OracleProbe(
            name=name,
            covers=covers,
            available=False,
            version=None,
            reason=f"{name!r} is not on PATH",
            install={
                "dpkg": "apt-get install dpkg",
                "rpm": "apt-get install rpm  (or: dnf install rpm)",
            }.get(name, f"install {name}"),
        )
    version = None
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [path, *version_args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        first_line = (completed.stdout or completed.stderr or "").strip().splitlines()
        if first_line:
            version = _extract_version(first_line[0])
    except (OSError, subprocess.SubprocessError):
        version = None
    return OracleProbe(
        name=name,
        covers=covers,
        available=True,
        version=version,
        reason=None,
        install=f"install {name}",
    )


def _extract_version(text: str) -> str:
    """Pull the first dotted numeric version out of a version banner."""
    for token in text.replace("(", " ").replace(")", " ").split():
        stripped = token.strip(",;")
        parts = stripped.split(".")
        if len(parts) >= 2 and all(part.isdigit() for part in parts[:2]):
            return stripped
    return text


@functools.lru_cache(maxsize=1)
def probes() -> tuple[OracleProbe, ...]:
    """Probe every oracle once per session."""
    return (
        _python_dist("packaging"),
        _python_dist("semantic_version"),
        _python_dist("rpm-vercmp"),
        _binary_dist("dpkg", ["--version"], "Debian version ordering (verrevcmp)"),
        _binary_dist("rpm", ["--version"], "RPM version ordering (rpmvercmp, incl. ^)"),
    )


def available(name: str) -> bool:
    return any(p.name == name and p.available for p in probes())


def version_of(name: str) -> str | None:
    for probe in probes():
        if probe.name == name:
            return probe.version
    return None


def require(name: str) -> None:
    """Skip the calling test, with an actionable reason, if an oracle is missing."""
    import pytest

    for probe in probes():
        if probe.name == name:
            if not probe.available:
                pytest.skip(
                    f"oracle {name!r} unavailable ({probe.reason}); "
                    f"install with: {probe.install}. This check did NOT run."
                )
            return
    pytest.skip(f"oracle {name!r} is not a known oracle; this check did NOT run")


def report() -> str:
    """A banner naming exactly which cross-checks ran and which did not."""
    lines = ["", "=" * 78, "VERSION-ORDERING ORACLE STATUS", "=" * 78]
    ran, missing = [], []
    for probe in probes():
        if probe.available:
            ran.append(probe)
            lines.append(
                f"  [RUNS ] {probe.name:<16} version={probe.version or 'unknown':<10}"
                f" covers={probe.covers}"
            )
        else:
            missing.append(probe)
            lines.append(
                f"  [SKIP ] {probe.name:<16} {probe.reason}"
                f"  -> install: {probe.install}"
            )
    lines.append("-" * 78)
    lines.append(
        f"  {len(ran)} oracle(s) available, {len(missing)} unavailable. "
        "Cross-checks that did not run are NOT evidence of correctness."
    )
    lines.append("=" * 78)
    return "\n".join(lines)


def pytest_terminal_summary(terminalreporter) -> None:
    """Print the oracle banner at the end of every pytest run."""
    terminalreporter.write_line(report())


def main() -> int:
    """``python -m tests.oracle_tools`` — print the status, non-zero if any missing."""
    text = report()
    print(text)
    return 0 if all(probe.available for probe in probes()) else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
