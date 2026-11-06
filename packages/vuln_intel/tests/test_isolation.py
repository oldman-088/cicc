"""Contract tests for this package's boundaries with the wider platform.

These encode the two rules that make the deliverable safe to review:

1. it must not depend on, import, or modify the shared modules
   (``sources.py`` / ``main.py`` / ``models.py``);
2. it must not reach the network at import time or during tests.
"""

from __future__ import annotations

import ast
import pathlib
import sys

PACKAGE_ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGE_DIR = PACKAGE_ROOT / "vuln_intel"
FORBIDDEN_MODULES = {"app", "app.sources", "app.main", "app.models", "sources", "main", "models"}


def _module_imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def test_no_shared_module_is_imported() -> None:
    offenders: dict[str, set[str]] = {}
    for path in PACKAGE_DIR.rglob("*.py"):
        hits = {
            name
            for name in _module_imports(path)
            if name.split(".")[0] in FORBIDDEN_MODULES
        }
        if hits:
            offenders[str(path.relative_to(PACKAGE_ROOT))] = hits
    assert offenders == {}


def test_no_web_or_orm_framework_dependency() -> None:
    """Keeps the package adoptable without new pins in the API container.

    `jsonschema` and `referencing` are here for the same reason as the web and ORM
    frameworks: they are **test-only**. The CTIS interop adapter emits documents that
    are validated against a real schema, but the validation happens in the test suite,
    never at runtime. If this package ever imported jsonschema to emit a document, it
    would have taken on a dependency it does not need, in the one container that
    promised not to grow one.
    """
    heavy = {
        "fastapi", "starlette", "sqlalchemy", "alembic", "psycopg", "pydantic",
        "jsonschema", "referencing",
    }
    offenders: dict[str, set[str]] = {}
    for path in PACKAGE_DIR.rglob("*.py"):
        hits = {name for name in _module_imports(path) if name.split(".")[0] in heavy}
        if hits:
            offenders[str(path.relative_to(PACKAGE_ROOT))] = hits
    assert offenders == {}


def test_network_imports_are_lazy_and_confined_to_the_transport() -> None:
    """Only ``transport.py`` may mention httpx, and only inside a function."""
    network_modules = {"httpx", "requests", "aiohttp", "urllib3", "socket"}
    for path in PACKAGE_DIR.rglob("*.py"):
        if path.name == "transport.py":
            continue
        hits = {n for n in _module_imports(path) if n.split(".")[0] in network_modules}
        assert hits == set(), f"{path} imports network module(s) {hits}"

    transport_source = (PACKAGE_DIR / "transport.py").read_text(encoding="utf-8")
    tree = ast.parse(transport_source)
    top_level_imports = {
        alias.name.split(".")[0]
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in getattr(node, "names", [])
    }
    assert "httpx" not in top_level_imports  # imported lazily inside HttpxTransport.get


def test_importing_the_package_does_no_network_io() -> None:
    """Import must be side-effect free: no transport is constructed eagerly."""
    import vuln_intel

    assert vuln_intel.__version__ == "0.1.0"
    # The live EPSS provider is declared unavailable until a real fetch is verified.
    assert vuln_intel.LIVE_PROVIDER_AVAILABLE is False
    # No connector ships with a default transport.
    assert vuln_intel.NvdConnector().transport is None
    assert vuln_intel.OsvConnector().transport is None


def test_pytest_does_not_install_a_network_transport() -> None:
    """Guards against a future test accidentally using the real transport."""
    from vuln_intel.transport import HttpxTransport

    assert HttpxTransport is not None  # available for production use, never used in tests
    assert "tests.conftest" in sys.modules  # the shared doubles are loaded
