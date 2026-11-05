"""
Static integrity checks for the Threat Intelligence package.

These are repository-supported static checks run through pytest, since the
repository ships no linter configuration. They assert structural and security
invariants that a unit test of a single module cannot see:

* the intra-package import graph is acyclic and every module imports standalone;
* no module performs network I/O or imports a networking client;
* no module spawns threads or background processes at import time;
* no secret-looking literal appears in source;
* the public package surface is complete, duplicate-free and importable;
* every service that ingests external data defaults to `fixture_tested`.
"""

import ast
import importlib
import os
import re
import subprocess
import sys
import threading

import pytest

PKG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO_ROOT = os.path.dirname(os.path.dirname(PKG_DIR))

BANNED_NETWORK_IMPORTS = (
    "requests", "httpx", "urllib.request", "urllib3", "aiohttp", "socket",
    "ftplib", "smtplib", "telnetlib", "http.client", "websockets", "boto3",
)

BANNED_CONCURRENCY_IMPORTS = ("multiprocessing", "asyncio")

# `threading` is permitted only for lock primitives that make a shared
# connection safe. Spawning a thread is banned separately by source inspection.
THREADING_LOCK_ONLY = re.compile(r"threading\.(R?Lock|Semaphore|BoundedSemaphore|Condition|Event)\b")
THREADING_BANNED_ATTR = re.compile(r"threading\.(Thread|Timer|Barrier|active_count|current_thread|main_thread)\b")

SECRET_PATTERNS = (
    re.compile(r"""(?i)(api[_-]?key|apikey|secret|passwd|password|token)"""),
)
# Patterns that are legitimate in this codebase and must not be flagged.
SECRET_ALLOWLIST = re.compile(
    r"(?i)(write_token|read_token|GH_TOKEN|GITHUB_TOKEN|secret-like|"
    r"credential_protection|no_credentials|CICC_GH_WEBHOOK_SECRET|"
    r"tokens?, or|tokens or|secret/credential|secrets,|secrets in|"
    r"never expose secrets|token is used header-only)"
)


def _module_names():
    return sorted(
        f[:-3] for f in os.listdir(PKG_DIR)
        if f.endswith(".py") and f != "__init__.py"
    )


def _read(name):
    with open(os.path.join(PKG_DIR, name + ".py"), encoding="utf-8") as fh:
        return fh.read()


def _imports_of(source):
    tree = ast.parse(source)
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module)
    return found


def _intra_package_deps(source):
    tree = ast.parse(source)
    deps = set()
    prefix = "apps.threat_intelligence."
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith(prefix):
            deps.add(node.module[len(prefix):].split(".")[0])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith(prefix):
                    deps.add(alias.name[len(prefix):].split(".")[0])
    return deps


class TestImportGraph:
    def test_every_module_is_syntactically_valid(self):
        for name in _module_names():
            ast.parse(_read(name)), name

    def test_intra_package_graph_is_acyclic(self):
        graph = {m: _intra_package_deps(_read(m)) for m in _module_names()}
        WHITE, GREY, BLACK = 0, 1, 2
        color = {m: WHITE for m in graph}
        cycles = []

        def dfs(node, path):
            color[node] = GREY
            path.append(node)
            for dep in sorted(graph.get(node, ())):
                if dep not in color:
                    continue
                if color[dep] == GREY:
                    cycles.append(path[path.index(dep):] + [dep])
                elif color[dep] == WHITE:
                    dfs(dep, path)
            path.pop()
            color[node] = BLACK

        for m in graph:
            if color[m] == WHITE:
                dfs(m, [])
        assert cycles == [], f"import cycle detected: {cycles}"

    def test_leaf_modules_have_no_intra_package_dependencies(self):
        """Core domain modules must stay dependency-free so they can be reused."""
        for name in ("threat_actors", "malware", "campaigns", "ttps", "mitre_mapping",
                     "relationships", "enrichment", "collection", "cisa_kev",
                     "vendor_advisories", "osint_sources", "mitre_ingestion",
                     "persistence", "collection_workers", "source_reliability"):
            assert _intra_package_deps(_read(name)) == set(), f"{name} must be a leaf module"

    @pytest.mark.parametrize("name", _module_names())
    def test_module_imports_standalone(self, name):
        """Each module must import without relying on package __init__ ordering."""
        env = dict(os.environ, PYTHONPATH=REPO_ROOT)
        result = subprocess.run(
            [sys.executable, "-c", f"import apps.threat_intelligence.{name}"],
            capture_output=True, text=True, env=env, cwd=REPO_ROOT,
        )
        assert result.returncode == 0, f"{name} failed standalone import:\n{result.stderr}"


class TestNoNetworkIO:
    @pytest.mark.parametrize("name", _module_names())
    def test_no_networking_client_is_imported(self, name):
        imports = _imports_of(_read(name))
        for banned in BANNED_NETWORK_IMPORTS:
            top = banned.split(".")[0]
            assert banned not in imports and top not in imports, \
                f"{name} imports networking client '{banned}'"

    @pytest.mark.parametrize("name", _module_names())
    def test_no_socket_or_url_open_calls(self, name):
        source = _read(name)
        for banned in ("socket.socket(", "urlopen(", ".request(", "http.client."):
            assert banned not in source, f"{name} contains '{banned}'"

    def test_importing_the_package_opens_no_connections(self):
        """Import must not resolve hosts or open sockets."""
        env = dict(os.environ, PYTHONPATH=REPO_ROOT)
        probe = (
            "import socket\n"
            "orig = socket.socket\n"
            "calls = []\n"
            "class Guard:\n"
            "    def __init__(self, *a, **k): calls.append(a)\n"
            "socket.socket = Guard\n"
            "import apps.threat_intelligence\n"
            "assert calls == [], f'socket opened at import: {calls}'\n"
            "print('ok')\n"
        )
        result = subprocess.run([sys.executable, "-c", probe],
                                capture_output=True, text=True, env=env, cwd=REPO_ROOT)
        assert result.returncode == 0, result.stderr
        assert "ok" in result.stdout


class TestNoHiddenBackgroundWork:
    @pytest.mark.parametrize("name", _module_names())
    def test_no_concurrency_primitive_is_imported(self, name):
        imports = _imports_of(_read(name))
        for banned in BANNED_CONCURRENCY_IMPORTS:
            assert banned not in imports, \
                f"{name} imports '{banned}'; background work must be caller-driven"

    @pytest.mark.parametrize("name", _module_names())
    def test_threading_is_used_only_for_locks(self, name):
        """
        `threading` may be imported, but only for lock primitives that make a
        shared connection safe. Spawning threads is never acceptable here:
        nothing in this package may run in the background.
        """
        source = _read(name)
        if "threading" not in _imports_of(source):
            return
        assert not THREADING_BANNED_ATTR.search(source), \
            f"{name} uses a threading primitive that can start background work"
        assert THREADING_LOCK_ONLY.search(source), \
            f"{name} imports threading but uses no lock primitive"

    @pytest.mark.parametrize("name", _module_names())
    def test_no_thread_or_process_is_started_in_source(self, name):
        source = _read(name)
        for banned in ("Thread(", "Process(", "start_new_thread(", "create_task(",
                       "asyncio.run(", "while True:"):
            assert banned not in source, f"{name} contains '{banned}'"

    def test_importing_the_package_starts_no_thread(self):
        # Run in a subprocess: deleting the package from sys.modules in-process
        # would corrupt the shared import cache for every later test.
        env = dict(os.environ, PYTHONPATH=REPO_ROOT)
        probe = (
            "import threading\n"
            "before = threading.active_count()\n"
            "import apps.threat_intelligence\n"
            "assert threading.active_count() == before, 'import started a thread'\n"
            "print('ok')\n"
        )
        result = subprocess.run([sys.executable, "-c", probe],
                                capture_output=True, text=True, env=env, cwd=REPO_ROOT)
        assert result.returncode == 0, result.stderr
        assert "ok" in result.stdout


class TestNoSecrets:
    @pytest.mark.parametrize("name", _module_names() + ["__init__"])
    def test_no_secret_looking_literals_in_source(self, name):
        source = _read(name)
        for lineno, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if SECRET_ALLOWLIST.search(line):
                continue
            for pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    # Only flag assignments that look like a real credential value.
                    if re.search(r"""(?i)(api[_-]?key|secret|passwd|password|token)\s*=\s*["'][^"']{8,}["']""", line):
                        pytest.fail(f"{name}.py:{lineno} looks like a hardcoded credential: {line.strip()}")

    def test_gitignore_excludes_env_and_venv(self):
        path = os.path.join(REPO_ROOT, ".gitignore")
        assert os.path.exists(path), "repository must ship a .gitignore"
        content = open(path, encoding="utf-8").read()
        for required in (".env", ".venv/", "__pycache__/"):
            assert required in content, f".gitignore must exclude {required}"

    def test_no_env_file_is_tracked(self):
        result = subprocess.run(
            ["git", "ls-files"], capture_output=True, text=True, cwd=REPO_ROOT
        )
        tracked = result.stdout.splitlines()
        offenders = [f for f in tracked if os.path.basename(f).startswith(".env")
                     and f != ".env.example"]
        assert offenders == [], f"tracked env files: {offenders}"


class TestPublicSurface:
    def test_package_exports_are_complete_and_unique(self):
        ti = importlib.import_module("apps.threat_intelligence")
        assert len(ti.__all__) > 100
        assert len(ti.__all__) == len(set(ti.__all__)), "duplicate entries in __all__"
        missing = [n for n in ti.__all__ if not hasattr(ti, n)]
        assert missing == [], f"declared but missing: {missing}"

    def test_every_public_module_is_reachable_from_the_package(self):
        ti = importlib.import_module("apps.threat_intelligence")
        for name in _module_names():
            assert hasattr(ti, name), f"apps.threat_intelligence.{name} is not re-exported"

    def test_version_is_semver_shaped(self):
        ti = importlib.import_module("apps.threat_intelligence")
        assert re.fullmatch(r"\d+\.\d+\.\d+", ti.__version__), ti.__version__

    def test_eager_import_cost_is_bounded(self):
        """The eager-import design must not impose a heavy import tax."""
        env = dict(os.environ, PYTHONPATH=REPO_ROOT)
        probe = (
            "import time, importlib\n"
            "t0 = time.perf_counter()\n"
            "importlib.import_module('apps.threat_intelligence')\n"
            "print((time.perf_counter() - t0) * 1000)\n"
        )
        result = subprocess.run([sys.executable, "-c", probe],
                                capture_output=True, text=True, env=env, cwd=REPO_ROOT)
        assert result.returncode == 0, result.stderr
        elapsed = float(result.stdout.strip().splitlines()[-1])
        assert elapsed < 2000.0, f"package import took {elapsed:.0f} ms"


class TestVerificationHonesty:
    """Every ingestion service must default to `fixture_tested`."""

    def test_services_default_to_fixture_tested(self):
        from apps.threat_intelligence.cisa_kev import CISAKEVIngestionService
        from apps.threat_intelligence.mitre_ingestion import MITREIngestionService
        from apps.threat_intelligence.osint_sources import OSINTIngestionService
        from apps.threat_intelligence.vendor_advisories import (
            VendorSecurityAdvisoryIngestionService,
        )

        for svc in (
            CISAKEVIngestionService(tenant_id="t"),
            MITREIngestionService(tenant_id="t"),
            OSINTIngestionService(tenant_id="t"),
            VendorSecurityAdvisoryIngestionService(tenant_id="t"),
        ):
            assert svc.verification_mode == "fixture_tested", type(svc).__name__

    def test_experimental_label_constant_is_uniform(self):
        import apps.threat_intelligence as ti
        for name in ("cisa_kev", "mitre_ingestion", "osint_sources", "vendor_advisories",
                     "persistence", "collection_workers", "source_reliability"):
            mod = importlib.import_module(f"apps.threat_intelligence.{name}")
            assert mod.EXPERIMENTAL_DEMO_DATA_ONLY == ti.EXPERIMENTAL_DEMO_DATA_ONLY

    def test_no_source_claims_live_verification(self):
        for name in _module_names():
            source = _read(name)
            assert 'verification_mode = "live_verified"' not in source, \
                f"{name} hardcodes live_verified"
            assert "verification_mode=\"live_verified\"" not in source, \
                f"{name} hardcodes live_verified"
