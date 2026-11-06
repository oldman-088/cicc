#!/usr/bin/env python3
"""Run a disposable API + production Next.js BFF smoke for M49 domain status.

Build the web app first (``cd apps/web && npm run build``), then run this script
with the Agent 1 API environment (for example ``apps/api/.venv/bin/python``).
It uses a temporary SQLite database, random in-memory bearer credentials, an
isolated Next.js runtime directory (so no repository .env file is loaded), and
loopback-only ephemeral ports. It does not mount or invoke a TI/VI module.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
API_DIR = ROOT / "apps" / "api"
WEB_DIR = ROOT / "apps" / "web"


def _port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _request(url: str, *, method: str = "GET", headers: dict[str, str] | None = None) -> tuple[int, bytes]:
    request = urllib.request.Request(url, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as response:
        return response.code, response.read()


def _wait(url: str, process: subprocess.Popen[Any], label: str) -> None:
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited before becoming ready (code {process.returncode})")
        try:
            _request(url)
            return
        except (OSError, TimeoutError, urllib.error.URLError):
            time.sleep(0.2)
    raise RuntimeError(f"{label} did not become ready within 45 seconds")


def _stop(process: subprocess.Popen[Any] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _link_runtime(web_runtime: Path) -> None:
    # Symlink only the build/runtime inputs. Deliberately omit every .env file.
    for name in (
        ".next",
        "node_modules",
        "app",
        "components",
        "lib",
        "messages",
        "public",
        "package.json",
        "next.config.js",
        "next.config.mjs",
        "tsconfig.json",
    ):
        source = WEB_DIR / name
        if source.exists():
            (web_runtime / name).symlink_to(source, target_is_directory=source.is_dir())


def _decode_json(status: int, body: bytes, label: str) -> dict[str, Any]:
    if status != 200:
        raise AssertionError(f"{label} returned HTTP {status}")
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AssertionError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise AssertionError(f"{label} returned a non-object JSON value")
    return value


def main() -> int:
    if not (WEB_DIR / ".next" / "BUILD_ID").is_file():
        raise SystemExit("build apps/web before running this smoke")
    next_bin = WEB_DIR / "node_modules" / "next" / "dist" / "bin" / "next"
    if not next_bin.is_file():
        raise SystemExit("apps/web/node_modules is missing; run npm ci first")
    if not Path(sys.executable).is_file():
        raise SystemExit("the active Python interpreter is unavailable")

    read_token = secrets.token_urlsafe(32)
    write_token = secrets.token_urlsafe(32)
    api_port, web_port = _port(), _port()
    api_url = f"http://127.0.0.1:{api_port}"
    web_url = f"http://127.0.0.1:{web_port}"
    api_process = None
    web_process = None

    with tempfile.TemporaryDirectory(prefix="cicc-m49-domain-smoke-") as temporary:
        temp = Path(temporary)
        db_path = temp / "ops.sqlite"
        web_runtime = temp / "web-runtime"
        web_runtime.mkdir()
        _link_runtime(web_runtime)

        common_env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": os.environ.get("HOME", str(temp)),
            "TMPDIR": str(temp),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        api_env = {
            **common_env,
            "PYTHONPATH": str(API_DIR),
            "DATABASE_URL": f"sqlite:///{db_path}",
            "CICC_OPS_READ_TOKEN": read_token,
            "CICC_OPS_WRITE_TOKEN": write_token,
        }
        web_env = {
            **common_env,
            "NODE_ENV": "production",
            "NEXT_TELEMETRY_DISABLED": "1",
            "API_INTERNAL_URL": api_url,
            "WEB_BFF_API_TOKEN": read_token,
            "WEB_BFF_ALLOW_WRITES": "0",
            "WEB_BFF_ALLOW_COORD_WRITE": "0",
            "WEB_BFF_ENFORCE_SAME_ORIGIN": "1",
        }

        try:
            api_process = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(api_port)],
                cwd=API_DIR,
                env=api_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _wait(f"{api_url}/live", api_process, "Agent 1 API")

            web_process = subprocess.Popen(
                ["node", str(next_bin), "start", "--hostname", "127.0.0.1", "--port", str(web_port)],
                cwd=web_runtime,
                env=web_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _wait(f"{web_url}/api/health", web_process, "Next.js BFF")

            direct_status, _ = _request(f"{api_url}/api/v1/coordination/domains")
            if direct_status != 401:
                raise AssertionError(f"API read gate expected 401 without a token, got {direct_status}")

            browser_headers = {
                "Authorization": "Bearer client-supplied-invalid-token",
                "Cookie": "session=client-cookie",
            }
            status_code, domains_body = _request(
                f"{web_url}/api/v1/coordination/domains", headers=browser_headers
            )
            domains = _decode_json(status_code, domains_body, "BFF domains read")
            metrics_code, metrics_body = _request(
                f"{web_url}/api/v1/coordination/domains/metrics", headers=browser_headers
            )
            metrics = _decode_json(metrics_code, metrics_body, "BFF domain metrics read")

            if domains.get("domains") != [] or domains.get("statuses") != {}:
                raise AssertionError("fresh isolated app unexpectedly reported a mounted domain")
            if metrics.get("domains") != {} or metrics.get("labels") != ["kind"]:
                raise AssertionError("unexpected domain metrics from a fresh isolated app")
            if read_token.encode() in domains_body + metrics_body or write_token.encode() in domains_body + metrics_body:
                raise AssertionError("server credential leaked in a BFF response")

            cross_site_status, _ = _request(
                f"{web_url}/api/v1/coordination/domains",
                headers={"Sec-Fetch-Site": "cross-site"},
            )
            if cross_site_status != 403:
                raise AssertionError(f"cross-site GET expected 403, got {cross_site_status}")

            write_status, write_body = _request(
                f"{web_url}/api/v1/coordination/domains", method="POST",
                headers={"Content-Type": "application/json"},
            )
            if write_status != 403 or b"method_not_allowed_via_bff" not in write_body:
                raise AssertionError(f"BFF domain write expected 403, got {write_status}")

            print(
                "M49 domain-gateway smoke PASS: direct API read gate=401; BFF domains/metrics=200 "
                "without browser credentials; cross-site GET=403; POST=403; no TI/VI module mounted; "
                "no server credential in responses."
            )
            return 0
        finally:
            _stop(web_process)
            _stop(api_process)


if __name__ == "__main__":
    raise SystemExit(main())
