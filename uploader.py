#!/usr/bin/env python3
"""Local one-click uploader for Firmware Audit reports.

The dashboard talks to this helper over a local Unix socket.  The helper owns
remote HTTPS access, so the read-only dashboard does not need outbound network
capability.  The public receiver accepts validated Firmware Audit reports
without a per-client credential.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import socketserver
import ssl
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler
from typing import Any


REPORT_FORMAT_NAME = "firmware-audit-report"
REPORT_FORMAT_VERSION = 1
DEFAULT_REPORT_DIR = Path(os.environ.get("REPORT_DIR", "/var/lib/firmware-audit/reports"))
MAX_LOCAL_REQUEST = 4096
MAX_REMOTE_RESPONSE = 64 * 1024

try:
    APP_VERSION = Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip()
except OSError:
    APP_VERSION = "development"

LOG = logging.getLogger("firmware-audit-uploader")


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_upload_url(value: str) -> urllib.parse.SplitResult:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme.lower() != "https":
        raise ValueError("UPLOAD_URL must use https")
    if not parsed.hostname:
        raise ValueError("UPLOAD_URL must include a host")
    if parsed.username or parsed.password:
        raise ValueError("UPLOAD_URL must not contain embedded credentials")
    if parsed.fragment:
        raise ValueError("UPLOAD_URL must not contain a fragment")
    return parsed


def destination_label(value: str) -> str:
    try:
        parsed = parse_upload_url(value)
    except ValueError:
        return ""
    if parsed.port and parsed.port != 443:
        return f"{parsed.hostname}:{parsed.port}"
    return str(parsed.hostname)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_and_verify_report(path: Path) -> tuple[bytes, dict[str, Any], str]:
    raw = path.read_bytes()
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"report is not valid JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise ValueError("report root must be a JSON object")
    format_info = report.get("format") or {}
    if format_info.get("name") != REPORT_FORMAT_NAME or format_info.get("version") != REPORT_FORMAT_VERSION:
        raise ValueError("unsupported Firmware Audit report format")
    integrity = report.get("integrity") or {}
    expected = str(integrity.get("digest") or "")
    if integrity.get("algorithm") != "sha256" or len(expected) != 64:
        raise ValueError("report does not contain a valid sha256 integrity digest")
    unsigned = dict(report)
    unsigned.pop("integrity", None)
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    computed = hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(expected, computed):
        raise ValueError("report integrity check failed")
    return raw, report, expected


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: urllib.request.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def remote_upload(raw: bytes, url: str, timeout: float) -> tuple[int, dict[str, Any]]:
    parse_upload_url(url)
    request = urllib.request.Request(
        url,
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"firmware-audit-uploader/{APP_VERSION}",
        },
    )
    opener = urllib.request.build_opener(
        NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            status = int(response.status)
            body = response.read(MAX_REMOTE_RESPONSE + 1)
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_REMOTE_RESPONSE + 1)
        status = int(exc.code)
    if len(body) > MAX_REMOTE_RESPONSE:
        raise ValueError("receiver response exceeded the local safety limit")
    try:
        payload = json.loads(body.decode("utf-8")) if body else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"receiver returned a non-JSON response (HTTP {status})") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"receiver returned an invalid JSON response (HTTP {status})")
    return status, payload


class UnixHTTPServer(socketserver.UnixStreamServer):
    allow_reuse_address = True


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # one local request per connection; avoids stale-body reuse
    server_version = "FirmwareAuditUploader"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.info('http "%s"', fmt % args)

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = (json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def read_small_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length < 0 or length > MAX_LOCAL_REQUEST:
            raise ValueError("local request body is too large")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("local request is not valid JSON") from exc
        if not isinstance(payload, dict):
            raise ValueError("local request must be a JSON object")
        return payload

    def do_GET(self) -> None:
        if self.path != "/status":
            self.send_json(404, {"error": "not_found"})
            return
        enabled = env_bool("UPLOAD_ENABLED", True)
        url = os.environ.get("UPLOAD_URL", "").strip()
        available = False
        message = ""
        if not enabled:
            message = "Remote upload is disabled on this machine."
        elif not url:
            message = "Remote upload URL is not configured."
        else:
            try:
                parse_upload_url(url)
            except ValueError as exc:
                message = str(exc)
            else:
                available = True
        self.send_json(200, {
            "status": "ok",
            "enabled": enabled,
            "available": available,
            "destination": destination_label(url),
            "message": message,
            "version": APP_VERSION,
        })

    def do_POST(self) -> None:
        if self.path != "/upload-current":
            self.send_json(404, {"error": "not_found"})
            return
        try:
            payload = self.read_small_json()
        except ValueError as exc:
            self.send_json(400, {"error": "invalid_request", "message": str(exc)})
            return

        if not env_bool("UPLOAD_ENABLED", True):
            self.send_json(503, {"error": "upload_disabled", "message": "Remote report upload is not enabled on this machine."})
            return
        url = os.environ.get("UPLOAD_URL", "").strip()
        if not url:
            self.send_json(503, {"error": "upload_not_configured", "message": "UPLOAD_URL is not configured."})
            return
        try:
            parse_upload_url(url)
        except ValueError as exc:
            self.send_json(503, {"error": "upload_not_configured", "message": str(exc)})
            return

        report_path = Path(os.environ.get("REPORT_DIR", str(DEFAULT_REPORT_DIR))) / "current.json"
        try:
            raw, report, digest = load_and_verify_report(report_path)
        except (OSError, ValueError) as exc:
            self.send_json(409, {"error": "invalid_local_report", "message": str(exc)})
            return

        expected_digest = str(payload.get("digest") or "")
        if expected_digest and not hmac.compare_digest(expected_digest, digest):
            self.send_json(409, {"error": "report_changed", "message": "The current report changed. Reload the dashboard and try again."})
            return

        try:
            timeout = float(os.environ.get("UPLOAD_TIMEOUT", "30"))
        except ValueError:
            timeout = 30.0
        timeout = min(max(timeout, 1.0), 45.0)

        report_id = str((report.get("report") or {}).get("id") or "")
        try:
            status, remote = remote_upload(raw, url, timeout)
        except (OSError, ValueError, urllib.error.URLError) as exc:
            LOG.warning("upload failed report_id=%s digest=%s error=%s", report_id, digest, exc)
            self.send_json(502, {"error": "receiver_unreachable", "message": f"Upload failed: {exc}"})
            return

        if status not in {200, 201} or remote.get("status") != "ok":
            message = str(remote.get("error") or remote.get("message") or f"receiver returned HTTP {status}")
            LOG.warning("receiver rejected report report_id=%s digest=%s status=%s error=%s", report_id, digest, status, message)
            self.send_json(502, {"error": "receiver_rejected", "message": message, "remote_status": status})
            return
        remote_digest = str(remote.get("digest") or "")
        if remote_digest and not hmac.compare_digest(remote_digest, digest):
            self.send_json(502, {"error": "receiver_digest_mismatch", "message": "Receiver acknowledged a different report digest."})
            return

        duplicate = bool(remote.get("duplicate"))
        LOG.info("upload complete report_id=%s digest=%s duplicate=%s destination=%s", report_id, digest, duplicate, destination_label(url))
        self.send_json(200, {
            "status": "ok",
            "digest": digest,
            "report_id": report_id,
            "duplicate": duplicate,
            "destination": destination_label(url),
        })


def main() -> int:
    parser = argparse.ArgumentParser(description="Local Firmware Audit HTTPS upload helper")
    parser.add_argument("--socket", default="/run/firmware-audit-uploader/uploader.sock")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    socket_path = Path(args.socket)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass

    with UnixHTTPServer(str(socket_path), Handler) as server:
        os.chmod(socket_path, 0o660)
        LOG.info(
            "uploader started socket=%s enabled=%s destination=%s",
            socket_path,
            env_bool("UPLOAD_ENABLED", True),
            destination_label(os.environ.get("UPLOAD_URL", "")),
        )
        try:
            server.serve_forever(poll_interval=0.5)
        finally:
            try:
                socket_path.unlink()
            except FileNotFoundError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
