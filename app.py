"""Local viewer for Firmware Audit JSON reports.

The viewer contains no scanner assessment logic. It verifies the report file's
self-digest and renders the already interpreted ``results`` data. Optional manual
remote upload is delegated to a separate sandboxed helper; the viewer never opens
an outbound Internet connection itself.
"""

from __future__ import annotations

from functools import wraps
import hashlib
import hmac
import http.client
import json
import os
import socket
from pathlib import Path
from typing import Any, Callable, TypeVar

from flask import Flask, Response, abort, jsonify, render_template, request, send_file
from werkzeug.security import check_password_hash


F = TypeVar("F", bound=Callable[..., Any])
REPORT_FORMAT_NAME = "firmware-audit-report"
REPORT_FORMAT_VERSION = 1

try:
    APP_VERSION = Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip()
except OSError:
    APP_VERSION = "development"


app = Flask(__name__)
app.config.update(
    REPORT_DIR=Path(os.environ.get("REPORT_DIR", "/var/lib/firmware-audit/reports")),
    STATUS_FILE=Path(os.environ.get("STATUS_FILE", "/run/firmware-audit/status.json")),
    WEB_USERNAME=os.environ.get("WEB_USERNAME", ""),
    WEB_PASSWORD_HASH=os.environ.get("WEB_PASSWORD_HASH", ""),
    UPLOAD_ENABLED=os.environ.get("UPLOAD_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"},
    UPLOAD_SOCKET=os.environ.get("UPLOAD_SOCKET", "/run/firmware-audit-uploader/uploader.sock"),
    CSRF_SECRET_FILE=Path(os.environ.get("CSRF_SECRET_FILE", "/etc/firmware-audit/csrf.key")),
)


def validate_auth_config() -> None:
    username = bool(app.config["WEB_USERNAME"])
    password = bool(app.config["WEB_PASSWORD_HASH"])
    if username != password:
        raise RuntimeError("WEB_USERNAME and WEB_PASSWORD_HASH must either both be set or both be empty")


def auth_enabled() -> bool:
    return bool(app.config["WEB_USERNAME"] and app.config["WEB_PASSWORD_HASH"])


validate_auth_config()


def require_auth(view: F) -> F:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if not auth_enabled():
            return view(*args, **kwargs)
        auth = request.authorization
        username_ok = bool(auth) and hmac.compare_digest(auth.username or "", app.config["WEB_USERNAME"])
        password_ok = bool(auth) and check_password_hash(app.config["WEB_PASSWORD_HASH"], auth.password or "")
        if not (username_ok and password_ok):
            return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="Firmware Audit"'})
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


class UnixHTTPConnection(http.client.HTTPConnection):
    """Minimal HTTP client for the local uploader Unix socket."""

    def __init__(self, socket_path: str, timeout: float = 3.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


def uploader_request(method: str, path: str, payload: dict[str, Any] | None = None) -> tuple[int, dict[str, Any]]:
    body = None
    headers = {"Accept": "application/json", "Connection": "close"}
    if payload is not None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
        headers["Content-Length"] = str(len(body))
    timeout = 3.0
    if method.upper() == "POST":
        try:
            remote_timeout = float(os.environ.get("UPLOAD_TIMEOUT", "30"))
        except ValueError:
            remote_timeout = 30.0
        timeout = min(max(remote_timeout + 10.0, 15.0), 55.0)
    connection = UnixHTTPConnection(str(app.config["UPLOAD_SOCKET"]), timeout=timeout)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(64 * 1024 + 1)
        status = int(response.status)
    finally:
        connection.close()
    if len(raw) > 64 * 1024:
        raise ValueError("Local uploader response exceeded the safety limit")
    try:
        data = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Local uploader returned an invalid response") from exc
    if not isinstance(data, dict):
        raise ValueError("Local uploader returned an invalid response")
    return status, data


def csrf_secret() -> bytes | None:
    try:
        secret = app.config["CSRF_SECRET_FILE"].read_bytes().strip()
    except OSError:
        return None
    return secret if len(secret) >= 32 else None


def upload_csrf_token(digest: str) -> str:
    secret = csrf_secret()
    if not secret or not digest:
        return ""
    return hmac.new(secret, f"upload-current\0{digest}".encode("utf-8"), hashlib.sha256).hexdigest()


def verify_upload_csrf(token: str, digest: str) -> bool:
    expected = upload_csrf_token(digest)
    return bool(expected and token and hmac.compare_digest(expected, token))


def load_uploader_status() -> dict[str, Any]:
    if not app.config["UPLOAD_ENABLED"]:
        return {"enabled": False, "available": False, "destination": "", "message": "Remote upload is disabled on this machine."}
    if csrf_secret() is None:
        return {"enabled": True, "available": False, "destination": "", "message": "Remote upload is not fully configured."}
    try:
        status, data = uploader_request("GET", "/status")
    except (OSError, ValueError, http.client.HTTPException):
        return {"enabled": True, "available": False, "destination": "", "message": "The local upload helper is unavailable."}
    available = status == 200 and bool(data.get("available", data.get("enabled")))
    message = str(data.get("message") or "")
    return {
        "enabled": True,
        "available": available,
        "destination": str(data.get("destination") or ""),
        "message": "" if available else (message or "Remote upload is not fully configured."),
    }


def format_duration_ms(value: Any) -> str:
    try:
        milliseconds = max(0, int(value))
    except (TypeError, ValueError):
        return "unknown"
    total_seconds = milliseconds / 1000.0
    if total_seconds < 10:
        return f"{total_seconds:.1f} s"
    seconds = int(round(total_seconds))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours} h {minutes} min {seconds} s"
    if minutes:
        return f"{minutes} min {seconds} s"
    return f"{seconds} s"


def current_report_path() -> Path:
    return app.config["REPORT_DIR"] / "current.json"


def load_collection_status() -> dict[str, Any]:
    path: Path = app.config["STATUS_FILE"]
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {"state": "idle", "current_area": "", "message": "No scan is currently running", "progress_percent": 0, "log": []}
    if not isinstance(data, dict):
        return {"state": "idle", "message": "No scan is currently running", "progress_percent": 0, "log": []}
    data.setdefault("state", "idle")
    data.setdefault("log", [])
    data.setdefault("progress_percent", 0)
    return data


def verify_report_integrity(report: dict[str, Any]) -> dict[str, Any]:
    integrity = report.get("integrity") or {}
    expected = str(integrity.get("digest") or "")
    unsigned = dict(report)
    unsigned.pop("integrity", None)
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    computed = hashlib.sha256(encoded).hexdigest()
    return {
        "available": bool(expected),
        "valid": bool(expected) and hmac.compare_digest(expected, computed),
        "expected": expected,
        "computed": computed,
    }


def load_report_path(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            report = json.load(handle)
    except (OSError, json.JSONDecodeError):
        abort(500, "Report is unreadable")
    if not isinstance(report, dict):
        abort(500, "Report has an invalid structure")
    format_info = report.get("format") or {}
    if format_info.get("name") != REPORT_FORMAT_NAME or format_info.get("version") != REPORT_FORMAT_VERSION:
        abort(500, "Unsupported Firmware Audit report format")
    report["integrity_verification"] = verify_report_integrity(report)
    return report


def current_report() -> dict[str, Any] | None:
    path = current_report_path()
    return load_report_path(path) if path.is_file() else None


def require_current_report() -> tuple[Path, dict[str, Any]]:
    path = current_report_path()
    if not path.is_file():
        abort(404)
    return path, load_report_path(path)


def forensic_items(report: dict[str, Any]) -> tuple[list[tuple[str, dict[str, Any]]], list[tuple[str, Any]]]:
    evidence = report.get("evidence") or {}
    commands = [(name, dict(item)) for name, item in sorted((evidence.get("commands") or {}).items())]
    artifacts = [(name, data) for name, data in sorted((evidence.get("artifacts") or {}).items())]
    return commands, artifacts


@app.context_processor
def inject_globals() -> dict[str, Any]:
    return {"auth_enabled": auth_enabled(), "app_version": APP_VERSION, "format_duration_ms": format_duration_ms}


@app.get("/")
@require_auth
def index() -> str:
    report = current_report()
    digest = str(((report or {}).get("integrity") or {}).get("digest") or "")
    return render_template(
        "index.html",
        report=report,
        scan_status=load_collection_status(),
        upload_status=load_uploader_status(),
        upload_csrf=upload_csrf_token(digest),
    )


@app.get("/status")
@require_auth
def collection_status() -> Response:
    response = jsonify(load_collection_status())
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/raw")
@require_auth
def raw_current() -> str:
    _, report = require_current_report()
    command_items, artifact_items = forensic_items(report)
    return render_template("raw.html", report=report, command_items=command_items, artifact_items=artifact_items)


@app.get("/download")
@require_auth
def download_current() -> Response:
    path, report = require_current_report()
    report_meta = report.get("report") or {}
    download_name = f"{report_meta.get('id', 'firmware-audit-current')}.json"
    return send_file(path, as_attachment=True, download_name=download_name, mimetype="application/json")


@app.post("/upload")
@require_auth
def upload_current() -> Response:
    if not app.config["UPLOAD_ENABLED"]:
        return jsonify({"status": "error", "message": "Remote upload is disabled on this machine."}), 503
    _, report = require_current_report()
    verification = report.get("integrity_verification") or {}
    digest = str(((report.get("integrity") or {}).get("digest")) or "")
    if not verification.get("valid") or not digest:
        return jsonify({"status": "error", "message": "The current report failed its local integrity check and was not uploaded."}), 409
    if not verify_upload_csrf(str(request.form.get("csrf_token") or ""), digest):
        return jsonify({"status": "error", "message": "The upload request could not be verified. Reload the dashboard and try again."}), 403
    try:
        status, data = uploader_request("POST", "/upload-current", {"digest": digest})
    except (OSError, ValueError, http.client.HTTPException) as exc:
        return jsonify({"status": "error", "message": f"The local upload helper is unavailable: {exc}"}), 502
    if status != 200 or data.get("status") != "ok":
        message = str(data.get("message") or data.get("error") or "Upload failed")
        return jsonify({"status": "error", "message": message}), 502 if status >= 500 else status
    duplicate = bool(data.get("duplicate"))
    destination = str(data.get("destination") or "the configured server")
    message = (
        f"This report was already stored on {destination}."
        if duplicate
        else f"Report uploaded successfully to {destination}."
    )
    return jsonify({
        "status": "ok",
        "message": message,
        "duplicate": duplicate,
        "digest": str(data.get("digest") or digest),
        "report_id": str(data.get("report_id") or (report.get("report") or {}).get("id") or ""),
    })


@app.after_request
def security_headers(response: Response) -> Response:
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    if request.path != "/healthz":
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/healthz")
def healthz() -> Response:
    return Response("ok\n", mimetype="text/plain")
