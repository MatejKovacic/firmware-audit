#!/usr/bin/env python3
"""Validated Gunicorn launcher for the local dashboard."""

from __future__ import annotations

import ipaddress
import os
import re


def valid_host(value: str) -> str:
    if value in {"localhost", "0.0.0.0", "::", "127.0.0.1", "::1"}:
        return value
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        if re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value):
            return value
    raise ValueError(f"Invalid BIND_HOST: {value}")


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def is_loopback_host(value: str) -> bool:
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def validate_listener_security(host: str, username: str, password_hash: str, allow_remote_http: bool, allow_unauthenticated_remote: bool) -> None:
    username_set = bool(username)
    password_set = bool(password_hash)
    if username_set != password_set:
        raise ValueError("WEB_USERNAME and WEB_PASSWORD_HASH must either both be set or both be empty")
    if not is_loopback_host(host) and not allow_remote_http:
        raise ValueError(
            "Refusing non-loopback HTTP listener; keep BIND_HOST on loopback behind a TLS reverse proxy "
            "or set ALLOW_REMOTE_HTTP=true explicitly"
        )
    if not is_loopback_host(host) and not (username_set and password_set) and not allow_unauthenticated_remote:
        raise ValueError(
            "Refusing unauthenticated non-loopback BIND_HOST; configure web authentication "
            "or set ALLOW_UNAUTHENTICATED_REMOTE=true explicitly"
        )


def main() -> None:
    try:
        host = valid_host(os.environ.get("BIND_HOST", "127.0.0.1"))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    try:
        port = int(os.environ.get("BIND_PORT", "8088"))
    except ValueError as exc:
        raise SystemExit("BIND_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("BIND_PORT must be between 1 and 65535")

    try:
        validate_listener_security(
            host,
            os.environ.get("WEB_USERNAME", ""),
            os.environ.get("WEB_PASSWORD_HASH", ""),
            env_bool("ALLOW_REMOTE_HTTP", False),
            env_bool("ALLOW_UNAUTHENTICATED_REMOTE", False),
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    workers = os.environ.get("WEB_WORKERS", "2")
    if not workers.isdigit() or not 1 <= int(workers) <= 16:
        raise SystemExit("WEB_WORKERS must be between 1 and 16")

    argv = [
        "/usr/bin/gunicorn",
        "--chdir",
        "/opt/firmware-audit",
        "--workers",
        workers,
        "--threads",
        "2",
        "--timeout",
        "60",
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
        "--bind",
        f"{host}:{port}",
        "app:app",
    ]
    os.execv(argv[0], argv)


if __name__ == "__main__":
    main()
