"""Stable v0.12+ report contract shared only at the scanner/viewer boundary.

The scanner owns collection and assessment.  The viewer consumes the already
interpreted ``results`` object and never imports scanner assessment logic.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import re
import shlex
from typing import Any, Iterable


REPORT_FORMAT_NAME = "firmware-audit-report"
REPORT_FORMAT_VERSION = 1


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _parse_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    values: dict[str, str] = {}
    text = _read_text(path)
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        try:
            parsed = shlex.split(value, posix=True)
            values[key] = parsed[0] if parsed else ""
        except ValueError:
            values[key] = value.strip('"\'')
    return values


def _dmi_value(name: str) -> str:
    value = _read_text(Path("/sys/class/dmi/id") / name)
    if value.lower() in {"none", "not specified", "to be filled by o.e.m.", "default string"}:
        return ""
    return value


def _cpu_model(cpuinfo_path: Path = Path("/proc/cpuinfo")) -> str:
    """Return a descriptive CPU model without mistaking a processor index for it."""
    text = _read_text(cpuinfo_path)
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in {"model name", "hardware", "processor"} and value and key not in values:
            values[key] = value

    # On x86, /proc/cpuinfo begins with ``processor : 0``.  Prefer explicit
    # descriptive fields and only use ``processor`` when it is not a numeric
    # per-CPU index (some non-x86 platforms use it as the model description).
    for key in ("model name", "hardware"):
        if values.get(key):
            return values[key]
    processor = values.get("processor", "")
    if processor and not processor.isdigit():
        return processor
    return platform.processor() or ""


def _version_sort_key(value: str) -> list[Any]:
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", value)]


def _dpkg_installed_kernel_releases(status_path: Path = Path("/var/lib/dpkg/status")) -> list[str]:
    """Return releases backed by installed Debian/Ubuntu kernel image packages."""
    text = _read_text(status_path)
    if not text:
        return []

    releases: set[str] = set()
    for paragraph in re.split(r"\n\s*\n", text):
        fields: dict[str, str] = {}
        for raw_line in paragraph.splitlines():
            if not raw_line or raw_line[:1].isspace() or ":" not in raw_line:
                continue
            key, value = raw_line.split(":", 1)
            fields[key.strip()] = value.strip()
        if fields.get("Status") != "install ok installed":
            continue
        package = fields.get("Package", "")
        match = re.match(r"^linux-image-(?:unsigned-)?(.+)$", package)
        if not match:
            continue
        release = match.group(1)
        # Ignore metapackages such as linux-image-generic/linux-image-amd64.
        if re.match(r"^\d", release):
            releases.add(release)
    return sorted(releases, key=_version_sort_key)


def _installed_kernel_releases(
    running_release: str,
    *,
    modules_dir: Path = Path("/lib/modules"),
    dpkg_status_path: Path = Path("/var/lib/dpkg/status"),
) -> list[str]:
    """Collect installed releases without treating removed-package leftovers as installed."""
    packaged = _dpkg_installed_kernel_releases(dpkg_status_path)
    if packaged:
        releases = set(packaged)
        if running_release:
            releases.add(running_release)
        return sorted(releases, key=_version_sort_key)

    # Non-dpkg systems (or damaged/unavailable package metadata) retain the
    # previous local-module-directory fallback.
    releases: set[str] = set()
    try:
        releases.update(p.name for p in modules_dir.iterdir() if p.is_dir())
    except OSError:
        pass
    if running_release:
        releases.add(running_release)
    return sorted(releases, key=_version_sort_key)


def _stable_system_id(hostname: str) -> tuple[str, str]:
    product_uuid = re.sub(r"[^0-9a-f]", "", _dmi_value("product_uuid").lower())
    if product_uuid and product_uuid not in {"0" * len(product_uuid), "f" * len(product_uuid)}:
        basis = product_uuid
        source = "dmi-product-uuid"
    else:
        machine_id = re.sub(r"\s+", "", _read_text(Path("/etc/machine-id"))).lower()
        if machine_id:
            basis = machine_id
            source = "machine-id"
        else:
            basis = hostname
            source = "hostname-fallback"
    digest = hashlib.sha256(("firmware-audit-system-id-v1\0" + basis).encode("utf-8")).hexdigest()
    return f"sha256:{digest}", source


def collect_system_context(hostname: str) -> dict[str, Any]:
    """Collect small, comparison-friendly host context for every scan."""
    osr = _parse_os_release()
    uname = os.uname()
    installed_releases = _installed_kernel_releases(uname.release)

    system_id, identity_source = _stable_system_id(hostname)
    return {
        "id": system_id,
        "id_source": identity_source,
        "hostname": hostname,
        "os": {
            "id": osr.get("ID", ""),
            "name": osr.get("NAME", ""),
            "pretty_name": osr.get("PRETTY_NAME", ""),
            "version_id": osr.get("VERSION_ID", ""),
            "version": osr.get("VERSION", ""),
            "version_codename": osr.get("VERSION_CODENAME", ""),
        },
        "kernel": {
            "running_release": uname.release,
            "running_version": uname.version,
            "architecture": uname.machine,
            "installed_releases": installed_releases,
        },
        "hardware": {
            "system_vendor": _dmi_value("sys_vendor"),
            "product_name": _dmi_value("product_name"),
            "product_version": _dmi_value("product_version"),
            "board_vendor": _dmi_value("board_vendor"),
            "board_name": _dmi_value("board_name"),
            "bios_vendor": _dmi_value("bios_vendor"),
            "bios_version": _dmi_value("bios_version"),
            "bios_date": _dmi_value("bios_date"),
            "cpu_model": _cpu_model(),
        },
    }


def _coverage_from_sections(sections: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = [str(section.get("status") or "unknown") for section in sections]
    unknown_sections = [
        section for section in sections
        if str(section.get("status") or "unknown") == "unknown"
    ]
    assessed_sections = [
        section for section in sections
        if str(section.get("status") or "unknown") not in {"unknown", "not_applicable"}
    ]

    if not sections or (unknown_sections and not assessed_sections):
        status = "insufficient"
        headline = "Assessment coverage is insufficient"
        explanation = "The selected scan areas do not contain enough local evidence for a meaningful security conclusion."
    elif unknown_sections:
        status = "partial"
        headline = "Assessment coverage is partial"
        names = ", ".join(str(section.get("short_title") or section.get("title")) for section in unknown_sections)
        explanation = f"Some selected areas could not be fully assessed: {names}."
    else:
        status = "complete"
        headline = "Assessment coverage is complete"
        explanation = "All selected scan areas were assessed or determined not applicable from the available local evidence."

    return {
        "status": status,
        "headline": headline,
        "explanation": explanation,
        "unknown_area_count": len(unknown_sections),
        "assessed_area_count": len(assessed_sections),
    }


def _overall_from_sections(sections: list[dict[str, Any]], scope: str, source: dict[str, Any]) -> dict[str, Any]:
    statuses = [str(section.get("status") or "unknown") for section in sections]
    coverage = _coverage_from_sections(sections)

    if "investigate" in statuses:
        status = "investigate"
    elif "attention" in statuses:
        status = "attention"
    elif any(value not in {"unknown", "not_applicable"} for value in statuses):
        status = "good"
    elif "unknown" in statuses:
        status = "unknown"
    elif statuses and all(value == "not_applicable" for value in statuses):
        status = "not_applicable"
    else:
        status = "unknown"

    labels = {
        "investigate": (
            "Selected scan areas require investigation",
            "At least one assessed area contains an unexplained integrity or compromise-like inconsistency.",
        ),
        "attention": (
            "Selected scan areas require attention",
            "At least one assessed area contains a meaningful condition that can be acted on or requires review.",
        ),
        "unknown": (
            "Security result could not be established",
            "The selected scan areas do not contain enough assessed evidence for a meaningful security result.",
        ),
        "not_applicable": (
            "Selected scan areas are not applicable",
            "The selected checks do not apply to this platform.",
        ),
        "good": (
            "No issues found in assessed areas",
            "No actionable security problem was identified in the selected areas that could be assessed.",
        ),
    }
    headline, explanation = labels[status]
    return {"status": status, "headline": headline, "explanation": explanation, "coverage": coverage}


def build_results(assessment: dict[str, Any], requested_areas: Iterable[str], *, scope: str) -> dict[str, Any]:
    requested = list(requested_areas)
    requested_set = set(requested)
    sections_by_slug = {str(item.get("slug") or ""): item for item in assessment.get("sections", []) or []}
    areas: list[dict[str, Any]] = []
    for slug in requested:
        section = sections_by_slug.get(slug)
        if not section:
            continue
        areas.append({
            "slug": slug,
            "title": section.get("title"),
            "short_title": section.get("short_title"),
            "question": section.get("question"),
            "status": section.get("status"),
            "summary": section.get("simple_result"),
            "explanation": section.get("simple_explanation"),
            "detailed_result": section.get("detailed_result"),
            "technical_result": section.get("technical_result"),
            "findings": [item for item in (section.get("actionable_findings") or []) if item.get("section") == slug],
            "security_notes": [item for item in (section.get("security_notes") or []) if item.get("section") == slug],
            "evidence": section.get("checks") or [],
        })

    findings = [item for item in (assessment.get("findings") or []) if item.get("section") in requested_set]
    notes = [item for item in (assessment.get("security_notes") or []) if item.get("section") in requested_set]
    return {
        "overall": _overall_from_sections(areas, scope, assessment),
        "areas": areas,
        "findings": findings,
        "security_notes": notes,
        "platform_profile": assessment.get("platform_profile"),
    }


def build_report(
    *,
    report_id: str,
    created_at: str,
    scanner_version: str,
    profile: str,
    requested_areas: list[str],
    all_areas: list[str],
    system: dict[str, Any],
    timing: dict[str, Any],
    assessment: dict[str, Any],
    commands: dict[str, Any],
    artifacts: dict[str, Any],
) -> dict[str, Any]:
    scope = "full" if requested_areas == all_areas else "partial"
    return {
        "format": {"name": REPORT_FORMAT_NAME, "version": REPORT_FORMAT_VERSION},
        "report": {
            "id": report_id,
            "created_at": created_at,
            "scope": scope,
            "profile": profile,
            "requested_areas": requested_areas,
            "scanner": {
                "name": "firmware-audit-scanner",
                "version": scanner_version,
                "effective_uid": os.geteuid(),
            },
            "timing": timing,
        },
        "system": system,
        "results": build_results(assessment, requested_areas, scope=scope),
        "evidence": {
            "commands": commands,
            "artifacts": artifacts,
        },
    }
