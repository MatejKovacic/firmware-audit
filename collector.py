#!/usr/bin/env python3
"""Privileged, non-interactive collector for Linux firmware evidence.

The command set is fixed in source. No command arguments are accepted from the
web application or from report viewers.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import socket
import subprocess
import tempfile
import threading
import time
from typing import Any

from assessment import assess, decode_taint, detect_platform_profile, derive_amd_secure_processor_state, derive_swap_topology
from collection_profiles import build_conventional_uefi_collection
from report_format import build_report, collect_system_context
from sections import SECTION_ORDER, SECTIONS, section_for_command


DEFAULT_REPORT_DIR = Path(os.environ.get("FIRMWARE_AUDIT_REPORT_DIR", "/var/lib/firmware-audit/reports"))
STATUS_FILE = Path(os.environ.get("FIRMWARE_AUDIT_STATUS_FILE", "/run/firmware-audit/status.json"))
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
# Every external command runs with a fixed locale. C.UTF-8 keeps UTF-8
# handling while disabling gettext translations on glibc-based distributions. LANGUAGE is set as an additional safeguard for
# tools that consult it directly.
COMMAND_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "LANGUAGE": "en",
    "HOME": "/root",
    "TERM": "dumb",
    "NO_COLOR": "1",
    "PAGER": "cat",
    "SYSTEMD_PAGER": "cat",
    "SYSTEMD_COLORS": "0",
}


@dataclass(frozen=True)
class CommandSpec:
    name: str
    argv: tuple[str, ...]
    timeout: int = 30
    description: str = ""
    sensitive: bool = False
    section: str = ""
    optional: bool = False

COLLECTION_AREAS = {
    "identity": ("System identity", "Reading machine and firmware identity"),
    "firmware-baseline": ("Firmware evidence", "Reading current firmware-adjacent evidence"),
    "firmware-protection": ("Firmware protections", "Checking firmware protection capabilities"),
    "platform-security-processor": ("Platform security processor", "Reading privileged platform security-processor state"),
    "out-of-band-management": ("Out-of-band management", "Checking local management-controller interfaces"),
    "secure-boot": ("Boot trust", "Checking startup trust configuration"),
    "tpm-measured-boot": ("TPM and measured boot", "Collecting measured-boot evidence"),
    "kernel-runtime": ("System runtime", "Checking runtime integrity and diagnostics"),
    "host-integrity": ("Installed files and persistence", "Checking installed files and startup mechanisms"),
    "memory-protection": ("Memory protection", "Checking hardware memory-encryption capabilities and state"),
    "storage-memory": ("Storage and memory protection", "Checking storage encryption, swap, sleep, and DMA protections"),
    "device-firmware": ("Device firmware", "Inventorying firmware-capable devices"),
    "updates": ("Firmware metadata", "Reading locally available firmware update metadata"),
}


class CollectionStatus:
    """Small high-level status channel for the web dashboard.

    It intentionally records areas, not individual commands or raw output.
    """

    def __init__(self, path: Path = STATUS_FILE) -> None:
        self.path = path
        started = datetime.now(timezone.utc)
        self.started_at = started.isoformat()
        self._started_monotonic_ns = time.monotonic_ns()
        self.current_area = ""
        self._current_area_started_at = ""
        self._current_area_started_monotonic_ns: int | None = None
        self._area_segments: list[dict[str, Any]] = []
        self.seen_areas: set[str] = set()
        self.log: list[dict[str, str]] = []
        self.report_id = ""

    def _write(self, *, state: str, area: str, message: str, progress: int, error: str = "") -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "state": state,
            "started_at": self.started_at,
            "updated_at": now,
            "current_area": area,
            "message": message,
            "progress_percent": max(0, min(100, int(progress))),
            "report_id": self.report_id or None,
            "error": error or None,
            "log": self.log[-40:],
        }
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.path.parent, delete=False) as handle:
            json.dump(payload, handle, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
            tmp = Path(handle.name)
        try:
            group_id = grp.getgrnam("firmware-audit").gr_gid
            os.chown(tmp, 0, group_id)
            os.chmod(tmp, 0o640)
        except (KeyError, PermissionError, OSError):
            os.chmod(tmp, 0o640)
        os.replace(tmp, self.path)

    def start(self) -> None:
        self.log = [{"at": self.started_at, "area": "Starting", "message": "Collection started"}]
        self._write(state="running", area="Starting", message="Preparing security checks", progress=0)

    def _close_area_segment(self, ended_at: datetime | None = None, ended_monotonic_ns: int | None = None) -> None:
        if not self.current_area or self._current_area_started_monotonic_ns is None:
            return
        ended_at = ended_at or datetime.now(timezone.utc)
        ended_monotonic_ns = ended_monotonic_ns if ended_monotonic_ns is not None else time.monotonic_ns()
        self._area_segments.append({
            "area": self.current_area,
            "started_at": self._current_area_started_at,
            "ended_at": ended_at.isoformat(),
            "duration_ms": max(0, int((ended_monotonic_ns - self._current_area_started_monotonic_ns) / 1_000_000)),
        })
        self._current_area_started_monotonic_ns = None
        self._current_area_started_at = ""

    def area(self, area: str, message: str, progress: int) -> None:
        if area != self.current_area:
            now = datetime.now(timezone.utc)
            now_mono = time.monotonic_ns()
            self._close_area_segment(now, now_mono)
            self.current_area = area
            self._current_area_started_at = now.isoformat()
            self._current_area_started_monotonic_ns = now_mono
        if area not in self.seen_areas:
            self.seen_areas.add(area)
            self.log.append({"at": datetime.now(timezone.utc).isoformat(), "area": area, "message": message})
        self._write(state="running", area=area, message=message, progress=progress)

    def timing_snapshot(self) -> dict[str, Any]:
        """Close timing and return report-safe scan and per-area measurements."""
        completed = datetime.now(timezone.utc)
        completed_mono = time.monotonic_ns()
        self._close_area_segment(completed, completed_mono)

        # One semantic area can be visited in more than one contiguous segment
        # because command collection and derived-artifact analysis are separate
        # phases. Aggregate active time without pretending the gaps belonged to
        # that area.
        scan_area_names = {title for title, _message in COLLECTION_AREAS.values()}
        scan_segments = [segment for segment in self._area_segments if str(segment.get("area") or "") in scan_area_names]
        aggregate: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        for segment in scan_segments:
            area = str(segment["area"])
            if area not in aggregate:
                order.append(area)
                aggregate[area] = {
                    "area": area,
                    "started_at": segment["started_at"],
                    "ended_at": segment["ended_at"],
                    "duration_ms": 0,
                    "segments": 0,
                }
            item = aggregate[area]
            item["ended_at"] = segment["ended_at"]
            item["duration_ms"] += int(segment["duration_ms"])
            item["segments"] += 1

        return {
            "started_at": self.started_at,
            "completed_at": completed.isoformat(),
            "duration_ms": max(0, int((completed_mono - self._started_monotonic_ns) / 1_000_000)),
            "areas": [aggregate[name] for name in order],
            "area_segments": scan_segments,
        }

    def complete(self, report_id: str) -> None:
        self.report_id = report_id
        now = datetime.now(timezone.utc).isoformat()
        self.log.append({"at": now, "area": "Complete", "message": "Security snapshot completed"})
        self._write(state="completed", area="Complete", message="Security snapshot completed", progress=100)

    def fail(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.log.append({"at": now, "area": "Stopped", "message": "Collection stopped before completion"})
        self._write(state="failed", area="Stopped", message="Collection stopped before completion", progress=100, error="See the collection service log for details")


def _area_for_command(spec: CommandSpec) -> tuple[str, str]:
    section = spec.section or section_for_command(spec.name)
    return COLLECTION_AREAS.get(section, ("Security data", "Collecting security data"))


COMMANDS = [
    CommandSpec("locale_effective", ("locale",), description="Locale enforced for evidence commands"),
    CommandSpec(
        "locale_host_config",
        ("cat", "/etc/default/locale"),
        description="Host locale configuration",
    ),
    CommandSpec("os_release", ("cat", "/etc/os-release"), description="Operating-system release"),
    CommandSpec("uname", ("uname", "-a"), description="Kernel and architecture"),
    CommandSpec("lscpu_json", ("lscpu", "--json"), description="Structured CPU architecture and vendor data", section="identity", optional=True),
    CommandSpec("intelmetool", ("intelmetool", "-m"), timeout=45, description="Independent Intel ME/CSME status dump from coreboot intelmetool", section="platform-security-processor", optional=True),
    CommandSpec("proc_self_status", ("cat", "/proc/self/status"), description="Collector process capability state used to explain blocked low-level Intel probes", section="platform-security-processor", optional=True),
    CommandSpec("hostnamectl", ("hostnamectl",), description="Host identity and virtualization", sensitive=True),
    CommandSpec("systemd_detect_virt", ("systemd-detect-virt",), description="Virtualization type"),
    CommandSpec("proc_cmdline", ("cat", "/proc/cmdline"), description="Kernel command line"),
    CommandSpec("dmidecode_full", ("dmidecode",), timeout=60, description="Complete SMBIOS/DMI data", sensitive=True),
    CommandSpec("dmidecode_bios", ("dmidecode", "--type", "bios"), description="BIOS/UEFI DMI data"),
    CommandSpec("dmidecode_system", ("dmidecode", "--type", "system"), description="System DMI data", sensitive=True),
    CommandSpec("dmidecode_baseboard", ("dmidecode", "--type", "baseboard"), description="Baseboard DMI data", sensitive=True),
    CommandSpec("dmidecode_ipmi", ("dmidecode", "--type", "38"), description="SMBIOS IPMI management-controller records", section="out-of-band-management", optional=True),
    CommandSpec("dmidecode_mchi", ("dmidecode", "--type", "42"), description="SMBIOS management-controller host-interface records", section="out-of-band-management", optional=True),
    CommandSpec("ipmitool_mc_info", ("ipmitool", "mc", "info"), timeout=45, description="Local BMC/IPMI controller information", section="out-of-band-management", optional=True),
    CommandSpec("cpuid_amd_memory_encryption", ("cpuid", "-1", "-r", "-l", "0x8000001f", "-s", "0"), timeout=30, description="AMD memory-encryption CPUID leaf 0x8000001f", section="memory-protection", optional=True),
    CommandSpec("msr_amd_syscfg", ("rdmsr", "-p", "0", "0xc0010010"), timeout=30, description="AMD SYSCFG memory-encryption enable state", section="memory-protection", optional=True),
    CommandSpec("msr_amd_sev_status", ("rdmsr", "-p", "0", "0xc0010131"), timeout=30, description="AMD SEV status MSR", section="memory-protection", optional=True),
    CommandSpec("fwupd_version", ("fwupdmgr", "--version"), description="fwupd client, daemon, and plugin versions"),
    CommandSpec("fwupd_security_json", ("fwupdmgr", "security", "--show-all", "--json"), timeout=90, description="fwupd Host Security ID JSON"),
    CommandSpec("fwupd_security_text", ("fwupdmgr", "security", "--show-all"), timeout=90, description="fwupd Host Security ID text"),
    CommandSpec("fwupd_devices_json", ("fwupdmgr", "get-devices", "--json"), timeout=90, description="Firmware-visible devices", sensitive=True),
    CommandSpec("fwupd_updates_json", ("fwupdmgr", "get-updates", "--json"), timeout=120, description="Available firmware updates"),
    CommandSpec("fwupd_remotes_json", ("fwupdmgr", "get-remotes", "--json"), timeout=90, description="Configured fwupd metadata remotes without refreshing them", section="updates", optional=True),
    CommandSpec("fwupd_hwids_json", ("fwupdmgr", "hwids", "--json"), timeout=90, description="fwupd hardware IDs used for firmware applicability matching", section="identity", sensitive=True, optional=True),
    CommandSpec("fwupd_topology_json", ("fwupdmgr", "get-topology", "--json"), timeout=90, description="fwupd device topology", section="device-firmware", sensitive=True, optional=True),
    CommandSpec("fwupd_bios_settings_json", ("fwupdmgr", "get-bios-settings", "--json"), timeout=90, description="Firmware settings exposed through fwupd", section="firmware-protection", sensitive=True, optional=True),
    CommandSpec("secure_boot_state", ("mokutil", "--sb-state"), description="Secure Boot state"),
    CommandSpec("efi_platform_size", ("cat", "/sys/firmware/efi/fw_platform_size"), description="UEFI firmware platform width", section="secure-boot", optional=True),
    CommandSpec("mok_pk", ("mokutil", "--pk"), timeout=45, description="UEFI Platform Key certificates"),
    CommandSpec("mok_kek", ("mokutil", "--kek"), timeout=45, description="UEFI Key Exchange Key certificates"),
    CommandSpec("mok_db", ("mokutil", "--db"), timeout=60, description="UEFI signature allow-list"),
    CommandSpec("mok_dbx", ("mokutil", "--dbx"), timeout=90, description="UEFI signature revocation database"),
    CommandSpec("mok_enrolled", ("mokutil", "--list-enrolled"), timeout=60, description="Machine Owner Keys"),
    CommandSpec("efibootmgr", ("efibootmgr", "-v"), description="UEFI boot entries", sensitive=True),
    CommandSpec("tpm_properties", ("tpm2_getcap", "properties-fixed"), description="TPM fixed properties", sensitive=True),
    CommandSpec("tpm_algorithms", ("tpm2_getcap", "algorithms"), description="TPM algorithms"),
    CommandSpec("tpm_pcrs", ("tpm2_pcrread", "sha1:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23+sha256:0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23"), timeout=45, description="TPM PCR values"),
    CommandSpec("kernel_lockdown", ("cat", "/sys/kernel/security/lockdown"), description="Linux kernel lockdown state"),
    CommandSpec("security_lsm", ("cat", "/sys/kernel/security/lsm"), description="Active Linux security modules", section="kernel-runtime", optional=True),
    CommandSpec("modules_disabled", ("cat", "/proc/sys/kernel/modules_disabled"), description="Kernel module-loading disable state", section="kernel-runtime", optional=True),
    CommandSpec("kexec_load_disabled", ("cat", "/proc/sys/kernel/kexec_load_disabled"), description="Runtime kexec disable state", section="kernel-runtime", optional=True),
    CommandSpec("module_sig_enforce", ("cat", "/sys/module/module/parameters/sig_enforce"), description="Kernel module-signature enforcement state", section="kernel-runtime", optional=True),
    CommandSpec("kernel_taint", ("cat", "/proc/sys/kernel/tainted"), description="Linux kernel taint value"),
    CommandSpec("lsmod", ("lsmod",), description="Loaded kernel modules"),
    CommandSpec("kernel_journal", ("journalctl", "-k", "-b", "--no-pager", "-o", "short-iso-precise"), timeout=90, description="Complete current-boot kernel journal", sensitive=True),
    CommandSpec("warning_journal", ("journalctl", "-b", "-p", "warning..alert", "--no-pager", "-o", "short-iso-precise"), timeout=90, description="Warnings and errors from current boot", sensitive=True),
    CommandSpec("lspci", ("lspci", "-nnk"), description="PCI hardware and drivers"),
    CommandSpec("lspci_verbose", ("lspci", "-nnvv"), timeout=90, description="Verbose PCI hardware state", sensitive=True),
    CommandSpec("lsusb", ("lsusb",), description="USB device inventory", sensitive=True),
    CommandSpec("lsusb_tree", ("lsusb", "-t"), description="USB topology"),
    CommandSpec("lsblk_json", ("lsblk", "--json", "--output-all"), description="Block-device and encryption topology", sensitive=True),
    CommandSpec("swapon_json", ("swapon", "--show", "--json", "--bytes"), description="Active swap devices in JSON when supported"),
    CommandSpec("swapon_text", ("swapon", "--show", "--noheadings", "--bytes", "--output", "NAME,TYPE,SIZE,USED,PRIO"), description="Portable active swap-device inventory"),
    CommandSpec("proc_swaps", ("cat", "/proc/swaps"), description="Kernel-reported active swap inventory"),
    CommandSpec("dmsetup_tree", ("dmsetup", "ls", "--tree"), description="Device-mapper dependency tree", sensitive=True),
    CommandSpec("mounts", ("findmnt", "--json", "--real"), description="Mounted filesystems", sensitive=True),
    CommandSpec("power_mem_sleep", ("cat", "/sys/power/mem_sleep"), description="Available and selected Linux memory sleep mode"),
    CommandSpec("power_state", ("cat", "/sys/power/state"), description="Linux power states exposed by the kernel"),
    CommandSpec("iommu_kernel_log", ("journalctl", "-k", "-b", "--no-pager", "-o", "short-iso-precise", "--grep=DMAR|IOMMU|AMD-Vi|Interrupt Remapping|remapping"), timeout=60, description="Focused kernel messages about IOMMU and DMA remapping", section="storage-memory", optional=True),
    CommandSpec("bootctl", ("bootctl", "status", "--no-pager"), description="Bootloader and Secure Boot status"),
    CommandSpec("apparmor", ("aa-status",), description="AppArmor state"),
    CommandSpec("selinux", ("sestatus",), description="SELinux state"),
    CommandSpec("dpkg_verify", ("dpkg", "--verify"), timeout=600, description="Verify installed package files against local package metadata", section="host-integrity"),
    CommandSpec("dpkg_package_inventory", ("dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n"), timeout=180, description="Installed package versions and states from dpkg", section="host-integrity", sensitive=True),
    CommandSpec("dpkg_diversions", ("dpkg-divert", "--list"), timeout=90, description="Registered dpkg file diversions", section="host-integrity"),
    CommandSpec("dpkg_statoverrides", ("dpkg-statoverride", "--list"), timeout=90, description="Registered dpkg ownership and mode overrides", section="host-integrity"),
    CommandSpec("systemd_service_files", ("systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend"), timeout=90, description="Installed systemd service unit files and enablement state", section="host-integrity"),
    CommandSpec("systemd_timer_files", ("systemctl", "list-unit-files", "--type=timer", "--no-pager", "--no-legend"), timeout=90, description="Installed systemd timer unit files and enablement state", section="host-integrity"),
    CommandSpec("systemd_running_services", ("systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"), timeout=90, description="Currently running systemd services", section="host-integrity"),
    CommandSpec("systemd_timers", ("systemctl", "list-timers", "--all", "--no-pager", "--no-legend"), timeout=90, description="Active and inactive systemd timers", section="host-integrity"),
    CommandSpec("suid_sgid_files", ("find", "/", "-xdev", "-type", "f", "-user", "root", "-perm", "/6000", "-perm", "/111", "-printf", "%m\t%u\t%g\t%p\n"), timeout=180, description="Setuid and setgid executable inventory on the root filesystem", section="host-integrity", sensitive=True),
    CommandSpec("aide_check", ("aide", "--check"), timeout=900, description="Optional AIDE filesystem-integrity comparison", section="host-integrity", sensitive=True, optional=True),

]


PROFILES: dict[str, list[str]] = {
    "full": list(SECTION_ORDER),
    "daily": [slug for slug in SECTION_ORDER if slug != "host-integrity"],
    "integrity": ["host-integrity"],
}

# Some areas need supporting evidence that semantically belongs to another area.
# The dependency is an implementation detail: only the requested area is assessed
# and shown in a partial report.
AREA_SUPPORT_DEPENDENCIES: dict[str, set[str]] = {
    "memory-protection": {"platform-security-processor"},
}


def _area_command_names(slug: str) -> set[str]:
    names: set[str] = set()
    for area in [slug, *sorted(AREA_SUPPORT_DEPENDENCIES.get(slug, set()))]:
        section = SECTIONS[area]
        names.update(str(name) for name in section.get("commands", []))
        names.update(str(name) for name in section.get("optional_commands", []))
    return names


AMD_ONLY_COMMANDS = {"cpuid_amd_memory_encryption", "msr_amd_syscfg", "msr_amd_sev_status"}
INTEL_ONLY_COMMANDS = {"intelmetool", "proc_self_status"}


def command_plan(
    requested_areas: list[str],
    *,
    cpu_vendor: str | None = None,
    virtualization_kind: str | None = None,
) -> tuple[list[CommandSpec], dict[str, list[str]]]:
    requested_by_command: dict[str, list[str]] = {}
    wanted: set[str] = set()
    for area in requested_areas:
        for name in _area_command_names(area):
            wanted.add(name)
            requested_by_command.setdefault(name, []).append(area)

    # The generic dependency view (cpu_vendor=None) retains all possible probes.
    # A live scan with a known non-AMD vendor must not execute AMD-only CPUID/MSR
    # reads and then accidentally interpret their values with AMD semantics.
    if cpu_vendor is not None and cpu_vendor != "AuthenticAMD":
        wanted.difference_update(AMD_ONLY_COMMANDS)
        for name in AMD_ONLY_COMMANDS:
            requested_by_command.pop(name, None)
    if cpu_vendor is not None and cpu_vendor != "GenuineIntel":
        wanted.difference_update(INTEL_ONLY_COMMANDS)
        for name in INTEL_ONLY_COMMANDS:
            requested_by_command.pop(name, None)

    # intelmetool performs direct chipset/MMIO probing. A normal guest cannot
    # use it to establish the physical host ME/CSME state, even when CPUID
    # exposes GenuineIntel. Avoid a misleading low-level probe inside VMs.
    if virtualization_kind and virtualization_kind != "none":
        wanted.difference_update(INTEL_ONLY_COMMANDS)
        for name in INTEL_ONLY_COMMANDS:
            requested_by_command.pop(name, None)

    specs = [spec for spec in COMMANDS if spec.name in wanted]
    return specs, requested_by_command


def _detect_virtualization_kind() -> str:
    """Return a cheap preflight virtualization type for command planning.

    The recorded systemd-detect-virt command still runs as normal later. This
    preflight exists only to avoid hardware-direct probes that are meaningless
    from inside a guest.
    """
    executable = shutil.which("systemd-detect-virt", path=COMMAND_ENV["PATH"])
    if not executable:
        return ""
    try:
        completed = subprocess.run(
            (executable,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=COMMAND_ENV,
            cwd="/",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if completed.returncode == 0:
        return completed.stdout.decode("utf-8", errors="replace").strip().lower()
    if completed.returncode == 1:
        return "none"
    return ""


def _profile_name(requested_areas: list[str], explicit_profile: str) -> str:
    if explicit_profile:
        return explicit_profile
    for name, areas in PROFILES.items():
        if requested_areas == areas:
            return name
    return "custom"


def _drain_stream(stream: Any, limit: int, result: dict[str, Any]) -> None:
    digest = hashlib.sha256()
    kept = bytearray()
    total = 0
    try:
        while True:
            chunk = stream.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            digest.update(chunk)
            if len(kept) < limit:
                kept.extend(chunk[: limit - len(kept)])
    finally:
        try:
            stream.close()
        except OSError:
            pass
    result.update({
        "data": bytes(kept),
        "sha256": digest.hexdigest(),
        "bytes": total,
        "truncated": total > limit,
    })


def _run_bounded(argv: tuple[str, ...], timeout: int) -> tuple[int | None, bytes, bytes, str, str, bool, bool]:
    """Run a fixed argv while keeping at most MAX_OUTPUT_BYTES per stream in RAM.

    The complete stdout/stderr streams are still hashed while excess bytes are
    drained and discarded. This prevents a verbose local command from forcing
    the privileged collector to retain unbounded output in memory.
    """
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=COMMAND_ENV,
        cwd="/",
    )
    stdout_result: dict[str, Any] = {}
    stderr_result: dict[str, Any] = {}
    assert process.stdout is not None and process.stderr is not None
    threads = [
        threading.Thread(target=_drain_stream, args=(process.stdout, MAX_OUTPUT_BYTES, stdout_result), daemon=True),
        threading.Thread(target=_drain_stream, args=(process.stderr, MAX_OUTPUT_BYTES, stderr_result), daemon=True),
    ]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        returncode = process.wait()
    for thread in threads:
        thread.join(timeout=5)
    stdout = bytes(stdout_result.get("data", b""))
    stderr = bytes(stderr_result.get("data", b""))
    stdout_hash = str(stdout_result.get("sha256") or hashlib.sha256(stdout).hexdigest())
    stderr_hash = str(stderr_result.get("sha256") or hashlib.sha256(stderr).hexdigest())
    truncated = bool(stdout_result.get("truncated") or stderr_result.get("truncated"))
    return returncode, stdout, stderr, stdout_hash, stderr_hash, truncated, timed_out


def _result_status(spec: CommandSpec, returncode: int, stdout: str, stderr: str) -> str:
    if returncode == 0:
        return "collected" if (stdout.strip() or stderr.strip()) else "collected_empty"
    # Several read-only query tools use a non-zero status for a valid empty
    # result. Preserve that distinction instead of presenting it as failure.
    if spec.name == "systemd_detect_virt" and returncode == 1:
        return "collected_empty"
    if spec.name == "iommu_kernel_log" and returncode == 1:
        return "collected_empty"
    if spec.name == "aide_check" and 1 <= returncode <= 7:
        return "collected"
    text = f"{stdout}\n{stderr}".lower()
    if spec.name in {"fwupd_security_json", "fwupd_security_text"} and "hsi unavailable for unprivileged hypervisor" in text:
        return "not_applicable"
    if spec.name == "ipmitool_mc_info" and (
        "could not open device at /dev/ipmi" in text
        or "no such file or directory" in text and "ipmi" in text
    ):
        return "not_applicable"
    if spec.name in {"msr_amd_syscfg", "msr_amd_sev_status"} and "rdmsr: open: no such file or directory" in text:
        return "not_applicable"
    if spec.name in {"tpm_properties", "tpm_algorithms", "tpm_pcrs"} and (
        "failed to open specified tcti device file /dev/tpmrm0: no such file or directory" in text
        and "failed to open specified tcti device file /dev/tpm0: no such file or directory" in text
    ):
        return "not_applicable"
    if spec.name.startswith("fwupd_") and returncode == 2:
        return "collected" if (stdout.strip() or stderr.strip()) else "collected_empty"
    if spec.name == "efi_platform_size" and "no such file" in text:
        return "not_applicable"
    if "efi variables are not supported" in text or "doesn't support efi" in text or "not booted with efi" in text:
        return "not_applicable"
    if "unrecognized option" in text or "unknown option" in text or "invalid option" in text:
        return "unsupported"
    if "permission denied" in text or "operation not permitted" in text:
        return "permission_denied"
    if stdout.strip():
        return "failed_with_output"
    return "failed"


def run_command(spec: CommandSpec) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    executable = shutil.which(spec.argv[0], path=COMMAND_ENV["PATH"])
    section = spec.section or section_for_command(spec.name)
    base = {
        "argv": list(spec.argv),
        "description": spec.description,
        "section": section,
        "sensitive": spec.sensitive,
        "optional": spec.optional,
        "started_at": started.isoformat(),
        "effective_uid": os.geteuid(),
        "environment": dict(COMMAND_ENV),
        "executable": executable,
    }

    def finish(
        *,
        status: str,
        returncode: int | None,
        duration_ms: int,
        stdout: str,
        stderr: str,
        truncated: bool,
        stdout_sha256: str = "",
        stderr_sha256: str = "",
    ) -> dict[str, Any]:
        return {
            **base,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "status": status,
            "returncode": returncode,
            "duration_ms": duration_ms,
            "stdout": stdout,
            "stderr": stderr,
            "stdout_sha256": stdout_sha256 or hashlib.sha256(stdout.encode("utf-8", errors="replace")).hexdigest(),
            "stderr_sha256": stderr_sha256 or hashlib.sha256(stderr.encode("utf-8", errors="replace")).hexdigest(),
            "truncated": truncated,
        }

    if executable is None:
        message = f"Executable not found: {spec.argv[0]}"
        return finish(
            status="not_available", returncode=None, duration_ms=0, stdout="", stderr=message,
            truncated=False, stderr_sha256=hashlib.sha256(message.encode("utf-8")).hexdigest(),
        )

    argv = (executable, *spec.argv[1:])
    begin = time.monotonic()
    try:
        returncode, raw_stdout, raw_stderr, stdout_hash, stderr_hash, truncated, timed_out = _run_bounded(argv, spec.timeout)
        stdout = raw_stdout.decode("utf-8", errors="replace")
        stderr = raw_stderr.decode("utf-8", errors="replace")
        if timed_out:
            suffix = f"\nTimed out after {spec.timeout}s"
            return finish(
                status="timeout",
                returncode=None,
                duration_ms=round((time.monotonic() - begin) * 1000),
                stdout=stdout,
                stderr=stderr + suffix,
                truncated=truncated,
                stdout_sha256=stdout_hash,
                stderr_sha256=stderr_hash,
            )
        assert returncode is not None
        return finish(
            status=_result_status(spec, returncode, stdout, stderr),
            returncode=returncode,
            duration_ms=round((time.monotonic() - begin) * 1000),
            stdout=stdout,
            stderr=stderr,
            truncated=truncated,
            stdout_sha256=stdout_hash,
            stderr_sha256=stderr_hash,
        )
    except OSError as exc:
        message = str(exc)
        return finish(
            status="error", returncode=None,
            duration_ms=round((time.monotonic() - begin) * 1000),
            stdout="", stderr=message, truncated=False,
            stderr_sha256=hashlib.sha256(message.encode("utf-8")).hexdigest(),
        )


def sha256_file(path: Path, max_bytes: int | None = None) -> tuple[str | None, str | None]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if max_bytes is not None and total > max_bytes:
                    return None, "file-too-large"
                digest.update(chunk)
        return digest.hexdigest(), None
    except (OSError, PermissionError) as exc:
        return None, str(exc)


def collect_file_hashes() -> list[dict[str, Any]]:
    """Hash every regular file under the boot roots.

    Versioned kernel/initramfs names and Heads signature/configuration
    files are intentionally included; the previous name regex missed them.
    """
    roots = [Path("/boot"), Path("/boot/efi"), Path("/efi")]
    records: list[dict[str, Any]] = []
    seen: set[tuple[int, int]] = set()
    for root in roots:
        if not root.exists():
            continue
        try:
            for path in root.rglob("*"):
                if len(records) >= 5000:
                    records.append({"path": str(root), "error": "hash-inventory-limit-reached"})
                    return records
                try:
                    if not path.is_file():
                        continue
                    stat = path.stat()
                except OSError as exc:
                    records.append({"path": str(path), "error": str(exc)})
                    continue
                inode_key = (stat.st_dev, stat.st_ino)
                if inode_key in seen:
                    continue
                seen.add(inode_key)
                digest, error = sha256_file(path, max_bytes=512 * 1024 * 1024)
                records.append({
                    "path": str(path),
                    "size": stat.st_size,
                    "mode": oct(stat.st_mode & 0o7777),
                    "uid": stat.st_uid,
                    "gid": stat.st_gid,
                    "mtime_ns": stat.st_mtime_ns,
                    "sha256": digest,
                    "error": error,
                    "scope": "boot-file hash; file content is not embedded",
                })
        except OSError as exc:
            records.append({"path": str(root), "error": str(exc)})
    return records


def collect_efivars() -> list[dict[str, Any]]:
    root = Path("/sys/firmware/efi/efivars")
    if not root.is_dir():
        return []
    records: list[dict[str, Any]] = []
    raw_capture_bytes = 0
    raw_capture_limit = 32 * 1024 * 1024
    for path in sorted(root.iterdir(), key=lambda item: item.name.lower()):
        try:
            stat = path.stat()
            digest, error = sha256_file(path, max_bytes=32 * 1024 * 1024)
            raw_b64 = None
            raw_error = error
            if error is None and stat.st_size <= 4 * 1024 * 1024 and raw_capture_bytes + stat.st_size <= raw_capture_limit:
                try:
                    raw_b64 = base64.b64encode(path.read_bytes()).decode("ascii")
                    raw_capture_bytes += stat.st_size
                except OSError as exc:
                    raw_error = str(exc)
            elif error is None and raw_capture_bytes + stat.st_size > raw_capture_limit:
                raw_error = "raw-capture-budget-exceeded"
            records.append(
                {
                    "name": path.name,
                    "size": stat.st_size,
                    "mode": oct(stat.st_mode & 0o7777),
                    "mtime_ns": stat.st_mtime_ns,
                    "sha256": digest,
                    "data_base64": raw_b64,
                    "error": raw_error,
                }
            )
        except OSError as exc:
            records.append({"name": path.name, "error": str(exc)})
    return records


def _module_origin(filename: str) -> str:
    """Classify a loaded module by its location, without knowing the product."""
    path = filename.strip()
    if not path or path in {"(builtin)", "builtin"}:
        return "unknown"
    normalized = path.replace("\\", "/")
    if "/updates/dkms/" in normalized:
        return "external-dkms"
    if any(marker in normalized for marker in ("/updates/", "/extra/", "/weak-updates/")):
        return "external-tree"
    if re.search(r"/(?:lib|usr/lib)/modules/[^/]+/kernel/", normalized):
        return "distribution-kernel-tree"
    if "/modules/" in normalized:
        return "module-tree-other"
    return "outside-module-tree"


def _dpkg_owner_for_path(path: str) -> str:
    """Return the installed dpkg package owning path, if one can be identified."""
    if not path or path in {"(builtin)", "builtin"} or shutil.which("dpkg-query", path=COMMAND_ENV["PATH"]) is None:
        return ""
    candidates = [path]
    try:
        resolved = str(Path(path).resolve(strict=True))
        if resolved not in candidates:
            candidates.append(resolved)
    except OSError:
        pass
    for candidate in candidates:
        try:
            completed = subprocess.run(
                ["dpkg-query", "-S", candidate],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
                check=False,
                env=COMMAND_ENV,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode != 0:
            continue
        line = completed.stdout.decode(errors="replace").splitlines()[:1]
        if not line:
            continue
        owner = line[0].split(":", 1)[0].strip()
        if owner:
            return owner
    return ""


def collect_module_metadata() -> list[dict[str, Any]]:
    modules_path = Path("/proc/modules")
    if not modules_path.exists() or shutil.which("modinfo", path=COMMAND_ENV["PATH"]) is None:
        return []
    names = []
    for line in modules_path.read_text(errors="replace").splitlines():
        if line:
            names.append(line.split()[0])
    records: list[dict[str, Any]] = []
    for name in names[:1000]:
        record: dict[str, Any] = {"name": name}
        for field in ("filename", "license", "signer", "sig_key", "sig_hashalgo", "vermagic"):
            try:
                completed = subprocess.run(
                    ["/sbin/modinfo" if Path("/sbin/modinfo").exists() else "modinfo", "-F", field, name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    check=False,
                    env=COMMAND_ENV,
                )
                record[field] = completed.stdout.decode(errors="replace").strip()
            except (OSError, subprocess.TimeoutExpired):
                record[field] = ""
        filename = str(record.get("filename") or "")
        origin = _module_origin(filename)
        license_text = str(record.get("license") or "")
        needs_owner = origin in {"external-dkms", "external-tree", "module-tree-other", "outside-module-tree"} or (license_text and "gpl" not in license_text.lower() and "dual" not in license_text.lower())
        owner = _dpkg_owner_for_path(filename) if needs_owner else ""
        record["origin"] = origin
        record["package_owner"] = owner
        record["package_managed"] = bool(owner) if needs_owner else None
        record["signature_reported"] = bool(str(record.get("signer") or "").strip())
        records.append(record)
    return records


def collect_tpm_eventlog(commands: dict[str, Any]) -> dict[str, Any]:
    candidates = [
        Path("/sys/kernel/security/tpm0/binary_bios_measurements"),
        Path("/sys/kernel/security/tpm1/binary_bios_measurements"),
    ]
    for path in candidates:
        if path.exists():
            # securityfs pseudo-files commonly report st_size=0 even though a
            # read returns the complete event log. Stream the file so size and
            # digest describe the actual evidence, while retaining raw bytes
            # only up to the report-embedding limit.
            digest_state = hashlib.sha256()
            raw = bytearray()
            total_size = 0
            raw_error = None
            try:
                with path.open("rb") as handle:
                    while True:
                        chunk = handle.read(64 * 1024)
                        if not chunk:
                            break
                        total_size += len(chunk)
                        digest_state.update(chunk)
                        if len(raw) <= 16 * 1024 * 1024:
                            remaining = 16 * 1024 * 1024 + 1 - len(raw)
                            raw.extend(chunk[:remaining])
            except OSError as exc:
                raw_error = str(exc)
            digest = digest_state.hexdigest() if raw_error is None else None
            raw_b64 = None
            if raw_error is None and total_size <= 16 * 1024 * 1024:
                raw_b64 = base64.b64encode(bytes(raw)).decode("ascii")
            result: dict[str, Any] = {
                "path": str(path),
                "size": total_size,
                "sha256": digest,
                "data_base64": raw_b64,
                "error": raw_error,
            }
            spec = CommandSpec(
                "tpm_eventlog",
                ("tpm2_eventlog", str(path)),
                timeout=90,
                description="Parsed TPM measured-boot event log",
                sensitive=True,
            )
            commands[spec.name] = run_command(spec)
            return result
    missing_message = "No TPM binary_bios_measurements file found"
    now = datetime.now(timezone.utc).isoformat()
    commands["tpm_eventlog"] = {
        "argv": ["tpm2_eventlog", "<binary_bios_measurements>"],
        "description": "Parsed TPM measured-boot event log",
        "section": "tpm-measured-boot",
        "sensitive": True,
        "started_at": now,
        "finished_at": now,
        "effective_uid": os.geteuid(),
        "environment": dict(COMMAND_ENV),
        "executable": shutil.which("tpm2_eventlog", path=COMMAND_ENV["PATH"]),
        "status": "not_available",
        "returncode": None,
        "duration_ms": 0,
        "stdout": "",
        "stderr": missing_message,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_sha256": hashlib.sha256(missing_message.encode("utf-8")).hexdigest(),
        "truncated": False,
    }
    return {}


def collect_crypt_mappings(lsblk_command: dict[str, Any], commands: dict[str, Any]) -> None:
    try:
        data = json.loads(lsblk_command.get("stdout", ""))
    except (json.JSONDecodeError, TypeError):
        return

    mappings: set[str] = set()

    def walk(devices: list[dict[str, Any]]) -> None:
        for device in devices:
            if str(device.get("type", "")).lower() == "crypt" and device.get("name"):
                mappings.add(str(device["name"]))
            walk(device.get("children", []) or [])

    walk(data.get("blockdevices", []) or [])
    for name in sorted(mappings):
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        commands[f"cryptsetup_status_{safe_name}"] = run_command(
            CommandSpec(
                f"cryptsetup_status_{safe_name}",
                ("cryptsetup", "status", name),
                description=f"Encryption mapping status for {name}",
                sensitive=True,
            )
        )


def collect_firmware_runtime_hashes() -> list[dict[str, Any]]:
    """Hash OS-visible DMI and ACPI tables without claiming they are the SPI image."""
    candidates = [
        Path("/sys/firmware/dmi/tables/DMI"),
        Path("/sys/firmware/dmi/tables/smbios_entry_point"),
    ]
    for root in (Path("/sys/firmware/acpi/tables"), Path("/sys/firmware/acpi/tables/dynamic")):
        if root.is_dir():
            try:
                candidates.extend(path for path in root.iterdir() if path.is_file())
            except OSError:
                pass

    volatile_names = {"FACS"}
    records: list[dict[str, Any]] = []
    for path in sorted(set(candidates), key=lambda item: str(item)):
        try:
            stat = path.stat()
            digest, error = sha256_file(path, max_bytes=64 * 1024 * 1024)
            volatile = path.name.upper() in volatile_names or "/dynamic/" in str(path)
            records.append({
                "path": str(path),
                "size": stat.st_size,
                "mtime_ns": stat.st_mtime_ns,
                "sha256": digest,
                "error": error,
                "volatile": volatile,
                "scope": "OS-visible runtime table; not a complete SPI flash image",
            })
        except OSError as exc:
            records.append({"path": str(path), "error": str(exc)})
    return records



def _read_sysfs_value(path: Path, max_bytes: int = 64 * 1024) -> dict[str, Any]:
    """Read a small sysfs value without writing to or mutating the interface."""
    try:
        stat = path.stat()
        if stat.st_size > max_bytes and stat.st_size != 0:
            return {"error": "value-too-large", "size": stat.st_size}
        data = path.read_bytes()
        if len(data) > max_bytes:
            return {"error": "value-too-large", "size": len(data)}
        digest = hashlib.sha256(data).hexdigest()
        try:
            value = data.decode("utf-8").rstrip("\n")
            if any(ord(char) < 9 or (13 < ord(char) < 32) for char in value):
                raise UnicodeDecodeError("utf-8", data, 0, 1, "control characters")
            return {"value": value, "sha256": digest, "size": len(data)}
        except UnicodeDecodeError:
            return {
                "data_base64": base64.b64encode(data).decode("ascii"),
                "sha256": digest,
                "size": len(data),
            }
    except (OSError, PermissionError) as exc:
        return {"error": str(exc)}


def collect_firmware_attributes() -> list[dict[str, Any]]:
    """Collect read-only firmware settings exported through Linux sysfs.

    The kernel firmware-attributes class is vendor-dependent.  Missing values
    are evidence of unavailable support, not a failed security control.
    """
    root = Path("/sys/class/firmware-attributes")
    if not root.is_dir():
        return []
    records: list[dict[str, Any]] = []
    seen_paths: set[str] = set()
    try:
        providers = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        return [{"path": str(root), "error": str(exc)}]
    for provider in providers:
        try:
            resolved = provider.resolve(strict=True)
        except OSError as exc:
            records.append({"provider": provider.name, "path": str(provider), "error": str(exc)})
            continue
        try:
            paths = sorted(resolved.rglob("*"), key=lambda item: str(item))
        except OSError as exc:
            records.append({"provider": provider.name, "path": str(resolved), "error": str(exc)})
            continue
        for path in paths:
            if len(records) >= 4000:
                records.append({"path": str(root), "error": "firmware-attribute-limit-reached"})
                return records
            try:
                if not path.is_file():
                    continue
                relative = str(path.relative_to(resolved))
            except (OSError, ValueError):
                continue
            key = f"{provider.name}/{relative}"
            if key in seen_paths:
                continue
            seen_paths.add(key)
            records.append({
                "provider": provider.name,
                "path": key,
                "source_path": str(path),
                "read_only_collection": True,
                **_read_sysfs_value(path),
            })
    return records


def collect_esrt_entries() -> list[dict[str, Any]]:
    """Collect UEFI ESRT entries exported by the Linux kernel."""
    root = Path("/sys/firmware/efi/esrt/entries")
    if not root.is_dir():
        return []
    records: list[dict[str, Any]] = []
    try:
        entries = sorted((path for path in root.iterdir() if path.is_dir()), key=lambda item: item.name)
    except OSError as exc:
        return [{"path": str(root), "error": str(exc)}]
    for entry in entries:
        record: dict[str, Any] = {"entry": entry.name, "fields": {}}
        try:
            fields = sorted((path for path in entry.iterdir() if path.is_file()), key=lambda item: item.name)
        except OSError as exc:
            record["error"] = str(exc)
            records.append(record)
            continue
        for field in fields:
            record["fields"][field.name] = _read_sysfs_value(field)
        records.append(record)
    return records


def collect_iommu_groups() -> list[dict[str, Any]]:
    """Collect Linux IOMMU group membership without changing device binding."""
    root = Path("/sys/kernel/iommu_groups")
    if not root.is_dir():
        return []
    records: list[dict[str, Any]] = []
    try:
        groups = sorted((path for path in root.iterdir() if path.is_dir()), key=lambda item: int(item.name))
    except (OSError, ValueError) as exc:
        return [{"path": str(root), "error": str(exc)}]
    for group in groups:
        devices_root = group / "devices"
        devices: list[dict[str, Any]] = []
        try:
            device_links = sorted(devices_root.iterdir(), key=lambda item: item.name) if devices_root.is_dir() else []
        except OSError as exc:
            records.append({"group": group.name, "devices": [], "error": str(exc)})
            continue
        for device in device_links:
            try:
                devices.append({"bdf": device.name, "target": str(device.resolve(strict=True))})
            except OSError as exc:
                devices.append({"bdf": device.name, "error": str(exc)})
        records.append({"group": group.name, "devices": devices})
    return records


def collect_cpu_vulnerabilities() -> list[dict[str, Any]]:
    """Collect the kernel's CPU vulnerability and mitigation status strings."""
    root = Path("/sys/devices/system/cpu/vulnerabilities")
    if not root.is_dir():
        return []
    records: list[dict[str, Any]] = []
    try:
        paths = sorted((path for path in root.iterdir() if path.is_file()), key=lambda item: item.name)
    except OSError as exc:
        return [{"path": str(root), "error": str(exc)}]
    for path in paths:
        records.append({"name": path.name, **_read_sysfs_value(path)})
    return records





def _parse_pcr_values(text: str, *, require_pcrs_marker: bool = False) -> dict[str, dict[str, str]]:
    """Parse tpm2-tools PCR output without an additional YAML dependency."""
    result: dict[str, dict[str, str]] = {}
    current_algorithm = ""
    in_pcrs = not require_pcrs_marker
    for raw in text.splitlines():
        stripped = raw.strip()
        if require_pcrs_marker and stripped == "pcrs:":
            in_pcrs = True
            current_algorithm = ""
            continue
        if not in_pcrs or not stripped:
            continue
        alg_match = re.fullmatch(r"([A-Za-z0-9_-]+)\s*:\s*", stripped)
        if alg_match:
            current_algorithm = alg_match.group(1).lower()
            result.setdefault(current_algorithm, {})
            continue
        if not current_algorithm:
            continue
        pcr_match = re.fullmatch(r"(\d+)\s*:\s*(?:0x)?([0-9A-Fa-f]+)", stripped)
        if pcr_match:
            result[current_algorithm][pcr_match.group(1)] = pcr_match.group(2).lower()
    return result


def _tpm_eventlog_tail_diagnostics(parsed_text: str, raw_size: int | None) -> dict[str, Any]:
    """Extract conservative signs that an EFI/TPM event log ended at a fixed buffer limit.

    There is no portable post-boot Linux flag that proves truncation.  Keep this
    heuristic deliberately multi-signal: a near power-of-two raw size is only
    considered meaningful when the parsed log also ends during active bootloader
    measurement.
    """
    event_text = parsed_text.split("\npcrs:", 1)[0]
    matches = list(re.finditer(r"(?m)^\s*-\s*EventNum:\s*(\d+)\s*$", event_text))
    last: dict[str, Any] = {}
    if matches:
        start = matches[-1].start()
        block = event_text[start:]
        num_match = re.search(r"(?m)^\s*-\s*EventNum:\s*(\d+)\s*$", block)
        pcr_match = re.search(r"(?m)^\s*PCRIndex:\s*(\d+)\s*$", block)
        type_match = re.search(r"(?m)^\s*EventType:\s*([^\r\n]+)", block)
        string_match = re.search(r'(?m)^\s*String:\s*["\']?([^\r\n"\']+)', block)
        if num_match:
            last["event_num"] = int(num_match.group(1))
        if pcr_match:
            last["pcr"] = int(pcr_match.group(1))
        if type_match:
            last["event_type"] = type_match.group(1).strip()
        if string_match:
            last["summary"] = string_match.group(1).replace("\\0", "").replace("\0", "").strip()[:240]

    size = int(raw_size or 0)
    boundary = 0
    bytes_below_boundary = None
    near_capacity_boundary = False
    if size >= 16 * 1024:
        boundary = 1 << (size - 1).bit_length()
        bytes_below_boundary = boundary - size
        tolerance = max(64, boundary // 256)
        near_capacity_boundary = 0 <= bytes_below_boundary <= tolerance

    event_type = str(last.get("event_type") or "").upper()
    summary = str(last.get("summary") or "").lower()
    ends_during_bootloader_activity = bool(
        event_type == "EV_IPL"
        and (
            summary.startswith("grub_")
            or "grub_cmd:" in summary
            or "grub_file:" in summary
            or "kernel_cmdline" in summary
        )
    )

    return {
        "raw_size": size or None,
        "capacity_boundary": boundary or None,
        "bytes_below_capacity_boundary": bytes_below_boundary,
        "near_capacity_boundary": near_capacity_boundary,
        "parsed_event_count": len(matches),
        "last_event": last or None,
        "ends_during_bootloader_activity": ends_during_bootloader_activity,
        "likely_truncated": bool(near_capacity_boundary and ends_during_bootloader_activity),
    }


def derive_tpm_eventlog_replay(commands: dict[str, Any], eventlog_artifact: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compare locally replayed event-log PCRs with live TPM PCR values."""
    live = _parse_pcr_values(str((commands.get("tpm_pcrs") or {}).get("stdout") or ""))
    parsed_text = str((commands.get("tpm_eventlog") or {}).get("stdout") or "")
    replayed = _parse_pcr_values(parsed_text, require_pcrs_marker=True)
    common = [alg for alg in ("sha256", "sha384", "sha1", "sha512", "sm3_256") if alg in live and alg in replayed]
    diagnostics = _tpm_eventlog_tail_diagnostics(parsed_text, (eventlog_artifact or {}).get("size"))
    if not common:
        return {
            "state": "unavailable",
            "reason": "No common PCR bank could be parsed from live PCRs and the locally replayed event log",
            "live_banks": sorted(live),
            "replayed_banks": sorted(replayed),
            "event_log_diagnostics": diagnostics,
        }
    algorithm = common[0]
    indexes = sorted(set(live[algorithm]) & set(replayed[algorithm]), key=lambda value: int(value))
    all_comparisons = []
    for idx in indexes:
        actual = live[algorithm][idx]
        calculated = replayed[algorithm][idx]
        all_comparisons.append({"pcr": int(idx), "live": actual, "replayed": calculated, "match": actual == calculated})
    firmware_comparisons = [item for item in all_comparisons if 0 <= int(item["pcr"]) <= 7]
    comparisons = firmware_comparisons or all_comparisons
    if not comparisons:
        state = "unavailable"
    elif any(not item["match"] for item in comparisons):
        state = "mismatch"
    else:
        state = "matched"

    all_mismatches = [item for item in all_comparisons if not item["match"]]
    diagnostics["mismatched_pcrs"] = [item["pcr"] for item in all_mismatches]
    diagnostics["likely_truncated"] = bool(diagnostics.get("likely_truncated") and all_mismatches)
    return {
        "state": state,
        "algorithm": algorithm,
        "scope": "PCR 0-7" if firmware_comparisons else "available common PCRs",
        "comparisons": comparisons,
        "all_comparisons": all_comparisons,
        "matched": sum(1 for item in comparisons if item["match"]),
        "mismatched": sum(1 for item in comparisons if not item["match"]),
        "all_mismatched": len(all_mismatches),
        "live_banks": sorted(live),
        "replayed_banks": sorted(replayed),
        "event_log_diagnostics": diagnostics,
    }


def _read_text_value(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def _symlink_basename(path: Path) -> str:
    try:
        return path.resolve(strict=True).name
    except OSError:
        return ""


def _command_json(commands: dict[str, Any], name: str) -> Any:
    text = str((commands.get(name) or {}).get("stdout") or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _walk_fwupd_devices(value: Any):
    if isinstance(value, dict):
        if any(key in value for key in ("Name", "DeviceId", "Guid", "Vendor", "Summary")):
            yield value
        for child in value.values():
            yield from _walk_fwupd_devices(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_fwupd_devices(child)


def _parse_lspci_records(text: str) -> list[dict[str, str]]:
    """Parse lspci's block-oriented output without relying on vendor models."""
    records: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    bdf_re = re.compile(r"^((?:[0-9A-Fa-f]{4}:)?[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7])\s+(.+)$")
    for raw in text.splitlines():
        match = bdf_re.match(raw)
        if match:
            if current:
                records.append(current)
            bdf = match.group(1)
            current = {
                "bdf": bdf,
                "slot": bdf.rsplit(".", 1)[0],
                "headline": match.group(2).strip(),
                "text": raw.strip(),
            }
        elif current is not None:
            stripped = raw.strip()
            if stripped:
                current["text"] += "\n" + stripped
    if current:
        records.append(current)
    return records


def _firmware_attribute_settings(records: list[dict[str, Any]] | None) -> list[dict[str, str]]:
    """Reconstruct named firmware settings from the flattened sysfs artifact."""
    grouped: dict[tuple[str, str], dict[str, str]] = {}
    value_fields = {"name", "display_name", "current_value", "possible_values", "default_value", "type"}
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        path = str(rec.get("path") or "")
        value = rec.get("value")
        if not path or value is None:
            continue
        parts = [part for part in path.split("/") if part]
        if len(parts) < 2:
            continue
        field = parts[-1]
        if field not in value_fields:
            continue
        provider = str(rec.get("provider") or parts[0])
        setting = parts[-2]
        if setting == "attributes" and len(parts) >= 3:
            setting = parts[-3]
        key = (provider, setting)
        item = grouped.setdefault(key, {"provider": provider, "setting": setting})
        item[field] = str(value).strip()
        item.setdefault("source", path)
    return list(grouped.values())


def _setting_state(setting: dict[str, str]) -> str:
    return str(setting.get("current_value") or setting.get("value") or "").strip().lower()


def _parse_cpuid_8000001f(text: str) -> dict[str, Any]:
    result: dict[str, Any] = {"available": False}
    match = re.search(
        r"(?:0x)?8000001f[^\n]*?eax\s*=\s*0x([0-9a-fA-F]+)\s+ebx\s*=\s*0x([0-9a-fA-F]+)\s+ecx\s*=\s*0x([0-9a-fA-F]+)\s+edx\s*=\s*0x([0-9a-fA-F]+)",
        text,
        re.IGNORECASE,
    )
    if not match:
        return result
    eax, ebx, ecx, edx = (int(value, 16) for value in match.groups())
    result.update({
        "available": True,
        "eax": f"0x{eax:08x}",
        "ebx": f"0x{ebx:08x}",
        "ecx": f"0x{ecx:08x}",
        "edx": f"0x{edx:08x}",
        "sme": bool(eax & (1 << 0)),
        "sev": bool(eax & (1 << 1)),
        "sev_es": bool(eax & (1 << 3)),
        "sev_snp": bool(eax & (1 << 4)),
        "c_bit_position": ebx & 0x3f,
        "physical_address_reduction_bits": (ebx >> 6) & 0x3f,
    })
    if result["sme"] and result["c_bit_position"] == 0:
        result["c_bit_warning"] = "SME is advertised but the decoded C-bit position is zero; retain the raw CPUID result for review."
    return result


def _parse_hex_command(commands: dict[str, Any], name: str) -> int | None:
    text = str((commands.get(name) or {}).get("stdout") or "").strip()
    match = re.search(r"(?:0x)?([0-9a-fA-F]+)", text)
    if not match:
        return None
    try:
        return int(match.group(1), 16)
    except ValueError:
        return None


def _proc_capability_context(commands: dict[str, Any]) -> dict[str, Any]:
    """Return narrowly scoped capability context for low-level x86 I/O probes."""
    text = str((commands.get("proc_self_status") or {}).get("stdout") or "")
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in {"CapEff", "CapPrm", "CapBnd", "NoNewPrivs"}:
            fields[key] = value.strip()

    # Linux capability number 17 is CAP_SYS_RAWIO.
    rawio_bit = 1 << 17
    result: dict[str, Any] = {"cap_sys_rawio_number": 17}
    for source, target in (("CapEff", "effective"), ("CapPrm", "permitted"), ("CapBnd", "bounding")):
        raw = fields.get(source)
        if raw:
            try:
                result[target] = bool(int(raw, 16) & rawio_bit)
                result[target + "_raw"] = raw
            except ValueError:
                result[target] = None
                result[target + "_raw"] = raw
    if "NoNewPrivs" in fields:
        result["no_new_privs"] = fields["NoNewPrivs"] == "1"
    return result


def _kernel_lockdown_context(commands: dict[str, Any]) -> dict[str, Any]:
    raw = str((commands.get("kernel_lockdown") or {}).get("stdout") or "").strip()
    result: dict[str, Any] = {"raw": raw, "active": None, "enabled": None}
    if not raw:
        return result
    match = re.search(r"\[([^\]]+)\]", raw)
    if match:
        active = match.group(1).strip().lower()
        result["active"] = active
        result["enabled"] = active != "none"
    return result


def _parse_intelmetool_state(commands: dict[str, Any]) -> dict[str, Any]:
    """Parse conservative, explicit state strings emitted by coreboot intelmetool.

    intelmetool knows how to decode supported chipset generations. Do not
    independently decode raw ME firmware-status registers here: the Linux MEI
    ABI explicitly notes that their layout is generation dependent.

    A low-level access failure is a collection restriction, not evidence that
    Intel ME/CSME is absent or disabled.
    """
    item = commands.get("intelmetool") or {}
    status = str(item.get("status") or "not_collected")
    stdout = str(item.get("stdout") or "")
    stderr = str(item.get("stderr") or "")
    text = f"{stdout}\n{stderr}"
    lower = text.lower()
    result: dict[str, Any] = {
        "command_status": status,
        "available": status not in {"not_available", "not_collected"},
        "executed": status not in {"not_available", "not_collected"},
        "usable": False,
        "state": "unknown",
        "evidence": [],
    }
    if item.get("returncode") is not None:
        result["returncode"] = item.get("returncode")
    if item.get("effective_uid") is not None:
        result["effective_uid"] = item.get("effective_uid")

    evidence_patterns = (
        "ME: Current Working State",
        "ME: Current Operation State",
        "ME: Current Operation Mode",
        "ME: Error Code",
        "ME: Progress Phase State",
        "ME: Firmware Init Complete",
    )
    result["evidence"] = [
        line.strip() for line in text.splitlines()
        if line.strip() and any(pattern.lower() in line.lower() for pattern in evidence_patterns)
    ][:20]

    failure_lines = [line.strip() for line in text.splitlines() if line.strip()]
    blocked_low_level_io = bool(
        re.search(r"\b(?:iopl|ioperm)\s*:\s*operation not permitted\b", lower)
        or ("operation not permitted" in lower and "you need to be root" in lower)
    )
    if blocked_low_level_io:
        result["state"] = "blocked"
        result["reason"] = "iopl-permission-denied"
        result["failure_evidence"] = failure_lines[:8]
        privilege_context = {
            "kernel_lockdown": _kernel_lockdown_context(commands),
            "capabilities": _proc_capability_context(commands),
        }
        restrictions: list[str] = []
        lockdown = privilege_context["kernel_lockdown"]
        caps = privilege_context["capabilities"]
        if lockdown.get("enabled") is True:
            restrictions.append("kernel-lockdown-active")
        if caps.get("effective") is False:
            restrictions.append("cap-sys-rawio-not-effective")
        if caps.get("bounding") is False:
            restrictions.append("cap-sys-rawio-not-in-bounding-set")
        if restrictions:
            privilege_context["observed_restrictions"] = restrictions
        if item.get("effective_uid") == 0 and "you need to be root" in lower:
            privilege_context["root_message_despite_euid0"] = True
        result["privilege_context"] = privilege_context
        return result

    # A zero exit status does not make this output conclusive. On newer or
    # unsupported platforms intelmetool may fail to identify the ME PCI device
    # while generic PCI enumeration still exposes a CSME/HECI function.
    if re.search(r"can(?:not|'t)\s+find\s+me\s+pci\s+device", lower):
        result["state"] = "inconclusive"
        result["reason"] = "me-pci-device-not-recognized"
        result["failure_evidence"] = failure_lines[:8]
        return result

    disabled_patterns = (
        r"ME:\s*Current Working State\s*:\s*Disabled\b",
        r"ME:\s*Current Operation Mode\s*:\s*Soft Temporary Disable\b",
        r"ME:\s*Error Code\s*:\s*Disabled\b",
        r"ME:\s*Progress Phase State\s*:\s*ME in temp disable\b",
    )
    active_patterns = (
        r"ME:\s*Current Working State\s*:\s*Normal\b",
        r"ME:\s*Current Operation Mode\s*:\s*Normal\b",
        r"ME:\s*Firmware Init Complete\s*:\s*YES\b",
    )
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in disabled_patterns):
        result["state"] = "disabled"
        result["confidence"] = "high"
        result["usable"] = True
    elif any(re.search(pattern, text, re.IGNORECASE) for pattern in active_patterns):
        result["state"] = "active"
        result["confidence"] = "high"
        result["usable"] = True
    elif "no me present at all" in lower:
        result["state"] = "not-present"
        result["confidence"] = "high"
        result["usable"] = True
    elif status in {"collected", "collected_empty"} and result["evidence"]:
        result["state"] = "observable-state-unclear"
        result["usable"] = True
    elif status in {"failed", "failed_with_output", "permission_denied", "unsupported", "timed_out", "timeout"}:
        result["state"] = "probe-failed"
        result["failure_evidence"] = failure_lines[:8]
    elif status == "not_available":
        result["state"] = "tool-not-available"
    elif status == "not_collected":
        result["state"] = "tool-not-collected"
    return result


def _intel_mei_journal_state(journal: str) -> dict[str, Any]:
    """Preserve MEI host-interface failures without equating them to ME state."""
    lines = [line.strip() for line in journal.splitlines() if "mei_me" in line.lower()]
    lower = "\n".join(lines).lower()
    initialization_failed = bool(
        "initialization failed" in lower
        or "init hw failure" in lower
        or "hw_start failed" in lower
        or "wait hw ready failed" in lower
    )
    driver_disabled = bool("disabling the device" in lower)
    return {
        "host_interface_seen": bool(lines),
        "initialization_failed": initialization_failed,
        "driver_disabled_after_failure": driver_disabled,
        "evidence": lines[:20],
    }


def collect_platform_security_processors(
    commands: dict[str, Any],
    *,
    mei_root: Path = Path("/sys/class/mei"),
    pci_root: Path = Path("/sys/bus/pci/devices"),
    acpi_ec_root: Path = Path("/sys/bus/acpi/drivers/ec"),
) -> dict[str, Any]:
    """Inventory locally observable privileged platform and embedded processors.

    Missing Linux host interfaces are never interpreted as proof that a
    coprocessor is physically absent. The artifact keeps independent platform,
    TEE, GPU-security and embedded-controller observations separate.
    """
    result: dict[str, Any] = {
        "intel_mei": {"observable": False, "hardware_present": False, "devices": [], "state": "unobserved"},
        "amd_psp": {"observable": False, "devices": []},
        "amd_tee": {"detected": False},
        "gpu_security_processors": [],
        "embedded_controllers": [],
        "explicit_other": [],
        "generic_security_management_hardware": [],
    }

    if mei_root.is_dir():
        try:
            entries = sorted(mei_root.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            result["intel_mei"]["error"] = str(exc)
            entries = []
        for entry in entries:
            rec: dict[str, Any] = {"name": entry.name}
            for field in ("fw_ver", "dev_state", "fw_status", "kind"):
                path = entry / field
                if path.exists():
                    rec[field] = _read_text_value(path)
            device_link = entry / "device"
            if device_link.exists():
                rec["device_path"] = str(device_link.resolve(strict=False))
                for field in ("vendor", "device", "subsystem_vendor", "subsystem_device"):
                    value = _read_text_value(device_link / field)
                    if value:
                        rec[field] = value
                driver = _symlink_basename(device_link / "driver")
                if driver:
                    rec["driver"] = driver
            result["intel_mei"]["devices"].append(rec)
        result["intel_mei"]["observable"] = bool(result["intel_mei"]["devices"])

    psp_fields = (
        "bootloader_version", "tee_version", "fused_part", "debug_lock_on",
        "anti_rollback_status", "rom_armor_enforced", "boot_integrity",
        "tsme_status", "rpmc_production_enabled", "rpmc_spirom_available", "hsp_tpm_available",
    )
    if pci_root.is_dir():
        try:
            pci_entries = sorted((item for item in pci_root.iterdir() if item.is_dir()), key=lambda item: item.name)
        except OSError as exc:
            result["amd_psp"]["error"] = str(exc)
            pci_entries = []
        for dev in pci_entries:
            vendor = _read_text_value(dev / "vendor").lower()
            if vendor != "0x1022":
                continue
            driver = _symlink_basename(dev / "driver")
            attrs = {field: _read_text_value(dev / field) for field in psp_fields if (dev / field).exists()}
            if driver == "ccp" or attrs:
                rec = {"bdf": dev.name, "vendor": vendor, "driver": driver, "attributes": attrs}
                for field in ("device", "subsystem_vendor", "subsystem_device", "class"):
                    value = _read_text_value(dev / field)
                    if value:
                        rec[field] = value
                result["amd_psp"]["devices"].append(rec)

    journal = str((commands.get("kernel_journal") or {}).get("stdout") or "")
    journal_lower = journal.lower()
    intel_journal = _intel_mei_journal_state(journal)
    result["intel_mei"]["journal"] = intel_journal
    result["amd_psp"]["journal_psp_enabled"] = "psp enabled" in journal_lower
    result["amd_psp"]["journal_tee_enabled"] = "tee enabled" in journal_lower
    result["amd_psp"]["ccp_access_warning"] = bool(re.search(r"ccp:.*(?:unable to access|broken bios)", journal, re.IGNORECASE))
    result["amd_psp"]["observable"] = any(
        bool(item.get("attributes")) for item in result["amd_psp"]["devices"]
    ) or result["amd_psp"]["journal_psp_enabled"] or result["amd_psp"]["journal_tee_enabled"]
    result["amd_tee"] = {
        "detected": bool(result["amd_psp"]["journal_tee_enabled"] or any(
            str((item.get("attributes") or {}).get("tee_version") or "").strip()
            for item in result["amd_psp"]["devices"] if isinstance(item, dict)
        )),
        "source": "AMD PSP sysfs/current-boot kernel journal",
    }

    gpu_lines = []
    for line in journal.splitlines():
        lower_line = line.lower()
        if "amdgpu" in lower_line and (
            re.search(r"<psp>", lower_line)
            or "firmware via psp" in lower_line
            or "use psp to load" in lower_line
            or "psp is resuming" in lower_line
            or "for psp tmr" in lower_line
        ):
            gpu_lines.append(line.strip())
    if gpu_lines:
        result["gpu_security_processors"].append({
            "technology": "AMD GPU PSP",
            "detected": True,
            "evidence": gpu_lines[:20],
        })

    dmi = str((commands.get("dmidecode_full") or {}).get("stdout") or "")
    ec_lines = [line.strip() for line in journal.splitlines() if "acpi: ec:" in line.lower()]
    bound_ec_devices: list[str] = []
    if acpi_ec_root.is_dir():
        try:
            for entry in sorted(acpi_ec_root.iterdir(), key=lambda item: item.name):
                if entry.name in {"bind", "unbind", "uevent", "module"}:
                    continue
                if entry.is_symlink():
                    bound_ec_devices.append(str(entry))
        except OSError:
            pass
    if bound_ec_devices or ec_lines or re.search(r"embedded controller", dmi, re.IGNORECASE):
        evidence = []
        evidence.extend(bound_ec_devices[:12])
        evidence.extend(ec_lines[:12])
        for line in dmi.splitlines():
            if "embedded controller" in line.lower():
                evidence.append(line.strip())
        result["embedded_controllers"].append({"technology": "System embedded controller", "detected": True, "evidence": evidence[:20]})

    inventory_parts = [
        str((commands.get("lspci") or {}).get("stdout") or ""),
        str((commands.get("lspci_verbose") or {}).get("stdout") or ""),
    ]
    intel_pci_evidence = []
    for record in _parse_lspci_records(str((commands.get("lspci") or {}).get("stdout") or "")):
        headline = str(record.get("headline") or "")
        if re.search(r"\b(?:CSME|MEI|HECI|Management Engine)\b", headline, re.IGNORECASE) and "intel" in headline.lower():
            intel_pci_evidence.append({"bdf": record.get("bdf"), "description": headline})
    if intel_pci_evidence:
        result["intel_mei"]["pci_evidence"] = intel_pci_evidence[:20]
        result["intel_mei"]["hardware_present"] = True

    intelmetool = _parse_intelmetool_state(commands)
    result["intel_mei"]["intelmetool"] = intelmetool
    if intelmetool.get("state") == "not-present":
        result["intel_mei"]["hardware_present"] = False
    elif intelmetool.get("state") in {"disabled", "active", "observable-state-unclear"}:
        result["intel_mei"]["hardware_present"] = True

    fwupd_data = _command_json(commands, "fwupd_devices_json")
    if fwupd_data is not None:
        for device in _walk_fwupd_devices(fwupd_data):
            item_text = " ".join(str(device.get(key) or "") for key in ("Name", "Summary", "Vendor"))
            inventory_parts.append(item_text)
            lower_item = item_text.lower()
            if any(marker in lower_item for marker in ("management engine", "csme", "intel mei")):
                result["intel_mei"].setdefault("fwupd_evidence", []).append(item_text.strip())
            if "secure processor" in lower_item and ("amd" in lower_item or "advanced micro devices" in lower_item):
                result["amd_psp"].setdefault("fwupd_evidence", []).append(item_text.strip())
    result["intel_mei"]["observable"] = bool(result["intel_mei"]["observable"] or result["intel_mei"].get("fwupd_evidence"))
    result["amd_psp"]["observable"] = bool(result["amd_psp"]["observable"] or result["amd_psp"].get("fwupd_evidence"))

    if result["intel_mei"].get("fwupd_evidence"):
        result["intel_mei"]["hardware_present"] = True
    tool_state = str(intelmetool.get("state") or "unknown")
    if tool_state == "disabled":
        result["intel_mei"]["state"] = "disabled"
        result["intel_mei"]["state_source"] = "intelmetool"
    elif tool_state == "active":
        result["intel_mei"]["state"] = "active"
        result["intel_mei"]["state_source"] = "intelmetool"
        result["intel_mei"]["observable"] = True
    elif result["intel_mei"]["observable"]:
        result["intel_mei"]["state"] = "host-interface-observable"
    elif result["intel_mei"].get("hardware_present") and intel_journal.get("initialization_failed"):
        result["intel_mei"]["state"] = "host-interface-unavailable"
    elif result["intel_mei"].get("hardware_present"):
        result["intel_mei"]["state"] = "hardware-present-state-unknown"
    elif tool_state == "not-present":
        result["intel_mei"]["state"] = "not-present"
        result["intel_mei"]["state_source"] = "intelmetool"

    inventory = "\n".join(inventory_parts).lower()
    explicit = []
    if "pluton" in inventory:
        explicit.append({"technology": "Microsoft Pluton", "evidence": "explicit local device/inventory name"})
    if "qualcomm secure processing unit" in inventory or "qualcomm spu" in inventory:
        explicit.append({"technology": "Qualcomm Secure Processing Unit", "evidence": "explicit local device/inventory name"})
    result["explicit_other"] = explicit

    generic_records = []
    seen = set()
    for record in _parse_lspci_records(str((commands.get("lspci") or {}).get("stdout") or "")):
        headline = record.get("headline", "")
        lower_headline = headline.lower()
        if any(term in lower_headline for term in (
            "security controller", "secure processor", "encryption controller", "cryptographic", "ipmi interface",
            "management controller", "trusted execution", "trusted platform",
        )):
            key = (record.get("bdf"), headline)
            if key not in seen:
                seen.add(key)
                generic_records.append({"bdf": record.get("bdf"), "description": headline})
    result["generic_security_management_hardware"] = generic_records[:40]
    result["detected"] = bool(
        result["intel_mei"]["observable"] or result["amd_psp"]["observable"] or explicit
        or result["gpu_security_processors"] or result["embedded_controllers"] or generic_records
    )
    return result


def collect_out_of_band_management(
    commands: dict[str, Any],
    *,
    firmware_attributes: list[dict[str, Any]] | None = None,
    ipmi_root: Path = Path("/sys/class/ipmi"),
    dev_root: Path = Path("/dev"),
) -> dict[str, Any]:
    """Collect local OOB-management evidence without any network discovery."""
    result: dict[str, Any] = {
        "bmc": {"detected": False, "interfaces": []},
        "intel_amt": {"detected": False},
        "nic_oob": {"detected": False, "functions": []},
        "dmtf_dash": {"detected": False, "state": "unknown", "evidence": []},
        "firmware_persistence": [],
    }

    if ipmi_root.is_dir():
        try:
            for item in sorted(ipmi_root.iterdir(), key=lambda path: path.name):
                result["bmc"]["interfaces"].append({"name": item.name, "path": str(item.resolve(strict=False))})
        except OSError as exc:
            result["bmc"]["error"] = str(exc)
    try:
        for item in sorted(dev_root.glob("ipmi*"), key=lambda path: path.name):
            result["bmc"]["interfaces"].append({"name": item.name, "path": str(item)})
    except OSError:
        pass

    dmi_ipmi = str((commands.get("dmidecode_ipmi") or {}).get("stdout") or "").strip()
    dmi_mchi = str((commands.get("dmidecode_mchi") or {}).get("stdout") or "").strip()
    ipmitool = str((commands.get("ipmitool_mc_info") or {}).get("stdout") or "").strip()
    dmi_ipmi_present = bool(re.search(r"^IPMI Device Information\s*$", dmi_ipmi, re.IGNORECASE | re.MULTILINE))
    dmi_mchi_present = bool(re.search(r"^Management Controller Host Interface\s*$", dmi_mchi, re.IGNORECASE | re.MULTILINE))
    if dmi_ipmi_present:
        result["bmc"]["smbios_record_present"] = True
    if dmi_mchi_present:
        result["bmc"]["mchi_record_present"] = True
    if ipmitool:
        result["bmc"]["ipmitool_info"] = ipmitool[:16384]
    result["bmc"]["detected"] = bool(result["bmc"]["interfaces"] or dmi_ipmi_present or ipmitool)

    fwupd_data = _command_json(commands, "fwupd_devices_json")
    amt_records = []
    if fwupd_data is not None:
        for device in _walk_fwupd_devices(fwupd_data):
            name = str(device.get("Name") or "")
            summary = str(device.get("Summary") or "")
            text = f"{name} {summary}".lower()
            if re.search(r"\bamt\b", text) or "active management technology" in text or "remote out-of-band management" in text:
                state = "unknown"
                if "unprovisioned" in text:
                    state = "unprovisioned"
                elif "provisioned" in text:
                    state = "provisioned"
                amt_records.append({
                    "name": name,
                    "summary": summary,
                    "version": str(device.get("Version") or ""),
                    "vendor": str(device.get("Vendor") or ""),
                    "provisioning_state": state,
                })
    result["intel_amt"] = {
        "detected": bool(amt_records),
        "records": amt_records,
        "mchi_present": dmi_mchi_present,
    }

    lspci_records = _parse_lspci_records(str((commands.get("lspci") or {}).get("stdout") or ""))
    ipmi_pci = [record for record in lspci_records if "ipmi interface" in record.get("headline", "").lower() or "[0c07]" in record.get("headline", "").lower()]
    for record in ipmi_pci:
        siblings = [item for item in lspci_records if item.get("slot") == record.get("slot") and item.get("bdf") != record.get("bdf")]
        network_siblings = [item for item in siblings if any(term in item.get("headline", "").lower() for term in ("ethernet controller", "network controller", "[0200]"))]
        result["nic_oob"]["functions"].append({
            "bdf": record.get("bdf"),
            "description": record.get("headline"),
            "multifunction_slot": record.get("slot"),
            "network_siblings": [{"bdf": item.get("bdf"), "description": item.get("headline")} for item in network_siblings],
            "sibling_functions": [{"bdf": item.get("bdf"), "description": item.get("headline")} for item in siblings[:12]],
        })
    result["nic_oob"]["detected"] = bool(result["nic_oob"]["functions"])
    journal = str((commands.get("kernel_journal") or {}).get("stdout") or "")
    ipmi_no_system_interface = bool(re.search(r"ipmi_si:.*unable to find any system interface", journal, re.IGNORECASE))
    result["nic_oob"]["kernel_no_system_interface"] = ipmi_no_system_interface
    nic_with_network = any(item.get("network_siblings") for item in result["nic_oob"]["functions"])
    if result["nic_oob"]["detected"] and not result["bmc"]["detected"] and ipmi_no_system_interface and nic_with_network:
        result["nic_oob"]["state"] = "nic-oob-function-dormant"
    elif result["nic_oob"]["detected"] and result["bmc"]["detected"]:
        result["nic_oob"]["state"] = "host-interface-present"
    elif result["nic_oob"]["detected"]:
        result["nic_oob"]["state"] = "interface-present-state-unknown"
    else:
        result["nic_oob"]["state"] = "not-observed"

    settings = _firmware_attribute_settings(firmware_attributes)
    dash_evidence: list[str] = []
    dash_states: list[str] = []
    for line in journal.splitlines():
        if re.search(r"\bDASH\s+disabled\b", line, re.IGNORECASE):
            dash_states.append("disabled")
            dash_evidence.append(line.strip())
        elif re.search(r"\bDASH\s+enabled\b", line, re.IGNORECASE):
            dash_states.append("enabled")
            dash_evidence.append(line.strip())
    for setting in settings:
        name = " ".join((setting.get("setting", ""), setting.get("name", ""), setting.get("display_name", ""))).lower()
        if "dash" not in name:
            continue
        state = _setting_state(setting)
        dash_evidence.append(f"{setting.get('provider')}/{setting.get('setting')}={setting.get('current_value', '')}")
        if state in {"disable", "disabled", "off", "false", "0", "no"}:
            dash_states.append("disabled")
        elif state in {"enable", "enabled", "on", "true", "1", "yes"}:
            dash_states.append("enabled")
    if dash_states:
        result["dmtf_dash"]["detected"] = True
        if "enabled" in dash_states and "disabled" in dash_states:
            result["dmtf_dash"]["state"] = "inconsistent"
        elif "enabled" in dash_states:
            result["dmtf_dash"]["state"] = "enabled"
        else:
            result["dmtf_dash"]["state"] = "disabled"
        result["dmtf_dash"]["evidence"] = dash_evidence[:20]

    for setting in settings:
        searchable = " ".join((setting.get("setting", ""), setting.get("name", ""), setting.get("display_name", ""))).lower()
        persistence_like = bool(
            "absolute" in searchable
            or "computrace" in searchable
            or re.search(r"(?:endpoint.*persistence|persistence.*(?:module|activation|agent|endpoint))", searchable)
        )
        if not persistence_like:
            continue
        raw_state = str(setting.get("current_value") or "").strip()
        state_lower = raw_state.lower()
        if state_lower in {"enable", "enabled", "on", "true", "1", "yes"}:
            state = "firmware-enabled-agent-state-unknown"
        elif "permanent" in state_lower and "disable" in state_lower:
            state = "permanently-disabled"
        elif state_lower in {"disable", "disabled", "off", "false", "0", "no"}:
            state = "disabled"
        else:
            state = "state-unknown"
        result["firmware_persistence"].append({
            "technology_class": "firmware endpoint persistence",
            "setting": setting.get("setting"),
            "provider": setting.get("provider"),
            "raw_value": raw_state,
            "state": state,
            "evidence": f"{setting.get('provider')}/{setting.get('setting')}={raw_state}",
        })

    result["detected"] = bool(
        result["bmc"]["detected"] or result["intel_amt"]["detected"] or result["nic_oob"]["detected"]
        or result["dmtf_dash"]["detected"] or result["firmware_persistence"]
    )
    return result


def _cpuinfo_text(cpuinfo_path: Path = Path("/proc/cpuinfo")) -> str:
    try:
        return cpuinfo_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _cpu_vendor_id(cpuinfo_path: Path = Path("/proc/cpuinfo")) -> str:
    text = _cpuinfo_text(cpuinfo_path)
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() in {"vendor_id", "vendor"}:
            vendor = value.strip()
            if vendor:
                return vendor
    return "unknown"


def _cpu_feature_flags(cpuinfo_path: Path = Path("/proc/cpuinfo")) -> set[str]:
    text = _cpuinfo_text(cpuinfo_path)
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() in {"flags", "features"}:
            return {item.strip().lower() for item in value.split() if item.strip()}
    return set()


def _intel_tme_runtime_state(journal: str, *, supported: bool) -> dict[str, Any]:
    relevant = [
        line.strip()
        for line in journal.splitlines()
        if re.search(r"\bx86/tme:|total memory encryption|\bintel tme\b", line, re.IGNORECASE)
    ]
    negative = next(
        (line for line in relevant if re.search(r"\b(?:not enabled|disabled|inactive|not active)\b", line, re.IGNORECASE)),
        "",
    )
    if negative:
        return {
            "active": False,
            "state": "supported-not-enabled" if supported else "not-enabled",
            "evidence": negative,
        }
    positive = next(
        (line for line in relevant if re.search(r"\b(?:enabled|active)\b", line, re.IGNORECASE)),
        "",
    )
    if positive:
        return {"active": True, "state": "active", "evidence": positive}
    return {
        "active": False,
        "state": "supported-state-unknown" if supported else "not-observed",
        "evidence": relevant[0] if relevant else "",
    }


def collect_memory_protection(
    commands: dict[str, Any],
    *,
    platform_security: dict[str, Any] | None = None,
    firmware_attributes: list[dict[str, Any]] | None = None,
    cpuinfo_path: Path = Path("/proc/cpuinfo"),
    module_root: Path = Path("/sys/module"),
    dev_root: Path = Path("/dev"),
) -> dict[str, Any]:
    """Collect memory-encryption capability separately from activation state.

    Architecture-specific CPUID/MSR meanings are only decoded for the CPU vendor
    that defines them.  This prevents unrelated non-zero leaves on another vendor
    from being mistaken for supported security features.
    """
    vendor = _cpu_vendor_id(cpuinfo_path)
    is_amd = vendor == "AuthenticAMD"
    is_intel = vendor == "GenuineIntel"
    flags = _cpu_feature_flags(cpuinfo_path)

    if is_amd:
        cpuid = _parse_cpuid_8000001f(str((commands.get("cpuid_amd_memory_encryption") or {}).get("stdout") or ""))
        cpuid["applicable"] = True
        cpuid["cpu_vendor"] = vendor
    else:
        cpuid = {"available": False, "applicable": False, "cpu_vendor": vendor}

    capabilities = {
        "amd_sme": is_amd and (bool(cpuid.get("sme")) if cpuid.get("available") else "sme" in flags),
        "amd_sev": is_amd and (bool(cpuid.get("sev")) if cpuid.get("available") else "sev" in flags),
        "amd_sev_es": is_amd and (bool(cpuid.get("sev_es")) if cpuid.get("available") else "sev_es" in flags),
        "amd_sev_snp": is_amd and (bool(cpuid.get("sev_snp")) if cpuid.get("available") else "sev_snp" in flags),
        "intel_tme": is_intel and "tme" in flags,
        "intel_tme_mk": is_intel and bool({"tme_mk", "tme-mk"} & flags),
        "intel_tdx": is_intel and bool({"tdx", "tdx_host_platform", "tdx_guest"} & flags),
    }

    journal = str((commands.get("kernel_journal") or {}).get("stdout") or "")
    lower = journal.lower()
    amd_sme_active = is_amd and bool(re.search(r"amd memory encryption features active:.*\bsme\b", lower))
    syscfg = _parse_hex_command(commands, "msr_amd_syscfg") if is_amd else None
    sev_msr = _parse_hex_command(commands, "msr_amd_sev_status") if is_amd else None
    syscfg_enabled = None if syscfg is None else bool(syscfg & (1 << 23))
    sev_msr_active = None if sev_msr is None else bool(sev_msr & 1)

    processor = platform_security if isinstance(platform_security, dict) else {}
    amd = processor.get("amd_psp") if isinstance(processor.get("amd_psp"), dict) else {}
    tsme_sysfs_values: list[dict[str, str]] = []
    if is_amd:
        for device in amd.get("devices", []) or []:
            if not isinstance(device, dict):
                continue
            attrs = device.get("attributes") if isinstance(device.get("attributes"), dict) else {}
            if "tsme_status" in attrs:
                tsme_sysfs_values.append({"bdf": str(device.get("bdf") or ""), "value": str(attrs.get("tsme_status") or "").strip()})
    tsme_active_sysfs = is_amd and any(item.get("value", "").lower() in {"1", "yes", "true", "on", "enabled", "enable"} for item in tsme_sysfs_values)

    settings = _firmware_attribute_settings(firmware_attributes)
    tsme_fw: list[dict[str, str]] = []
    if is_amd:
        for setting in settings:
            searchable = " ".join((setting.get("setting", ""), setting.get("name", ""), setting.get("display_name", ""))).lower()
            if re.search(r"\btsme\b|transparent secure memory encryption", searchable):
                tsme_fw.append(setting)
    tsme_fw_enabled = is_amd and any(_setting_state(item) in {"enable", "enabled", "on", "true", "1", "yes"} for item in tsme_fw)
    tsme_active = is_amd and (tsme_active_sysfs or (tsme_fw_enabled and not tsme_sysfs_values))
    tsme_confidence = "high" if tsme_active_sysfs else ("medium" if tsme_fw_enabled else "unknown")

    kvm_amd: dict[str, str] = {}
    if is_amd:
        for field in ("sev", "sev_es", "sev_snp"):
            path = module_root / "kvm_amd" / "parameters" / field
            if path.exists():
                kvm_amd[field] = _read_text_value(path)
    true_values = {"1", "y", "yes", "true", "on", "enabled"}
    kvm_sev_enabled = str(kvm_amd.get("sev") or "").strip().lower() in true_values
    kvm_sev_es_enabled = str(kvm_amd.get("sev_es") or "").strip().lower() in true_values
    kvm_sev_snp_enabled = str(kvm_amd.get("sev_snp") or "").strip().lower() in true_values

    intel_tme_state = _intel_tme_runtime_state(journal, supported=bool(capabilities["intel_tme"])) if is_intel else {
        "active": False,
        "state": "not-applicable",
        "evidence": "",
    }

    active_technologies = []
    if amd_sme_active:
        active_technologies.append("AMD SME (Linux-managed)")
    if tsme_active:
        active_technologies.append("AMD TSME")
    if intel_tme_state.get("active"):
        active_technologies.append("Intel TME")
    system_active = bool(active_technologies)

    if capabilities["amd_sme"]:
        if amd_sme_active:
            sme_state = "active-linux-managed"
        elif tsme_active:
            sme_state = "supported-os-not-active-tsme-active"
        elif syscfg_enabled is True:
            sme_state = "enabled-not-observed-active"
        elif syscfg_enabled is False:
            sme_state = "supported-not-enabled"
        else:
            sme_state = "supported-state-unknown"
    else:
        sme_state = "not-observed" if is_amd else "not-applicable"

    if tsme_active_sysfs:
        tsme_state = "active-transparent"
    elif tsme_fw_enabled:
        tsme_state = "firmware-enabled-runtime-state-unavailable"
    elif tsme_sysfs_values:
        tsme_state = "inactive"
    else:
        tsme_state = "not-observed" if is_amd else "not-applicable"

    sev_host_enabled = is_amd and bool(kvm_sev_enabled or (sev_msr_active is True and (dev_root / "sev").exists()))
    if capabilities["amd_sev"]:
        sev_state = "enabled-for-host" if sev_host_enabled else "supported-host-disabled"
    else:
        sev_state = "not-observed" if is_amd else "not-applicable"

    return {
        "cpu_vendor": vendor,
        "cpu_flags_observed": sorted(flag for flag in flags if flag in {"sme", "sev", "sev_es", "sev_snp", "tme", "tme_mk", "tme-mk", "tdx", "tdx_host_platform", "tdx_guest"}),
        "amd_cpuid_8000001f": cpuid,
        "capabilities": capabilities,
        "system_memory": {
            # Compatibility fields retained for scanner-side assessment helpers.
            "amd_sme_kernel_active": amd_sme_active,
            "mem_encrypt_requested": is_amd and "mem_encrypt=on" in str((commands.get("proc_cmdline") or {}).get("stdout") or "").lower(),
            "active": system_active,
            "active_technologies": active_technologies,
            "amd_sme": {
                "supported": capabilities["amd_sme"],
                "state": sme_state,
                "linux_managed_active": amd_sme_active,
                "syscfg_msr": f"0x{syscfg:x}" if syscfg is not None else None,
                "memory_encryption_enable_bit23": syscfg_enabled,
            },
            "amd_tsme": {
                "state": tsme_state,
                "active": tsme_active,
                "confidence": tsme_confidence,
                "sysfs": tsme_sysfs_values,
                "firmware_settings": [
                    {"provider": item.get("provider"), "setting": item.get("setting"), "current_value": item.get("current_value", "")}
                    for item in tsme_fw
                ],
            },
            "intel_tme": {
                "supported": capabilities["intel_tme"],
                "multi_key_supported": capabilities["intel_tme_mk"],
                "active": bool(intel_tme_state.get("active")),
                "state": str(intel_tme_state.get("state") or "unknown"),
                "evidence": str(intel_tme_state.get("evidence") or ""),
            },
        },
        "confidential_vm": {
            "amd_sev": {
                "supported": capabilities["amd_sev"],
                "sev_es_supported": capabilities["amd_sev_es"],
                "sev_snp_supported": capabilities["amd_sev_snp"],
                "state": sev_state,
                "host_enabled": sev_host_enabled,
                "kvm_parameters": kvm_amd,
                "dev_sev_present": is_amd and (dev_root / "sev").exists(),
                "sev_status_msr": f"0x{sev_msr:x}" if sev_msr is not None else None,
                "sev_status_active_bit0": sev_msr_active,
                "sev_enabled_parameter": kvm_sev_enabled,
                "sev_es_enabled_parameter": kvm_sev_es_enabled,
                "sev_snp_enabled_parameter": kvm_sev_snp_enabled,
            },
            "kvm_amd_parameters": kvm_amd,
            "dev_sev_present": is_amd and (dev_root / "sev").exists(),
            "intel_tdx": {"supported": capabilities["intel_tdx"]},
        },
    }

def collect_thunderbolt_security() -> dict[str, Any]:
    """Collect USB4/Thunderbolt authorization and DMA-protection state from sysfs."""
    root = Path("/sys/bus/thunderbolt/devices")
    if not root.is_dir():
        return {"available": False, "domains": [], "devices": []}
    domains: list[dict[str, Any]] = []
    devices: list[dict[str, Any]] = []
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        return {"available": True, "domains": [], "devices": [], "error": str(exc)}
    for path in entries:
        record: dict[str, Any] = {"name": path.name}
        if path.name.startswith("domain"):
            for field in ("security", "iommu_dma_protection"):
                value_path = path / field
                if value_path.exists():
                    record[field] = _read_sysfs_value(value_path).get("value", "")
            domains.append(record)
        else:
            for field in ("authorized", "device_name", "vendor_name", "generation", "unique_id"):
                value_path = path / field
                if value_path.exists():
                    record[field] = _read_sysfs_value(value_path).get("value", "")
            devices.append(record)
    return {"available": True, "domains": domains, "devices": devices}


def _safe_read_small_text(path: Path, limit: int = 128 * 1024) -> tuple[str, str | None]:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            return data[:limit].decode("utf-8", errors="replace"), "truncated"
        return data.decode("utf-8", errors="replace"), None
    except OSError as exc:
        return "", str(exc)


def collect_integrity_frameworks() -> dict[str, Any]:
    """Inventory local kernel integrity frameworks without modifying policy."""
    security = Path("/sys/kernel/security")
    result: dict[str, Any] = {"securityfs_available": security.is_dir()}
    ima_root = next((candidate for candidate in (security / "integrity/ima", security / "ima") if candidate.is_dir()), None)
    ima: dict[str, Any] = {"available": ima_root is not None}
    if ima_root is not None:
        ima["root"] = str(ima_root)
        policy = ima_root / "policy"
        if policy.exists():
            text, error = _safe_read_small_text(policy)
            ima["policy"] = text
            if error:
                ima["policy_error"] = error
        for filename in ("runtime_measurements_count", "ascii_runtime_measurements", "binary_runtime_measurements"):
            path = ima_root / filename
            if path.exists():
                try:
                    st = path.stat()
                    ima[filename] = {"path": str(path), "size": st.st_size}
                    if filename == "runtime_measurements_count":
                        text, error = _safe_read_small_text(path, 4096)
                        ima[filename]["value"] = text.strip()
                        if error:
                            ima[filename]["error"] = error
                except OSError as exc:
                    ima[filename] = {"path": str(path), "error": str(exc)}
    result["ima"] = ima
    ipe_root = security / "ipe"
    ipe: dict[str, Any] = {"available": ipe_root.is_dir(), "policies": []}
    if ipe_root.is_dir():
        try:
            for policy_dir in sorted((item for item in ipe_root.iterdir() if item.is_dir()), key=lambda item: item.name):
                rec: dict[str, Any] = {"directory": policy_dir.name}
                for field in ("active", "name", "version"):
                    path = policy_dir / field
                    if path.exists():
                        rec[field] = _read_sysfs_value(path).get("value", "")
                ipe["policies"].append(rec)
        except OSError as exc:
            ipe["error"] = str(exc)
    result["ipe"] = ipe
    return result



def derive_kernel_enforcement_state(commands: dict[str, Any]) -> dict[str, Any]:
    lsm = str((commands.get("security_lsm") or {}).get("stdout") or "").strip()
    return {
        "active_lsms": [item.strip() for item in lsm.split(",") if item.strip()],
        "modules_disabled": str((commands.get("modules_disabled") or {}).get("stdout") or "").strip(),
        "kexec_load_disabled": str((commands.get("kexec_load_disabled") or {}).get("stdout") or "").strip(),
        "module_signature_enforcement": str((commands.get("module_sig_enforce") or {}).get("stdout") or "").strip(),
        "lockdown": str((commands.get("kernel_lockdown") or {}).get("stdout") or "").strip(),
    }


def _record_file(path: Path, *, capture_text: bool = False, max_hash_bytes: int = 256 * 1024 * 1024) -> dict[str, Any]:
    record: dict[str, Any] = {"path": str(path)}
    try:
        stat = path.lstat()
        record.update({
            "mode": oct(stat.st_mode & 0o7777),
            "uid": stat.st_uid,
            "gid": stat.st_gid,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "is_symlink": path.is_symlink(),
        })
        if path.is_symlink():
            record["target"] = os.readlink(path)
            record["sha256"] = hashlib.sha256(record["target"].encode("utf-8", errors="replace")).hexdigest()
            return record
        digest, error = sha256_file(path, max_bytes=max_hash_bytes)
        record["sha256"] = digest
        record["error"] = error
        if capture_text and error is None and stat.st_size <= 64 * 1024:
            record["text"] = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        record["error"] = str(exc)
    return record


def _iter_files(roots: list[Path], limit: int = 10000):
    seen: set[str] = set()
    count = 0
    for root in roots:
        if not root.exists():
            continue
        candidates = [root] if root.is_file() or root.is_symlink() else root.rglob("*")
        try:
            for path in candidates:
                key = str(path)
                if key in seen:
                    continue
                seen.add(key)
                try:
                    if not (path.is_file() or path.is_symlink()):
                        continue
                except OSError:
                    continue
                yield path
                count += 1
                if count >= limit:
                    return
        except OSError:
            continue


def collect_host_persistence_files() -> list[dict[str, Any]]:
    roots = [
        Path("/etc/systemd/system"), Path("/usr/local/lib/systemd/system"),
        Path("/etc/cron.d"), Path("/etc/cron.daily"), Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"), Path("/etc/cron.monthly"), Path("/var/spool/cron/crontabs"),
        Path("/etc/profile.d"), Path("/etc/modules-load.d"), Path("/etc/modprobe.d"),
        Path("/etc/ld.so.conf.d"), Path("/etc/crontab"), Path("/etc/rc.local"),
        Path("/etc/ld.so.preload"),
    ]
    return [
        _record_file(path, capture_text=(path == Path("/etc/ld.so.preload")))
        for path in _iter_files(roots, limit=10000)
    ]


def collect_host_executable_inventory() -> list[dict[str, Any]]:
    roots = [Path("/usr/local/bin"), Path("/usr/local/sbin"), Path("/opt"), Path("/tmp"), Path("/var/tmp"), Path("/dev/shm")]
    records: list[dict[str, Any]] = []
    hash_budget = 128 * 1024 * 1024
    hashed_bytes = 0
    for path in _iter_files(roots, limit=5000):
        try:
            stat = path.lstat()
            followed = path.stat() if path.is_symlink() else stat
        except OSError:
            continue
        if not path.is_symlink() and not (followed.st_mode & 0o111):
            continue
        record: dict[str, Any] = {
            "path": str(path),
            "mode": oct(stat.st_mode & 0o7777),
            "uid": stat.st_uid,
            "gid": stat.st_gid,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "is_symlink": path.is_symlink(),
            "temporary_path": str(path).startswith(("/tmp/", "/var/tmp/", "/dev/shm/")),
        }
        metadata = f"{record['path']}|{record['mode']}|{record['uid']}|{record['gid']}|{record['size']}|{record['mtime_ns']}"
        record["metadata_sha256"] = hashlib.sha256(metadata.encode("utf-8", errors="replace")).hexdigest()
        if path.is_symlink():
            try:
                record["target"] = os.readlink(path)
                record["sha256"] = hashlib.sha256(record["target"].encode("utf-8", errors="replace")).hexdigest()
            except OSError as exc:
                record["error"] = str(exc)
        elif stat.st_size <= 16 * 1024 * 1024 and hashed_bytes + stat.st_size <= hash_budget:
            digest, error = sha256_file(path, max_bytes=16 * 1024 * 1024)
            record["sha256"] = digest
            record["error"] = error
            if error is None:
                hashed_bytes += stat.st_size
        else:
            record["error"] = "content-hash-budget-or-size-limit"
        records.append(record)
    return records



def _dpkg_verify_path(line: str) -> tuple[str, bool] | None:
    """Return (path, conffile) for a dpkg --verify record."""
    text = line.rstrip()
    missing = re.match(r"^missing\s+(.+)$", text)
    if missing:
        return missing.group(1).strip(), False
    match = re.match(r"^(.{9})\s+(?:(c)\s+)?(.+)$", text)
    if not match:
        return None
    return match.group(3).strip(), bool(match.group(2))


def _security_relevant_package_path(path: str, mode: int | None = None) -> tuple[bool, str]:
    """Classify package drift by the object that can influence execution.

    Directories are never executable package content.  In particular, a
    missing or metadata-different /lib/modules/<kernel-version> directory must
    not be promoted to a kernel-code integrity alarm.  Under module trees we
    only elevate actual module objects and the small set of runtime metadata
    files that influence module loading.
    """
    lower = path.lower()
    name = Path(path).name.lower()

    if mode is not None and stat.S_ISDIR(mode):
        return False, "package directory"

    executable_prefixes = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/")
    module_prefixes = ("/lib/modules/", "/usr/lib/modules/")
    startup_policy_prefixes = (
        "/lib/systemd/system/",
        "/lib/systemd/system-generators/",
        "/lib/systemd/system-environment-generators/",
        "/usr/lib/systemd/system/",
        "/usr/lib/systemd/system-generators/",
        "/usr/lib/systemd/system-environment-generators/",
        "/usr/lib/udev/rules.d/",
        "/usr/lib/sysusers.d/",
        "/usr/lib/tmpfiles.d/",
        "/usr/share/dbus-1/system-services/",
        "/usr/share/dbus-1/services/",
        "/usr/share/polkit-1/rules.d/",
    )

    if path.startswith(executable_prefixes):
        return True, "program executable"

    if path.startswith(module_prefixes):
        if re.search(r"\.ko(?:\.(?:xz|gz|zst))?$", lower):
            return True, "kernel module"
        if name in {
            "modules.dep", "modules.dep.bin", "modules.alias", "modules.alias.bin",
            "modules.softdep", "modules.symbols", "modules.symbols.bin",
            "modules.builtin", "modules.builtin.bin", "modules.builtin.modinfo",
            "modules.order", "modules.devname",
        }:
            return True, "kernel module loading metadata"
        return False, "kernel package directory or non-runtime metadata"

    if path.startswith(startup_policy_prefixes):
        return True, "startup, service-activation, device-policy, or privilege-policy object"

    if path.startswith(("/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/")):
        if "/security/" in lower or "/pam_" in lower:
            return True, "authentication module"
        if lower.endswith((".so", ".efi")) or ".so." in lower:
            return True, "library or firmware code"
        if any(token in lower for token in ("/python", "/perl", "/ruby", "/node_modules/")):
            return True, "runtime/library code"

    if path.startswith("/boot/"):
        # Existing directories have already been rejected above.  For missing
        # objects, require a file-like basename rather than flagging /boot/grub
        # or another directory merely because it lives under /boot.
        if mode is not None or name.startswith(("vmlinuz", "initrd", "initramfs", "system.map", "config-")) or "." in name:
            return True, "boot component"
        return False, "boot directory"

    if mode is not None and not stat.S_ISDIR(mode) and mode & 0o111 and path.startswith(("/usr/", "/lib/", "/opt/")):
        return True, "executable package file"

    return False, "non-executable package data"


def _dpkg_diversion_paths(output: str) -> set[str]:
    """Parse exact original/diverted paths from dpkg-divert --list output."""
    paths: set[str] = set()
    pattern = re.compile(r"^(?:local )?diversion of (.+?) to (.+?)(?: by package .+)?$")
    for raw in output.splitlines():
        match = pattern.match(raw.strip())
        if match:
            paths.add(match.group(1))
            paths.add(match.group(2))
    return paths


def _dpkg_statoverride_paths(output: str) -> set[str]:
    """Parse exact paths from dpkg-statoverride --list output."""
    paths: set[str] = set()
    for raw in output.splitlines():
        parts = raw.strip().split(None, 3)
        if len(parts) == 4 and parts[3].startswith("/"):
            paths.add(parts[3])
    return paths


def collect_dpkg_verify_analysis(commands: dict[str, Any]) -> dict[str, Any]:
    """Enrich dpkg --verify drift with file role and local SHA-256 evidence.

    This remains drift detection. It does not claim that a changed file is malicious
    and it does not replace verification against a trusted package repository.
    """
    output = str((commands.get("dpkg_verify") or {}).get("stdout") or "")
    diversion_output = str((commands.get("dpkg_diversions") or {}).get("stdout") or "")
    statoverride_output = str((commands.get("dpkg_statoverrides") or {}).get("stdout") or "")
    diversions = _dpkg_diversion_paths(diversion_output)
    statoverrides = _dpkg_statoverride_paths(statoverride_output)
    ignored_prefixes = (
        "/usr/share/doc/", "/usr/share/man/", "/usr/share/locale/", "/usr/share/lintian/",
        "/usr/share/info/", "/usr/share/icons/", "/usr/share/help/",
        "/var/lib/apt/lists/", "/var/cache/", "/run/", "/tmp/", "/var/tmp/",
    )
    records: list[dict[str, Any]] = []
    counters = {"configuration": 0, "ignored": 0, "security_relevant": 0, "other_drift": 0, "unparsed": 0}
    for line in [line.rstrip() for line in output.splitlines() if line.strip()]:
        parsed = _dpkg_verify_path(line)
        if not parsed:
            counters["unparsed"] += 1
            records.append({"raw": line, "classification": "unparsed", "security_relevant": False})
            continue
        path_text, conffile = parsed
        classification = "other_drift"
        reason = "package-owned file differs from local package metadata"
        security_relevant = False
        if conffile:
            classification = "configuration"
            reason = "locally modifiable package configuration"
        elif path_text.startswith(ignored_prefixes):
            classification = "ignored"
            reason = "documentation/cache/temporary path"
        elif path_text in diversions or path_text in statoverrides:
            classification = "ignored"
            reason = "exact registered package diversion or metadata override"

        record: dict[str, Any] = {
            "path": path_text,
            "raw": line,
            "conffile": conffile,
            "classification": classification,
            "security_relevant": False,
            "reason": reason,
        }
        package_owner = _dpkg_owner_for_path(path_text)
        if package_owner:
            record["package_owner"] = package_owner
        path = Path(path_text)
        if classification == "other_drift":
            try:
                st = path.lstat()
                if stat.S_ISDIR(st.st_mode):
                    file_type = "directory"
                elif stat.S_ISREG(st.st_mode):
                    file_type = "regular"
                elif stat.S_ISLNK(st.st_mode):
                    file_type = "symlink"
                else:
                    file_type = "other"
                record.update({
                    "exists": True,
                    "mode": oct(st.st_mode & 0o7777),
                    "uid": st.st_uid,
                    "gid": st.st_gid,
                    "size": st.st_size,
                    "is_symlink": path.is_symlink(),
                    "file_type": file_type,
                })
                security_relevant, role = _security_relevant_package_path(path_text, st.st_mode)
                record["file_role"] = role
                record["security_relevant"] = security_relevant
                if file_type == "directory":
                    classification = "ignored"
                    record["classification"] = classification
                    record["reason"] = "package directory metadata is not executable content"
                elif security_relevant:
                    classification = "security_relevant"
                    record["classification"] = classification
                    record["reason"] = f"modified {role}"
                if path.is_file() and not path.is_symlink() and st.st_size <= 256 * 1024 * 1024:
                    digest, error = sha256_file(path, max_bytes=256 * 1024 * 1024)
                    record["sha256"] = digest
                    if error:
                        record["hash_error"] = error
            except OSError as exc:
                record["exists"] = False
                record["stat_error"] = str(exc)
                # A missing executable/library is still operationally meaningful.
                security_relevant, role = _security_relevant_package_path(path_text)
                record["file_role"] = role
                record["security_relevant"] = security_relevant
                if security_relevant:
                    classification = "security_relevant"
                    record["classification"] = classification
                    record["reason"] = f"missing {role}"
                elif path_text.startswith(("/lib/modules/", "/usr/lib/modules/")):
                    classification = "ignored"
                    record["classification"] = classification
                    record["reason"] = "missing kernel package directory or non-runtime metadata"
        counters[record["classification"]] = counters.get(record["classification"], 0) + 1
        records.append(record)

    verify_status = str((commands.get("dpkg_verify") or {}).get("status") or "")
    return {
        "backend": "dpkg",
        "available": verify_status in {"collected", "collected_empty"},
        "source": "dpkg --verify plus local file metadata",
        "interpretation": "drift-detection-only",
        "counts": counters,
        "records": records[:1000],
        "truncated": len(records) > 1000,
    }


def collect_initramfs_hashes(boot_hashes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for item in boot_hashes:
        name = Path(str(item.get("path") or "")).name.lower()
        if name.startswith(("initrd", "initramfs")):
            result.append(dict(item))
    return result


def canonical_hash(report: dict[str, Any]) -> str:
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def collect(report_dir: Path, requested_areas: list[str] | None = None, *, profile: str = "") -> Path:
    if os.geteuid() != 0:
        raise PermissionError("The scanner must run as root to obtain complete firmware evidence")

    requested_areas = list(requested_areas or SECTION_ORDER)
    unknown = [area for area in requested_areas if area not in SECTION_ORDER]
    if unknown:
        raise ValueError(f"Unknown scan area(s): {', '.join(unknown)}")
    if not requested_areas:
        raise ValueError("At least one scan area must be selected")

    # Canonicalize ordering so reports compare cleanly regardless of CLI order.
    requested_set = set(requested_areas)
    requested_areas = [slug for slug in SECTION_ORDER if slug in requested_set]
    profile = _profile_name(requested_areas, profile)

    report_dir.mkdir(mode=0o2750, parents=True, exist_ok=True)
    lock_path = Path("/run/firmware-audit/scan.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    status = CollectionStatus()

    with lock_path.open("w") as lock_handle:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another firmware audit scan is already running") from exc

        status.start()
        try:
            generated = datetime.now(timezone.utc)
            hostname = socket.gethostname()
            safe_host = re.sub(r"[^A-Za-z0-9_.-]", "_", hostname)[:80] or "host"
            report_id = f"{generated.strftime('%Y%m%dT%H%M%S.%fZ')}-{safe_host}"
            scanner_version = Path(__file__).with_name("VERSION").read_text(encoding="utf-8").strip()
            system_context = collect_system_context(hostname)

            virtualization_kind = _detect_virtualization_kind()
            specs, requested_by_command = command_plan(
                requested_areas,
                cpu_vendor=_cpu_vendor_id(),
                virtualization_kind=virtualization_kind,
            )
            commands: dict[str, Any] = {}
            total_commands = max(1, len(specs))
            for index, spec in enumerate(specs, start=1):
                owners = requested_by_command.get(spec.name) or [spec.section or section_for_command(spec.name)]
                owner = next((area for area in requested_areas if area in owners), owners[0])
                title, message = COLLECTION_AREAS[owner]
                status.area(title, message, round((index - 1) * 58 / total_commands))
                commands[spec.name] = run_command(spec)
                commands[spec.name]["requested_by_areas"] = owners

            artifacts: dict[str, Any] = {
                "uefi_mode": Path("/sys/firmware/efi").is_dir(),
            }

            def requested(*areas: str) -> bool:
                return any(area in requested_set for area in areas)

            # Storage mapping expansion is only useful for the storage/memory area.
            if requested("storage-memory"):
                title, message = COLLECTION_AREAS["storage-memory"]
                status.area(title, "Confirming encryption mappings and active swap", 61)
                collect_crypt_mappings(commands.get("lsblk_json", {}), commands)

            tpm_eventlog: dict[str, Any] = {}
            if requested("tpm-measured-boot", "firmware-baseline"):
                title, _ = COLLECTION_AREAS["tpm-measured-boot"]
                status.area(title, "Reading the measured-boot event log", 65)
                tpm_eventlog = collect_tpm_eventlog(commands)
                if "tpm_eventlog" in commands:
                    commands["tpm_eventlog"]["requested_by_areas"] = [area for area in requested_areas if area in {"tpm-measured-boot", "firmware-baseline"}]
                artifacts["tpm_devices"] = sorted(str(path) for path in Path("/dev").glob("tpm*"))
                artifacts["tpm_eventlog"] = tpm_eventlog
                artifacts["tpm_eventlog_replay"] = derive_tpm_eventlog_replay(commands, tpm_eventlog)

            boot_file_hashes: list[dict[str, Any]] = []
            if requested("firmware-baseline", "secure-boot", "host-integrity"):
                owner = next(area for area in requested_areas if area in {"firmware-baseline", "secure-boot", "host-integrity"})
                title, _ = COLLECTION_AREAS[owner]
                status.area(title, "Hashing startup files and initramfs images", 69)
                boot_file_hashes = collect_file_hashes()
                artifacts["boot_file_hashes"] = boot_file_hashes

            taint_value = 0
            if requested("kernel-runtime"):
                try:
                    taint_value = int(commands.get("kernel_taint", {}).get("stdout", "0").strip())
                except ValueError:
                    pass
                artifacts["kernel_taint"] = {"value": taint_value, "decoded": decode_taint(taint_value)}

            # Build the internal scanner model.  This shape is deliberately not
            # the public report contract; assessment.py can evolve independently.
            internal: dict[str, Any] = {
                "schema_version": 16,
                "report_id": report_id,
                "generated_at": generated.isoformat(),
                "collector": {"name": "firmware-audit-scanner", "version": scanner_version},
                "host": {"hostname": hostname},
                "system": system_context,
                "commands": commands,
                "artifacts": artifacts,
            }

            if requested("identity", "firmware-baseline"):
                owner = "identity" if requested("identity") else "firmware-baseline"
                title, _ = COLLECTION_AREAS[owner]
                status.area(title, "Reading firmware runtime tables", 73)
                artifacts["firmware_runtime_hashes"] = collect_firmware_runtime_hashes()

            if requested("firmware-baseline", "secure-boot"):
                owner = "firmware-baseline" if requested("firmware-baseline") else "secure-boot"
                title, _ = COLLECTION_AREAS[owner]
                status.area(title, "Reading EFI variables", 76)
                artifacts["efi_variables"] = collect_efivars()

            if requested("firmware-protection", "out-of-band-management", "memory-protection"):
                owner = next(area for area in requested_areas if area in {"firmware-protection", "out-of-band-management", "memory-protection"})
                title, _ = COLLECTION_AREAS[owner]
                status.area(title, "Reading firmware-exposed security settings", 78)
                artifacts["firmware_attributes"] = collect_firmware_attributes()

            if requested("secure-boot", "updates", "firmware-protection"):
                owner = next(area for area in requested_areas if area in {"secure-boot", "updates", "firmware-protection"})
                title, _ = COLLECTION_AREAS[owner]
                status.area(title, "Reading firmware update table metadata", 80)
                artifacts["esrt_entries"] = collect_esrt_entries()

            if requested("host-integrity"):
                title, _ = COLLECTION_AREAS["host-integrity"]
                status.area(title, "Inventorying startup mechanisms and privileged executables", 82)
                artifacts.update({
                    "initramfs_hashes": collect_initramfs_hashes(boot_file_hashes),
                    "host_persistence_files": collect_host_persistence_files(),
                    "host_executable_inventory": collect_host_executable_inventory(),
                    "package_verify_analysis": collect_dpkg_verify_analysis(commands),
                })

            if requested("kernel-runtime"):
                title, _ = COLLECTION_AREAS["kernel-runtime"]
                status.area(title, "Collecting module and runtime-isolation metadata", 86)
                artifacts.update({
                    "cpu_vulnerabilities": collect_cpu_vulnerabilities(),
                    "integrity_frameworks": collect_integrity_frameworks(),
                    "kernel_enforcement_state": derive_kernel_enforcement_state(commands),
                    "loaded_module_metadata": collect_module_metadata(),
                })

            if requested("storage-memory"):
                title, _ = COLLECTION_AREAS["storage-memory"]
                status.area(title, "Collecting DMA and external-device isolation metadata", 88)
                artifacts.update({
                    "iommu_groups": collect_iommu_groups(),
                    "thunderbolt_security": collect_thunderbolt_security(),
                })

            platform_security: dict[str, Any] = {}
            if requested("platform-security-processor", "memory-protection"):
                owner = "platform-security-processor" if requested("platform-security-processor") else "memory-protection"
                title, _ = COLLECTION_AREAS[owner]
                status.area(title, "Interpreting platform security-processor evidence", 90)
                platform_security = collect_platform_security_processors(commands)
                artifacts["platform_security_processors"] = platform_security

            if requested("out-of-band-management"):
                title, _ = COLLECTION_AREAS["out-of-band-management"]
                status.area(title, "Interpreting local management-controller evidence", 91)
                artifacts["out_of_band_management"] = collect_out_of_band_management(
                    commands, firmware_attributes=artifacts.get("firmware_attributes") or []
                )

            if requested("memory-protection"):
                title, _ = COLLECTION_AREAS["memory-protection"]
                status.area(title, "Interpreting hardware memory protection", 92)
                artifacts["memory_protection"] = collect_memory_protection(
                    commands,
                    platform_security=platform_security,
                    firmware_attributes=artifacts.get("firmware_attributes") or [],
                )

            if requested("storage-memory"):
                title, _ = COLLECTION_AREAS["storage-memory"]
                status.area(title, "Building the active storage and swap protection result", 93)
                artifacts["swap_topology"] = derive_swap_topology(internal)

            # Platform profile is cheap and provides useful interpretation context
            # in every report, including partial scans.
            artifacts["platform_profile"] = detect_platform_profile(internal)
            if requested("platform-security-processor"):
                artifacts["amd_secure_processor_state"] = derive_amd_secure_processor_state(internal)
            if requested("firmware-protection"):
                artifacts["conventional_uefi_collection"] = build_conventional_uefi_collection(internal)

            status.area("Assessment", "Interpreting the selected evidence", 96)
            assessment = assess(internal)

            status.area("Saving snapshot", "Writing the immutable scan report", 98)
            timing = status.timing_snapshot()
            public_report = build_report(
                report_id=report_id,
                created_at=generated.isoformat(),
                scanner_version=scanner_version,
                profile=profile,
                requested_areas=requested_areas,
                all_areas=list(SECTION_ORDER),
                system=system_context,
                timing=timing,
                assessment=assessment,
                commands=commands,
                artifacts=artifacts,
            )
            public_report["integrity"] = {
                "algorithm": "sha256",
                "scope": "canonical JSON excluding this integrity object",
                "digest": canonical_hash(public_report),
            }

            archive_target = report_dir / f"{report_id}.json"
            current_target = report_dir / "current.json"
            encoded = json.dumps(public_report, indent=2, ensure_ascii=False, sort_keys=True) + "\n"

            for target in (archive_target, current_target):
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=report_dir, delete=False) as handle:
                    handle.write(encoded)
                    temp_path = Path(handle.name)
                os.chmod(temp_path, 0o640)
                os.replace(temp_path, target)

            status.complete(report_id)
            return archive_target
        except Exception:
            status.fail()
            raise

def main() -> int:
    parser = argparse.ArgumentParser(description="Collect and assess firmware security evidence")
    parser.add_argument(
        "--report-dir",
        type=Path,
        default=DEFAULT_REPORT_DIR,
        help="Report output directory",
    )
    parser.add_argument("--profile", choices=sorted(PROFILES), default="", help="Named scan profile")
    parser.add_argument("--area", action="append", default=[], choices=SECTION_ORDER, help="Scan one area; repeat to select more")
    parser.add_argument("--areas", default="", help="Comma-separated scan areas")
    parser.add_argument("--list-areas", action="store_true", help="List selectable scan areas and exit")
    parser.add_argument("--list-profiles", action="store_true", help="List named scan profiles and exit")
    args = parser.parse_args()

    if args.list_areas:
        for slug in SECTION_ORDER:
            print(f"{slug}\t{SECTIONS[slug]['title']}")
        return 0
    if args.list_profiles:
        for name, areas in PROFILES.items():
            print(f"{name}\t{','.join(areas)}")
        return 0

    selected: list[str] = []
    if args.profile:
        selected.extend(PROFILES[args.profile])
    selected.extend(args.area)
    if args.areas:
        selected.extend(part.strip() for part in args.areas.split(",") if part.strip())
    if not selected:
        selected = list(PROFILES["full"])
        profile = "full"
    else:
        unknown = [area for area in selected if area not in SECTION_ORDER]
        if unknown:
            parser.error(f"unknown scan area(s): {', '.join(unknown)}")
        selected_set = set(selected)
        selected = [slug for slug in SECTION_ORDER if slug in selected_set]
        profile = args.profile or ""

    try:
        path = collect(args.report_dir, selected, profile=profile)
    except Exception as exc:  # noqa: BLE001 - CLI must return a useful error
        print(f"firmware-audit scanner failed: {exc}", file=os.sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
