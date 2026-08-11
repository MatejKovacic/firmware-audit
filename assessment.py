"""Rule-based assessment for Linux firmware-audit reports.

The assessor separates integrity indicators from protection weaknesses,
exposure, maintenance, compatibility, and ordinary diagnostic conditions.
It never claims that a host is conclusively clean.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Iterable

from sections import CATEGORY_TO_SECTION, SECTION_ORDER, SECTIONS


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ACTIONABLE_TYPES = {
    "integrity-indicator",
    "protection-weakness",
    "data-exposure",
    "maintenance-issue",
}
UEFI_COMMANDS = {
    "secure_boot_state",
    "mok_pk",
    "mok_kek",
    "mok_db",
    "mok_dbx",
    "mok_enrolled",
    "efibootmgr",
    "bootctl",
}
UEFI_ARTIFACTS = {"efi_variables"}
HOST_INTEGRITY_COMMANDS = {"dpkg_verify", "dpkg_package_inventory", "dpkg_diversions", "dpkg_statoverrides", "systemd_service_files", "systemd_timer_files", "systemd_running_services", "systemd_timers", "suid_sgid_files", "aide_check"}
HOST_INTEGRITY_ARTIFACTS = {"host_persistence_files", "host_executable_inventory", "initramfs_hashes", "package_verify_analysis"}

def _kernel_release_version_key(value: str) -> tuple[int, ...] | None:
    """Return the numeric Linux/ABI prefix without treating kernel flavor names as versions."""
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-(\d+))?", str(value or "").strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups() if part is not None)


def _newer_installed_kernel(report: dict[str, Any]) -> tuple[str, str] | None:
    """Return (running, newest-installed) when a strictly newer installed kernel is available locally."""
    system = report.get("system") if isinstance(report.get("system"), dict) else {}
    kernel = system.get("kernel") if isinstance(system.get("kernel"), dict) else {}
    running = str(kernel.get("running_release") or "").strip()
    installed = [str(item).strip() for item in (kernel.get("installed_releases") or []) if str(item).strip()]
    running_key = _kernel_release_version_key(running)
    if not running or running_key is None or not installed:
        return None
    candidates = [(item, _kernel_release_version_key(item)) for item in installed]
    newer = [(item, key) for item, key in candidates if key is not None and key > running_key]
    if not newer:
        return None
    newest, _ = max(newer, key=lambda pair: pair[1])
    return running, newest


FWUPD_LABELS = {
    "org.fwupd.hsi.Fwupd.Plugins": "fwupd plugin integrity",
    "org.fwupd.hsi.Kernel.Lockdown": "Kernel lockdown",
    "org.fwupd.hsi.Kernel.Swap": "Swap encryption",
    "org.fwupd.hsi.Kernel.Tainted": "Kernel taint",
    "org.fwupd.hsi.Uefi.Db": "UEFI signature database",
    "org.fwupd.hsi.Uefi.Pk": "UEFI Platform Key",
    "org.fwupd.hsi.Uefi.SecureBoot": "UEFI Secure Boot",
    "org.fwupd.hsi.Uefi.BootserviceVars": "UEFI boot-service variables",
    "org.fwupd.hsi.Amd.SpiWriteProtection": "AMD SPI write protection",
    "org.fwupd.hsi.Amd.SpiReplayProtection": "AMD SPI replay protection",
    "org.fwupd.hsi.Spi.Ble": "SPI controller lock",
    "org.fwupd.hsi.Spi.Bioswe": "SPI BIOS write enable",
    "org.fwupd.hsi.Spi.SmmBwp": "SPI SMM BIOS write protection",
    "org.fwupd.hsi.Bios.RollbackProtection": "BIOS rollback protection",
    "org.fwupd.hsi.Amd.RollbackProtection": "AMD Secure Processor rollback protection",
    "org.fwupd.hsi.Amd.PlatformRollbackProtection": "AMD Secure Processor rollback protection",
    "org.fwupd.hsi.Amd.PlatformSecureBoot": "AMD Platform Secure Boot",
    "org.fwupd.hsi.Mei.ManufacturingMode": "Intel ME/CSME manufacturing mode",
    "org.fwupd.hsi.Mei.Version": "Intel ME/CSME firmware version",
    "org.fwupd.hsi.IntelBootguard.Acm": "Intel BootGuard ACM protection",
    "org.fwupd.hsi.IntelBootguard.Verified": "Intel BootGuard verified boot",
    "org.fwupd.hsi.IntelBootguard.Policy": "Intel BootGuard error policy",
    "org.fwupd.hsi.PlatformDebugLocked": "Platform debug lock",
    "org.fwupd.hsi.PlatformDebugEnabled": "Platform debugging",
    "org.fwupd.hsi.Iommu": "IOMMU",
    "org.fwupd.hsi.PrebootDma": "Pre-boot DMA protection",
    "org.fwupd.hsi.SuspendToIdle": "Suspend-to-idle",
    "org.fwupd.hsi.SuspendToRam": "Suspend-to-RAM",
    "org.fwupd.hsi.EncryptedRam": "Encrypted RAM",
    "org.fwupd.hsi.Tpm.ReconstructionPcr0": "TPM PCR0 reconstruction",
    "org.fwupd.hsi.Tpm.EmptyPcr": "TPM empty-PCR check",
    "org.fwupd.hsi.Tpm.Version20": "TPM 2.0",
    "org.fwupd.hsi.Cet.Active": "CET operating-system support",
    "org.fwupd.hsi.Cet.Enabled": "CET platform support",
    "org.fwupd.hsi.Smap": "SMAP",
}


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    category: str
    summary: str
    recommendation: str
    evidence: list[str]
    confidence: str = "medium"
    compromise_indicator: bool = False
    detailed: str = ""
    technical: str = ""
    section: str = ""
    finding_type: str = ""
    evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        section = self.section or CATEGORY_TO_SECTION.get(self.category, "firmware-baseline")
        finding_type = self.finding_type or _finding_type(self.category, self.compromise_indicator)
        evidence_ids = self.evidence_ids or _default_evidence_ids(self.finding_id, section)
        detailed = self.detailed
        technical = self.technical or (
            "Interpretation is based on the following collected evidence: "
            + "; ".join(self.evidence)
            + "."
        )
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "section": section,
            "finding_type": finding_type,
            "simple": self.summary,
            "summary": self.summary,
            "detailed": detailed,
            "technical": technical,
            "recommendation": self.recommendation,
            "evidence": list(self.evidence),
            "evidence_ids": list(evidence_ids),
            "evidence_strength": self.confidence,
            "compromise_indicator": self.compromise_indicator,
        }


def _finding_type(category: str, compromise_indicator: bool) -> str:
    if compromise_indicator or category in {"trust-store", "integrity-signal", "evidence-integrity"}:
        return "integrity-indicator"
    if category in {"firmware-protection", "boot-protection", "host-security", "platform-security-processor"}:
        return "protection-weakness"
    if category in {"data-protection", "physical-security", "memory-protection"}:
        return "data-exposure"
    if category == "maintenance":
        return "maintenance-issue"
    if category == "compatibility":
        return "compatibility-issue"
    if category == "reliability":
        return "reliability-issue"
    if category in {"visibility", "measured-boot", "scope"}:
        return "unknown"
    if category == "changes":
        return "expected-change"
    return "informational"


def _default_evidence_ids(finding_id: str, section: str) -> list[str]:
    explicit = {
        "spi-write-protection": ["fwupd_security_json", "fwupd_security_text"],
        "secure-boot-disabled": ["secure_boot_state", "bootctl", "kernel_journal"],
        "secure-boot-unknown": ["secure_boot_state"],
        "legacy-boot": ["artifact:platform_profile", "artifact:uefi_mode"],
        "heads-platform": ["dmidecode_bios", "dmidecode_full", "tpm_eventlog"],
        "heads-boot-model": ["dmidecode_bios", "tpm_eventlog", "tpm_pcrs", "artifact:boot_file_hashes"],
        "kernel-tainted": ["kernel_taint", "kernel_journal", "artifact:loaded_module_metadata"],
        "kernel-external-module-state": ["kernel_taint", "artifact:loaded_module_metadata"],
        "kernel-unsigned-module": ["kernel_taint", "artifact:loaded_module_metadata"],
        "kernel-warning-state": ["kernel_taint", "kernel_journal"],
        "kernel-diagnostic-state": ["kernel_taint", "kernel_journal"],
        "amd-ccp-unavailable": ["kernel_journal", "lspci_verbose"],
        "intel-me-manufacturing-mode": ["fwupd_security_json", "artifact:platform_security_processors"],
        "intel-csme-firmware-policy": ["fwupd_security_json", "fwupd_security_text", "artifact:platform_security_processors"],
        "intel-bootguard-policy": ["fwupd_security_json", "fwupd_security_text"],
        "amd-psp-security-controls": ["fwupd_security_json", "artifact:platform_security_processors"],
        "amd-platform-secure-boot": ["fwupd_security_json", "artifact:platform_security_processors"],
        "amd-platform-rollback-protection": ["fwupd_security_json", "artifact:platform_security_processors"],
        "oob-management-provisioned": ["fwupd_devices_json", "dmidecode_mchi", "artifact:out_of_band_management"],
        "oob-dash-enabled": ["kernel_journal", "artifact:firmware_attributes", "artifact:out_of_band_management"],
        "firmware-persistence-enabled": ["artifact:firmware_attributes", "artifact:out_of_band_management"],
        "memory-encryption-not-active": ["fwupd_security_json", "artifact:memory_protection"],
        "swap-unencrypted": ["lsblk_json", "swapon_text", "dmsetup_tree"],
        "swap-fwupd-overridden": ["fwupd_security_json", "lsblk_json", "dmsetup_tree"],
        "tpm-eventlog-replay-mismatch": ["tpm_pcrs", "tpm_eventlog", "artifact:tpm_eventlog_replay"],
        "boot-trust-inconsistent": ["secure_boot_state", "bootctl", "kernel_lockdown", "fwupd_security_json"],
        "cpu-vulnerability-unmitigated": ["artifact:cpu_vulnerabilities", "proc_cmdline"],
        "security-boot-parameter": ["proc_cmdline", "artifact:cpu_vulnerabilities", "artifact:thunderbolt_security"],
        "thunderbolt-dma-exposure": ["artifact:thunderbolt_security", "iommu_kernel_log", "artifact:iommu_groups"],
        "tpm-not-observed": ["tpm_properties", "artifact:tpm_devices"],
        "firmware-updates-available": ["fwupd_updates_json", "fwupd_devices_json"],
        "heads-update-unverified": ["dmidecode_bios", "fwupd_updates_json", "fwupd_devices_json"],
        "boot-signature-failure": ["kernel_journal", "secure_boot_state"],
        "uefi-platform-key-invalid": ["mok_pk", "fwupd_security_json"],
        "uefi-db-invalid": ["mok_db", "fwupd_security_json"],
        "package-files-modified": ["dpkg_verify", "dpkg_package_inventory", "dpkg_diversions", "dpkg_statoverrides"],
        "dynamic-loader-preload": ["artifact:host_persistence_files"],
        "aide-differences": ["aide_check"],
        "incomplete-scan": [],
    }
    if finding_id in explicit:
        return explicit[finding_id]
    definition = SECTIONS.get(section, {})
    commands = list(definition.get("commands", []))[:3]
    artifacts = [f"artifact:{name}" for name in definition.get("artifacts", [])[:2]]
    return commands + artifacts


def _command(report: dict[str, Any], name: str) -> dict[str, Any]:
    return report.get("commands", {}).get(name, {}) or {}


def _stdout(report: dict[str, Any], name: str) -> str:
    value = _command(report, name).get("stdout", "")
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _combined(report: dict[str, Any], name: str) -> str:
    item = _command(report, name)
    return f"{item.get('stdout', '')}\n{item.get('stderr', '')}".strip()


def _parse_json_output(report: dict[str, Any], name: str) -> Any | None:
    text = _stdout(report, name).strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _walk_json(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def decode_taint(value: int) -> list[dict[str, Any]]:
    meanings = {
        0: ("proprietary-module", "A proprietary module was loaded"),
        1: ("forced-module", "A module was force-loaded"),
        2: ("unsafe-smp", "Kernel is running on hardware considered unsafe for SMP"),
        3: ("forced-unload", "A module was force-unloaded"),
        4: ("machine-check", "A machine-check exception occurred"),
        5: ("bad-page", "A bad page was detected"),
        6: ("user-requested", "Taint was explicitly requested by userspace"),
        7: ("kernel-oops", "The kernel recently recorded an oops or bug"),
        8: ("acpi-override", "An ACPI table was overridden by the user"),
        9: ("kernel-warning", "The kernel issued a warning"),
        10: ("staging-driver", "A staging driver was loaded"),
        11: ("firmware-workaround", "A platform firmware workaround was applied"),
        12: ("out-of-tree", "An externally built module was loaded"),
        13: ("unsigned-module", "An unsigned module was loaded"),
        14: ("soft-lockup", "A soft lockup occurred"),
        15: ("live-patched", "The kernel was live-patched"),
        16: ("auxiliary", "An auxiliary taint condition was recorded"),
        17: ("randstruct", "The kernel was built with structure randomization"),
        18: ("in-kernel-test", "An in-kernel test was run"),
        19: ("fwctl-debug-write", "Userspace performed a mutating fwctl debug operation"),
    }
    return [
        {"bit": bit, "code": code, "text": text}
        for bit, (code, text) in meanings.items()
        if value & (1 << bit)
    ]


def _platform_boot_paths(report: dict[str, Any]) -> set[str]:
    artifacts = report.get("artifacts", {}) or {}
    paths: set[str] = set()
    for item in artifacts.get("boot_file_hashes", []) or []:
        if isinstance(item, dict):
            path = str(item.get("path") or "").strip()
            if path:
                paths.add(path)
    markers = artifacts.get("platform_boot_markers")
    if isinstance(markers, dict):
        for raw in markers.get("existing_paths", []) or []:
            path = str(raw or "").strip()
            if path:
                paths.add(path)
    return paths


def _platform_signal_summary(report: dict[str, Any]) -> dict[str, Any]:
    """Normalize platform evidence into independent, explainable dimensions.

    Detection deliberately uses technology-level signals rather than machine-model
    allow-lists. A profile is derived from virtualization, firmware-family,
    boot-interface and boot-trust evidence so one missing product string does not
    cascade into unrelated UEFI/legacy conclusions.
    """
    system = report.get("system") if isinstance(report.get("system"), dict) else {}
    hardware = system.get("hardware") if isinstance(system.get("hardware"), dict) else {}
    system_text = "\n".join(str(hardware.get(key) or "") for key in (
        "system_vendor", "product_name", "product_version", "board_vendor", "board_name",
        "bios_vendor", "bios_version", "bios_date",
    ))
    dmi_text = "\n".join([
        system_text,
        *(_combined(report, name) for name in ("dmidecode_bios", "dmidecode_full", "dmidecode_system")),
    ]).lower()
    tpm_text = _combined(report, "tpm_eventlog").lower()
    boot_paths = _platform_boot_paths(report)
    artifacts = report.get("artifacts", {}) or {}
    virt = _stdout(report, "systemd_detect_virt").strip().lower()
    if not virt:
        virt = str(artifacts.get("virtualization_kind") or "").strip().lower()
    uefi = bool(artifacts.get("uefi_mode"))

    signals: list[dict[str, str]] = []

    def signal(signal_id: str, dimension: str, evidence: str) -> None:
        if signal_id not in {item["id"] for item in signals}:
            signals.append({"id": signal_id, "dimension": dimension, "evidence": evidence})

    coreboot_score = 0
    if "coreboot" in dmi_text:
        coreboot_score += 4
        signal("dmi-coreboot", "firmware-family", "SMBIOS/DMI contains coreboot")
    # Dasharo is a coreboot distribution/firmware-family marker. It is used as
    # technology evidence, not as a machine-model allow-list.
    if "dasharo" in dmi_text:
        coreboot_score += 3
        signal("dmi-dasharo", "firmware-family", "SMBIOS/DMI identifies Dasharo firmware")
    textual_coreboot_measurements = (
        ("cbfs:" in tpm_text and "fmap:" in tpm_text)
        or ("cbfs" in tpm_text and "coreboot" in tpm_text)
    )
    encoded_coreboot_measurements = "43424653" in tpm_text and "464d4150" in tpm_text
    if textual_coreboot_measurements or encoded_coreboot_measurements:
        coreboot_score += 5
        signal("tpm-cbfs-fmap", "firmware-family", "TPM event log contains CBFS/FMAP coreboot measurements")

    heads_score = 0
    if "heads" in dmi_text or "heads" in tpm_text:
        heads_score += 6
        signal("explicit-heads", "boot-trust", "DMI or measured-boot evidence explicitly identifies Heads")

    # Heads installations expose a characteristic set of signed-kexec/HOTP
    # state files. Require several independent artifact families so a single
    # generic kexec file cannot classify a machine by itself.
    heads_groups = 0
    if any(path in boot_paths for path in {
        "/boot/kexec_hashes.txt", "/boot/kexec_default_hashes.txt", "/boot/kexec_primhdl_hash.txt",
    }):
        heads_groups += 1
        signal("heads-kexec-hashes", "boot-trust", "Heads-style kexec hash metadata is present")
    if "/boot/kexec.sig" in boot_paths:
        heads_groups += 1
        signal("heads-kexec-signature", "boot-trust", "Signed kexec metadata is present")
    if any(path in boot_paths for path in {"/boot/kexec_hotp_counter", "/boot/kexec_hotp_key"}):
        heads_groups += 1
        signal("heads-hotp-state", "boot-trust", "Heads-style HOTP state is present")
    if any(path in boot_paths for path in {
        "/boot/kexec_rollback.txt", "/boot/kexec_tree.txt", "/boot/kexec_default.1.txt",
    }):
        heads_groups += 1
        signal("heads-kexec-policy", "boot-trust", "Heads-style kexec policy metadata is present")
    if heads_groups >= 3:
        heads_score += 5

    legacy_loader = any(path.startswith("/boot/grub/i386-pc/") for path in boot_paths)
    if legacy_loader:
        signal("grub-pc-loader", "boot-interface", "GRUB i386-pc boot modules are present")

    if virt and virt != "none":
        signal("virtualization", "environment", f"systemd-detect-virt: {virt}")
    signal(
        "uefi-runtime" if uefi else "non-uefi-runtime",
        "boot-interface",
        "/sys/firmware/efi is present" if uefi else "UEFI runtime services are absent",
    )

    coreboot = coreboot_score >= 3 or heads_score >= 6
    heads = heads_score >= 6 or (coreboot and heads_groups >= 3)
    firmware_family = "coreboot" if coreboot else ("conventional-or-unknown" if uefi or legacy_loader else "unknown")
    if heads:
        boot_trust_model = "heads"
    elif uefi:
        boot_trust_model = "uefi"
    elif legacy_loader and not coreboot:
        boot_trust_model = "legacy"
    else:
        boot_trust_model = "unknown"

    return {
        "virtualization": virt or "unknown",
        "uefi_runtime": uefi,
        "firmware_family": firmware_family,
        "boot_trust_model": boot_trust_model,
        "coreboot_score": coreboot_score,
        "heads_score": heads_score,
        "legacy_loader_evidence": legacy_loader,
        "signals": signals,
    }


def detect_platform_profile(report: dict[str, Any]) -> dict[str, Any]:
    stored = report.get("artifacts", {}).get("platform_profile")
    if isinstance(stored, dict) and stored.get("kind"):
        return stored
    if isinstance(stored, str) and stored:
        return {"kind": stored, "confidence": "high", "evidence": ["stored platform profile"]}

    summary = _platform_signal_summary(report)
    virt = str(summary.get("virtualization") or "")
    uefi = bool(summary.get("uefi_runtime"))
    firmware_family = str(summary.get("firmware_family") or "unknown")
    trust = str(summary.get("boot_trust_model") or "unknown")
    signals = list(summary.get("signals") or [])
    evidence = [
        str(item.get("evidence"))
        for item in signals
        if isinstance(item, dict) and item.get("evidence")
    ]

    base = {
        "runtime_interface": "uefi" if uefi else "non-uefi",
        "firmware_family": firmware_family,
        "boot_trust_model": trust,
        "signals": signals,
    }

    # Virtualization is an orthogonal trust boundary and wins as the top-level
    # profile. Guest firmware/trust dimensions are retained for guest checks.
    if virt and virt not in {"none", "unknown"}:
        return {
            **base,
            "kind": "virtual-machine",
            "boot_mode": "uefi" if uefi else "legacy-bios",
            "confidence": "high",
            "evidence": evidence or [f"systemd-detect-virt: {virt}"],
        }
    if trust == "heads":
        return {
            **base,
            "kind": "coreboot-heads",
            "confidence": "high",
            "evidence": evidence or ["Independent coreboot/Heads evidence was detected"],
        }
    if firmware_family == "coreboot":
        return {
            **base,
            "kind": "coreboot",
            "confidence": "high" if int(summary.get("coreboot_score") or 0) >= 5 else "medium",
            "evidence": evidence or ["Coreboot-family evidence was detected"],
        }
    if uefi:
        return {
            **base,
            "kind": "uefi",
            "confidence": "high",
            "evidence": evidence or ["/sys/firmware/efi is present"],
        }
    if bool(summary.get("legacy_loader_evidence")):
        return {
            **base,
            "kind": "legacy-bios",
            "confidence": "high",
            "evidence": evidence,
        }
    return {
        **base,
        "kind": "non-uefi-unknown",
        "confidence": "low",
        "evidence": evidence or [
            "UEFI runtime services are absent and no alternative boot model was positively identified"
        ],
    }


def _is_heads(profile: dict[str, Any]) -> bool:
    return profile.get("kind") == "coreboot-heads" or profile.get("boot_trust_model") == "heads"


def _is_coreboot(profile: dict[str, Any]) -> bool:
    return profile.get("firmware_family") == "coreboot" or profile.get("kind") in {"coreboot", "coreboot-heads"}


def _is_vm(profile: dict[str, Any]) -> bool:
    return profile.get("kind") == "virtual-machine"


def _is_uefi_runtime(profile: dict[str, Any]) -> bool:
    if profile.get("runtime_interface"):
        return profile.get("runtime_interface") == "uefi"
    return profile.get("kind") == "uefi" or (_is_vm(profile) and profile.get("boot_mode") == "uefi")


def _uses_conventional_uefi_boot(profile: dict[str, Any]) -> bool:
    return _is_uefi_runtime(profile) and not _is_heads(profile)


def _is_physical_conventional_uefi(profile: dict[str, Any]) -> bool:
    return _uses_conventional_uefi_boot(profile) and not _is_vm(profile)


def _is_non_uefi_vm(profile: dict[str, Any]) -> bool:
    """Return true for a virtual-machine guest without UEFI runtime services."""
    return _is_vm(profile) and not _is_uefi_runtime(profile)


def _is_unclassified_non_uefi(profile: dict[str, Any]) -> bool:
    return profile.get("kind") == "non-uefi-unknown" or (
        _is_coreboot(profile) and not _is_heads(profile) and not _is_uefi_runtime(profile)
    )


def _command_state(report: dict[str, Any], name: str, profile: dict[str, Any]) -> str:
    if name in UEFI_COMMANDS and not _uses_conventional_uefi_boot(profile):
        return "not_applicable"
    if int(report.get("schema_version") or 0) < 5 and name in HOST_INTEGRITY_COMMANDS and name not in (report.get("commands", {}) or {}):
        return "not_applicable"
    item = _command(report, name)
    if not item:
        return "not_collected"
    status = str(item.get("status") or "")
    if status in {
        "collected",
        "collected_empty",
        "not_applicable",
        "not_available",
        "unsupported",
        "permission_denied",
        "failed",
        "timeout",
        "error",
    }:
        return status
    if status == "ok":
        return "collected" if _combined(report, name).strip() else "collected_empty"
    if status == "not_available":
        return "not_available"
    if status in {"timeout", "error"}:
        return status
    if status == "nonzero":
        text = _combined(report, name).lower()
        if "efi variables are not supported" in text or "doesn't support efi" in text or "not booted with efi" in text:
            return "not_applicable"
        if "unrecognized option" in text or "unknown option" in text or "invalid option" in text:
            return "unsupported"
        if "permission denied" in text or "operation not permitted" in text:
            return "permission_denied"
        if _stdout(report, name).strip():
            return "failed_with_output"
        return "failed"
    return status or "unknown"


def _available(report: dict[str, Any], name: str, profile: dict[str, Any] | None = None) -> bool:
    profile = profile or detect_platform_profile(report)
    return _command_state(report, name, profile) in {"collected", "collected_empty"}


def _fwupd_attributes(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Return current HSI attributes only, never historical SecurityEvents."""
    data = _parse_json_output(report, "fwupd_security_json")
    attrs: list[dict[str, Any]] = []
    if isinstance(data, dict) and isinstance(data.get("SecurityAttributes"), list):
        for obj in data["SecurityAttributes"]:
            if not isinstance(obj, dict):
                continue
            appstream_id = str(obj.get("AppstreamId") or obj.get("Id") or "")
            result = str(obj.get("HsiResult") or obj.get("Result") or obj.get("Status") or "")
            success_result = str(obj.get("HsiResultSuccess") or "")
            flags = [str(flag) for flag in (obj.get("Flags") or [])]
            passed = "success" in flags or bool(result and success_result and result == success_result)
            if passed:
                state = "pass"
            elif result == "not-supported" and not success_result:
                state = "not_applicable"
            elif success_result and result != success_result:
                state = "fail"
            elif "missing-data" in flags:
                state = "unknown"
            else:
                state = "unknown"
            attrs.append({
                "appstream_id": appstream_id,
                "name": FWUPD_LABELS.get(appstream_id, str(obj.get("Name") or appstream_id or "Unknown HSI attribute")),
                "reported_name": str(obj.get("Name") or ""),
                "result": result,
                "success_result": success_result,
                "flags": flags,
                "state": state,
                "uri": str(obj.get("Uri") or ""),
            })
        return attrs

    # Fallback for older reports or fwupd versions without JSON. This fallback
    # intentionally relies on the failure marker rather than translated words.
    text = _combined(report, "fwupd_security_text")
    pattern = re.compile(r"^[✘!xX]\s+(.+?):\s*(.+?)\s*(?::\s*https?://\S+)?$", re.MULTILINE)
    for match in pattern.finditer(text):
        name = match.group(1).strip()
        attrs.append({
            "appstream_id": "",
            "name": name,
            "reported_name": name,
            "result": match.group(2).strip(),
            "success_result": "",
            "flags": [],
            "state": "fail",
            "uri": "",
        })
    return attrs


def _attr_map(attrs: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(attr.get("appstream_id")): attr for attr in attrs if attr.get("appstream_id")}


def _failed_attrs(attrs: list[dict[str, Any]], profile: dict[str, Any]) -> list[dict[str, Any]]:
    failed = []
    for attr in attrs:
        appstream_id = str(attr.get("appstream_id") or "")
        if attr.get("state") != "fail":
            continue
        if _is_heads(profile) and appstream_id.startswith("org.fwupd.hsi.Uefi."):
            continue
        failed.append(attr)
    return failed


def _attr_evidence(attr: dict[str, Any]) -> str:
    ident = str(attr.get("appstream_id") or attr.get("name") or "unknown")
    reported = str(attr.get("reported_name") or "").strip()
    normalized = str(attr.get("name") or "").strip()
    if reported and reported not in {ident, normalized}:
        ident = f"{ident} ({reported})"
    expected = attr.get("success_result") or "unspecified"
    return f"{ident}: result={attr.get('result') or 'unknown'}, expected={expected}, flags={attr.get('flags') or []}"


def _add_unique(findings: list[Finding], finding: Finding) -> None:
    if finding.finding_id not in {item.finding_id for item in findings}:
        findings.append(finding)


def derive_swap_topology(report: dict[str, Any]) -> dict[str, Any]:
    """Determine protection of every currently active swap target.

    fwupd's swap HSI result is deliberately not used. The result comes from the
    active swap inventory plus the block-device and mounted-filesystem topology.
    """
    data = _parse_json_output(report, "lsblk_json")
    if not isinstance(data, dict):
        return {
            "known": False,
            "state": "unknown",
            "swap_devices": [],
            "all_encrypted": False,
            "any_unencrypted": False,
            "method": "active swap inventory + block-device topology",
        }

    active: list[dict[str, str]] = []
    swapon = _stdout(report, "swapon_text")
    for line in swapon.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            active.append({"target": parts[0], "type": parts[1].lower()})

    if not active:
        proc_swaps = _stdout(report, "proc_swaps")
        for line in proc_swaps.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                active.append({"target": parts[0], "type": parts[1].lower()})

    inventory_available = str((report.get("commands", {}).get("swapon_text", {}) or {}).get("status") or "") in {
        "collected", "collected_empty", "ok", "nonzero"
    } or str((report.get("commands", {}).get("proc_swaps", {}) or {}).get("status") or "") in {
        "collected", "collected_empty", "ok", "nonzero"
    }

    # Backward compatibility for older reports that did not record an active
    # swap inventory: infer swap nodes only when no reliable inventory exists.
    if not active and not inventory_available:
        def infer_swap_nodes(devices: list[dict[str, Any]]) -> None:
            for device in devices:
                if not isinstance(device, dict):
                    continue
                fstype = str(device.get("fstype") or "").lower()
                mountpoint = str(device.get("mountpoint") or "")
                mountpoints = [str(item) for item in (device.get("mountpoints") or []) if item is not None]
                if fstype == "swap" or mountpoint == "[SWAP]" or "[SWAP]" in mountpoints:
                    target = str(device.get("path") or device.get("name") or "")
                    if target and not target.startswith("/dev/"):
                        target = "/dev/" + target
                    if target:
                        active.append({"target": target, "type": "partition"})
                infer_swap_nodes(device.get("children", []) or [])
        infer_swap_nodes(data.get("blockdevices", []) or [])
        inventory_available = bool(active)

    node_chains: list[tuple[set[str], list[dict[str, Any]]]] = []

    def walk_nodes(devices: list[dict[str, Any]], ancestors: list[dict[str, Any]]) -> None:
        for device in devices:
            if not isinstance(device, dict):
                continue
            chain = ancestors + [device]
            aliases: set[str] = set()
            for key in ("path", "name", "kname"):
                value = str(device.get(key) or "").strip()
                if not value:
                    continue
                aliases.add(value)
                aliases.add(value.rsplit("/", 1)[-1])
                if not value.startswith("/dev/"):
                    aliases.add("/dev/" + value)
            node_chains.append((aliases, chain))
            walk_nodes(device.get("children", []) or [], chain)

    walk_nodes(data.get("blockdevices", []) or [], [])

    mounts_data = _parse_json_output(report, "mounts")
    mount_rows: list[dict[str, str]] = []

    def walk_mounts(rows: list[dict[str, Any]]) -> None:
        for row in rows:
            if not isinstance(row, dict):
                continue
            target = str(row.get("target") or "")
            source = str(row.get("source") or "")
            if target and source:
                mount_rows.append({"target": target, "source": source})
            walk_mounts(row.get("children", []) or [])

    if isinstance(mounts_data, dict):
        walk_mounts(mounts_data.get("filesystems", []) or [])

    def find_chain(device_name: str) -> list[dict[str, Any]]:
        cleaned = device_name.split("[", 1)[0]
        candidates = {cleaned, cleaned.rsplit("/", 1)[-1]}
        if not cleaned.startswith("/dev/"):
            candidates.add("/dev/" + cleaned)
        matches = [chain for aliases, chain in node_chains if aliases & candidates]
        return max(matches, key=len) if matches else []

    def backing_source_for_file(path: str) -> str:
        normalized = path.rstrip("/") or "/"
        candidates = []
        for row in mount_rows:
            target = row["target"].rstrip("/") or "/"
            if normalized == target or normalized.startswith(target.rstrip("/") + "/"):
                candidates.append(row)
        if not candidates:
            return ""
        return max(candidates, key=lambda row: len(row["target"]))["source"]

    swap_devices: list[dict[str, Any]] = []
    for item in active:
        target = item["target"]
        swap_type = item["type"]
        if target.startswith("/dev/zram") or "zram" in target.lower():
            swap_devices.append({
                "target": target,
                "type": swap_type,
                "protection": "ram-backed",
                "encrypted": True,
                "disk_backed": False,
                "backing_source": target,
                "chain": [target],
            })
            continue

        backing_source = backing_source_for_file(target) if swap_type == "file" else target
        chain = find_chain(backing_source)
        encrypted = any(
            str(node.get("type") or "").lower() == "crypt"
            or str(node.get("fstype") or "").lower() in {"crypto_luks", "crypto_luks2"}
            for node in chain
        )
        protection = "encrypted" if encrypted else ("unencrypted" if chain else "unknown")
        swap_devices.append({
            "target": target,
            "type": swap_type,
            "protection": protection,
            "encrypted": encrypted,
            "disk_backed": True,
            "backing_source": backing_source,
            "chain": [str(node.get("path") or node.get("name") or "unknown") for node in chain],
        })

    if not active:
        state = "none" if inventory_available else "unknown"
    elif any(item["protection"] == "unencrypted" for item in swap_devices):
        state = "unencrypted"
    elif any(item["protection"] == "unknown" for item in swap_devices):
        state = "unknown"
    elif all(item["protection"] == "ram-backed" for item in swap_devices):
        state = "ram-backed"
    else:
        state = "encrypted"

    disk_backed = [item for item in swap_devices if item["disk_backed"]]
    return {
        "known": inventory_available and state != "unknown",
        "state": state,
        "swap_devices": swap_devices,
        "all_encrypted": bool(disk_backed) and all(item["encrypted"] for item in disk_backed),
        "any_unencrypted": any(item["protection"] == "unencrypted" for item in swap_devices),
        "method": "active swap inventory + block-device and mounted-filesystem topology",
        "fwupd_used": False,
    }


def _swap_topology(report: dict[str, Any]) -> dict[str, Any]:
    stored = (report.get("artifacts", {}) or {}).get("swap_topology")
    if isinstance(stored, dict) and stored.get("method"):
        return stored
    return derive_swap_topology(report)


def derive_amd_secure_processor_state(report: dict[str, Any]) -> dict[str, Any]:
    journal = _stdout(report, "kernel_journal").lower()
    ccp_failure = "ccp: unable to access the device: you might be running a broken bios" in journal
    tee_enabled = "tee enabled" in journal
    psp_enabled = "psp enabled" in journal
    if ccp_failure and tee_enabled and psp_enabled:
        state = "secure-processor-initialized-with-ccp-interface-warning"
    elif ccp_failure:
        state = "initialization-needs-review"
    elif tee_enabled or psp_enabled:
        state = "secure-processor-initialized"
    else:
        state = "not-observed"
    return {
        "state": state,
        "ccp_access_failure": ccp_failure,
        "tee_enabled": tee_enabled,
        "psp_enabled": psp_enabled,
        "source": "current-boot kernel journal",
    }


def _heads_measurements_present(report: dict[str, Any]) -> bool:
    text = _stdout(report, "tpm_eventlog").lower()
    return bool(text and (("cbfs:" in text and "fmap:" in text) or ("cbfs" in text and "coreboot" in text) or ("43424653" in text and "464d4150" in text)))


def _kernel_modules(report: dict[str, Any]) -> list[dict[str, Any]]:
    items = report.get("artifacts", {}).get("loaded_module_metadata", []) or []
    return [item for item in items if isinstance(item, dict)]


def _module_origin_from_record(item: dict[str, Any]) -> str:
    stored = str(item.get("origin") or "").strip()
    if stored:
        return stored
    filename = str(item.get("filename") or "").replace("\\", "/")
    if "/updates/dkms/" in filename:
        return "external-dkms"
    if any(marker in filename for marker in ("/updates/", "/extra/", "/weak-updates/")):
        return "external-tree"
    if re.search(r"/(?:lib|usr/lib)/modules/[^/]+/kernel/", filename):
        return "distribution-kernel-tree"
    if "/modules/" in filename:
        return "module-tree-other"
    return "unknown"


def _module_observations(modules: list[dict[str, Any]], taint_codes: set[str]) -> list[dict[str, Any]]:
    """Derive product-neutral module facts relevant to the active taint flags."""
    observations: list[dict[str, Any]] = []
    for item in modules:
        name = str(item.get("name") or "").strip()
        filename = str(item.get("filename") or "").strip()
        license_text = str(item.get("license") or "").strip()
        origin = _module_origin_from_record(item)
        normalized_filename = filename.replace("\\", "/")
        external = origin in {"external-dkms", "external-tree", "module-tree-other", "outside-module-tree"}
        proprietary = bool(license_text and "gpl" not in license_text.lower() and "dual" not in license_text.lower())
        staging = "/kernel/drivers/staging/" in normalized_filename
        livepatch = "/kernel/livepatch/" in normalized_filename
        relevant = (
            ("out-of-tree" in taint_codes and external)
            or ("proprietary-module" in taint_codes and (external or proprietary))
            or ("staging-driver" in taint_codes and staging)
            or ("live-patched" in taint_codes and livepatch)
        )
        if not relevant:
            continue
        observations.append({
            "name": name,
            "filename": filename,
            "origin": origin,
            "package_owner": str(item.get("package_owner") or "").strip(),
            "package_managed": bool(item.get("package_managed")),
            "signer": str(item.get("signer") or "").strip(),
            "license": license_text,
        })
    return observations


def _format_module_observation(item: dict[str, Any]) -> str:
    parts = [f"module {item.get('name') or 'unknown'}"]
    if item.get("filename"):
        parts.append(f"path={item['filename']}")
    if item.get("origin") and item.get("origin") != "unknown":
        parts.append(f"origin={item['origin']}")
    if item.get("package_owner"):
        parts.append(f"package={item['package_owner']}")
    elif item.get("package_managed") is False:
        parts.append("package owner not identified")
    if item.get("signer"):
        parts.append(f"signer={item['signer']}")
    return "; ".join(parts)


def _kernel_warning_evidence(journal: str, limit: int = 4) -> list[str]:
    """Return representative warning lines without recognizing a specific driver/product."""
    markers = ("warning", "warn_on", "bug:", "kernel bug", "oops")
    selected: list[str] = []
    for raw in journal.splitlines():
        line = raw.strip()
        lower = line.lower()
        if line and any(marker in lower for marker in markers):
            selected.append(line[:500])
            if len(selected) >= limit:
                break
    return selected



def _ld_preload_entries(report: dict[str, Any]) -> list[str]:
    records = report.get("artifacts", {}).get("host_persistence_files", []) or []
    for item in records:
        if str(item.get("path")) == "/etc/ld.so.preload":
            text = str(item.get("text") or "")
            return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    return []

def _section_definition(slug: str, profile: dict[str, Any]) -> dict[str, Any]:
    definition = dict(SECTIONS[slug])
    if slug == "secure-boot" and _is_heads(profile):
        definition.update({
            "title": "Heads boot-chain trust",
            "short_title": "Heads boot trust",
            "question": "Is the Heads measured and verified boot chain visible and internally consistent?",
            "simple": "Checks the Heads/coreboot boot model, TPM measurements, and protected boot-file evidence instead of requiring UEFI Secure Boot.",
            "detailed": (
                "Heads does not use the conventional UEFI Secure Boot trust chain. UEFI PK, KEK, db, dbx, MOK, "
                "and EFI runtime checks are therefore marked not applicable. The section instead evaluates whether "
                "Heads/coreboot was identified and whether TPM and boot-file evidence was collected."
            ),
            "technical": (
                "The profile is derived from DMI and measured-boot evidence. CBFS/FMAP events, TPM PCRs, the binary "
                "event log, and hashes of files under /boot are retained. The application does not claim to verify "
                "a user token, HOTP/TOTP state, or Heads signing keys unless those values are explicitly collected."
            ),
        })
    elif slug == "secure-boot" and _is_unclassified_non_uefi(profile):
        definition.update({
            "title": "Non-UEFI boot trust",
            "short_title": "Boot trust",
            "question": "What trust model protects this non-UEFI boot path?",
            "simple": "The machine is not using UEFI runtime services, and the available evidence is insufficient to map the boot path to a known trust model.",
            "detailed": (
                "Firmware Audit does not assume that every non-UEFI platform is conventional legacy BIOS. Coreboot payloads, measured-boot designs, and other boot models can legitimately operate without EFI runtime services. The result remains Unknown until positive evidence identifies the trust model."
            ),
            "technical": (
                "Platform classification separates virtualization, firmware family, runtime interface, and boot trust. UEFI-specific commands are marked not applicable when no conventional UEFI runtime/trust model is detected; the boot-trust section remains Unknown rather than being converted into a legacy-boot weakness from absence alone."
            ),
        })
    elif slug == "secure-boot" and _is_non_uefi_vm(profile):
        definition.update({
            "title": "Guest boot trust",
            "short_title": "Guest boot trust",
            "question": "Does UEFI Secure Boot apply to this virtual machine's current boot mode?",
            "simple": "The guest is running without UEFI runtime services, so UEFI Secure Boot checks do not apply to this guest boot path.",
            "detailed": (
                "A virtual machine can use either legacy/SeaBIOS-style boot or virtual UEFI. This guest was detected as a "
                "virtual machine without UEFI runtime services. Its physical host firmware and host Secure Boot state are outside "
                "the guest's trust boundary and cannot be verified from this scan."
            ),
            "technical": (
                "The virtual-machine profile is selected only when virtualization is detected and /sys/firmware/efi is absent. "
                "UEFI PK, KEK, db, dbx, MOK, efibootmgr, mokutil, and EFI-variable checks are therefore not applicable to this guest."
            ),
        })
    elif slug == "firmware-protection" and _is_vm(profile):
        definition.update({
            "title": "Physical firmware write protection",
            "short_title": "Write protections",
            "question": "Can the physical host's firmware write protections be assessed from this virtual machine?",
            "simple": "A normal virtual-machine guest cannot directly test the physical host's SPI flash write protections.",
            "detailed": (
                "Guest-visible firmware interfaces describe the virtual platform presented by the hypervisor. They do not prove whether "
                "the physical host's SPI controller, protected ranges, SMM protections, or external hardware write-protect mechanisms are active."
            ),
            "technical": "Physical host firmware write resistance is outside the guest trust boundary and is marked not applicable rather than Good.",
        })
    elif slug == "out-of-band-management" and _is_vm(profile):
        definition.update({
            "title": "Physical out-of-band management",
            "short_title": "OOB management",
            "question": "Can physical host out-of-band management be assessed from this virtual machine?",
            "simple": "A normal virtual-machine guest cannot determine whether the physical host has AMT, DASH, IPMI/BMC, or similar management enabled.",
            "detailed": (
                "The absence of management interfaces inside a guest is not evidence that the physical hypervisor host lacks an out-of-band "
                "management controller. Host-level collection is required for that conclusion."
            ),
            "technical": "Physical management controllers and provisioning state are outside the normal guest hardware namespace and are marked not applicable.",
        })
    return definition


def build_sections(report: dict[str, Any], finding_dicts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = []
    commands = report.get("commands", {}) or {}
    artifacts = report.get("artifacts", {}) or {}
    profile = detect_platform_profile(report)

    schema_version = int(report.get("schema_version") or 0)
    schema12_sections = {"platform-security-processor", "out-of-band-management", "memory-protection"}

    for slug in SECTION_ORDER:
        definition = _section_definition(slug, profile)
        legacy_new_section = schema_version < 12 and slug in schema12_sections
        section_findings = [item for item in finding_dicts if item.get("section") == slug]
        section_findings.sort(key=lambda item: (-SEVERITY_ORDER.get(str(item.get("severity")), 0), str(item.get("title", "")).lower()))

        checks: list[dict[str, Any]] = []
        required_commands = list(definition.get("commands", []))
        optional_commands = list(definition.get("optional_commands", []))
        for name in [*required_commands, *optional_commands]:
            item = commands.get(name, {}) or {}
            state = "not_collected" if legacy_new_section else _command_state(report, name, profile)
            checks.append({
                "kind": "command",
                "id": name,
                "description": item.get("description") or name,
                "status": state,
                "available": state in {"collected", "collected_empty"},
                "applicable": state != "not_applicable",
                "optional": name in optional_commands,
            })
        required_artifacts = list(definition.get("artifacts", []))
        optional_artifacts = list(definition.get("optional_artifacts", []))
        for name in [*required_artifacts, *optional_artifacts]:
            if legacy_new_section:
                state = "not_collected"
                present = False
            elif name in UEFI_ARTIFACTS and not _uses_conventional_uefi_boot(profile):
                state = "not_applicable"
                present = False
            elif int(report.get("schema_version") or 0) < 5 and name in HOST_INTEGRITY_ARTIFACTS:
                state = "not_applicable"
                present = False
            else:
                present = name in artifacts and artifacts.get(name) not in (None, [], {})
                state = "collected" if present else "not_collected"
            checks.append({
                "kind": "artifact",
                "id": name,
                "description": name.replace("_", " "),
                "status": state,
                "available": present,
                "applicable": state != "not_applicable",
                "optional": name in optional_artifacts,
            })

        applicable_checks = [item for item in checks if item["applicable"] and not item.get("optional")]
        available_count = sum(1 for item in applicable_checks if item["available"])
        optional_checks = [item for item in checks if item["applicable"] and item.get("optional")]
        optional_available = sum(1 for item in optional_checks if item["available"])
        critical_integrity = [item for item in section_findings if item.get("compromise_indicator")]
        actionable = [item for item in section_findings if _dict_is_actionable(item)]
        section_notes = [item for item in section_findings if _dict_is_security_note(item)]
        unresolved = [item for item in section_notes if item.get("finding_type") == "unknown"]

        if slug in {"firmware-protection", "out-of-band-management"} and _is_vm(profile):
            status = "not_applicable"
        elif critical_integrity:
            status = "investigate"
        elif actionable:
            status = "attention"
        elif slug == "secure-boot" and _is_non_uefi_vm(profile):
            status = "not_applicable"
        elif slug == "platform-security-processor" and _is_vm(profile):
            status = "not_applicable"
        elif slug == "secure-boot" and _is_unclassified_non_uefi(profile):
            status = "unknown"
        elif checks and not applicable_checks:
            status = "not_applicable"
        elif applicable_checks and available_count == 0:
            status = "unknown"
        elif unresolved:
            status = "unknown"
        else:
            status = "good"

        if status in {"investigate", "attention"} and actionable:
            simple_result = actionable[0]["simple"]
        elif status == "not_applicable":
            if slug == "secure-boot" and _is_non_uefi_vm(profile):
                simple_result = "UEFI Secure Boot is not applicable to this guest because it is using a non-UEFI virtual boot path."
            elif slug == "platform-security-processor" and _is_vm(profile):
                simple_result = "Physical host security processors such as Intel ME/CSME or AMD PSP cannot be assessed from a normal virtual-machine guest."
            elif slug == "firmware-protection" and _is_vm(profile):
                simple_result = "Physical host firmware write protection cannot be assessed from a normal virtual-machine guest."
            elif slug == "out-of-band-management" and _is_vm(profile):
                simple_result = "Physical host out-of-band management cannot be assessed from a normal virtual-machine guest."
            else:
                simple_result = "This section does not apply to the detected platform or boot model."
        elif status == "unknown":
            if legacy_new_section:
                simple_result = "This check was not collected by the Firmware Audit version that generated this report. Run a new collection with the current version."
            elif slug == "platform-security-processor" and unresolved:
                simple_result = str(unresolved[0].get("simple") or "The Intel platform security-engine state could not be established from the available local evidence.")
            else:
                simple_result = "The application could not collect enough applicable evidence for this section."
        else:
            if slug == "storage-memory":
                stored_swap = ((report.get("artifacts", {}) or {}).get("swap_topology") or {})
                swap_state = str((stored_swap if isinstance(stored_swap, dict) and stored_swap else _swap_topology(report)).get("state") or "")
                if swap_state == "encrypted":
                    simple_result = "Active swap storage is encrypted."
                elif swap_state == "ram-backed":
                    simple_result = "Active swap is RAM-backed and is not written to disk."
                else:
                    simple_result = "No problem requiring action was identified from the available checks."
            elif slug == "tpm-measured-boot":
                replay = ((report.get("artifacts", {}) or {}).get("tpm_eventlog_replay") or {})
                if isinstance(replay, dict) and replay.get("state") == "matched":
                    simple_result = "The measured-boot event log reconstructs the live TPM PCRs for the compared range."
                else:
                    simple_result = "No problem requiring action was identified from the available checks."
            elif slug == "platform-security-processor":
                processor = _processor_artifact(report)
                names = []
                intel = processor.get("intel_mei") if isinstance(processor.get("intel_mei"), dict) else {}
                amd = processor.get("amd_psp") if isinstance(processor.get("amd_psp"), dict) else {}
                amd_tee = processor.get("amd_tee") if isinstance(processor.get("amd_tee"), dict) else {}
                intel_state = str(intel.get("state") or "")
                if intel_state == "disabled":
                    names.append("Intel ME/CSME (reported disabled)")
                elif intel_state == "not-present":
                    names.append("Intel ME/CSME (intelmetool reports not present)")
                elif intel.get("observable"):
                    names.append("Intel ME/CSME/SPS-family host interface")
                elif intel.get("hardware_present"):
                    names.append("Intel ME/CSME hardware/HECI interface (runtime state unresolved)")
                if amd.get("observable"):
                    names.append("AMD Secure Processor")
                if amd_tee.get("detected"):
                    names.append("AMD TEE")
                names.extend(str(item.get("technology")) for item in processor.get("gpu_security_processors", []) if isinstance(item, dict) and item.get("technology"))
                names.extend(str(item.get("technology")) for item in processor.get("embedded_controllers", []) if isinstance(item, dict) and item.get("technology"))
                names.extend(str(item.get("technology")) for item in processor.get("explicit_other", []) if isinstance(item, dict) and item.get("technology"))
                simple_result = ("Detected locally: " + "; ".join(dict.fromkeys(names)) + ".") if names else "No platform security processor was directly observable from the available local interfaces."
            elif slug == "out-of-band-management":
                oob = _oob_artifact(report)
                labels = []
                bmc = oob.get("bmc") if isinstance(oob.get("bmc"), dict) else {}
                amt = oob.get("intel_amt") if isinstance(oob.get("intel_amt"), dict) else {}
                nic_oob = oob.get("nic_oob") if isinstance(oob.get("nic_oob"), dict) else {}
                dash = oob.get("dmtf_dash") if isinstance(oob.get("dmtf_dash"), dict) else {}
                if bmc.get("detected"):
                    labels.append("BMC/IPMI host interface")
                if nic_oob.get("detected"):
                    state = str(nic_oob.get("state") or "state unknown")
                    labels.append("NIC-integrated management/IPMI function" + (" (dormant)" if state == "nic-oob-function-dormant" else f" ({state})"))
                if amt.get("detected"):
                    states_seen = sorted({str(item.get("provisioning_state") or "unknown") for item in amt.get("records", []) if isinstance(item, dict)})
                    labels.append("Intel AMT" + (f" ({'/'.join(states_seen)})" if states_seen else ""))
                if dash.get("detected"):
                    labels.append(f"DMTF DASH ({dash.get('state') or 'unknown'})")
                persistence = [item for item in oob.get("firmware_persistence", []) if isinstance(item, dict)]
                if persistence:
                    states = sorted({str(item.get("state") or "unknown") for item in persistence})
                    labels.append("firmware endpoint persistence (" + "/".join(states) + ")")
                simple_result = ("Detected locally: " + "; ".join(labels) + ".") if labels else "No out-of-band management controller was detected from local host interfaces."
            elif slug == "memory-protection":
                memory = _memory_artifact(report)
                hsi = _memory_encryption_hsi(_fwupd_attributes(report))
                system_memory = memory.get("system_memory") if isinstance(memory.get("system_memory"), dict) else {}
                caps = memory.get("capabilities") if isinstance(memory.get("capabilities"), dict) else {}
                amd_sme = system_memory.get("amd_sme") if isinstance(system_memory.get("amd_sme"), dict) else {}
                amd_tsme = system_memory.get("amd_tsme") if isinstance(system_memory.get("amd_tsme"), dict) else {}
                confidential = memory.get("confidential_vm") if isinstance(memory.get("confidential_vm"), dict) else {}
                amd_sev = confidential.get("amd_sev") if isinstance(confidential.get("amd_sev"), dict) else {}
                if amd_tsme.get("active"):
                    if amd_sme.get("supported") and not amd_sme.get("linux_managed_active"):
                        simple_result = "AMD Transparent SME (TSME) is active for system memory; OS-managed SME is supported but is not the active path."
                    else:
                        simple_result = "AMD Transparent SME (TSME) is active for system memory."
                elif _amd_tsme_active(report):
                    simple_result = "Hardware-backed system-memory encryption is reported active."
                elif amd_sme.get("linux_managed_active") or system_memory.get("amd_sme_kernel_active"):
                    simple_result = "Linux-managed AMD SME is active for system memory."
                elif (system_memory.get("intel_tme") or {}).get("active") if isinstance(system_memory.get("intel_tme"), dict) else False:
                    simple_result = "Intel Total Memory Encryption is reported active for system memory."
                elif isinstance(system_memory.get("intel_tme"), dict) and (system_memory.get("intel_tme") or {}).get("supported"):
                    simple_result = "Intel Total Memory Encryption is supported but is not reported active for system memory."
                elif hsi and hsi.get("state") == "pass":
                    simple_result = "Hardware-backed system-memory encryption is reported active."
                else:
                    supported = [name for name, enabled in caps.items() if enabled]
                    if _is_vm(profile):
                        simple_result = (
                            "Guest-visible memory-protection capabilities detected: " + ", ".join(supported) + ". Physical host memory protection is outside the guest scan scope."
                            if supported
                            else "No guest-visible confidential-memory or memory-encryption capability was identified. Physical host memory protection is outside the guest scan scope."
                        )
                    elif amd_sev.get("supported") and not amd_sev.get("host_enabled"):
                        simple_result = ("Memory-protection capabilities detected: " + ", ".join(supported) + ". AMD SEV-family capability is supported but not enabled for host virtualization.") if supported else "AMD SEV-family capability is supported but not enabled for host virtualization."
                    else:
                        simple_result = ("Memory-protection capabilities detected: " + ", ".join(supported) + ".") if supported else "No hardware memory-encryption capability was identified from the available local evidence."
            else:
                simple_result = "No problem requiring action was identified from the available checks."

        type_counts: dict[str, int] = {}
        for item in section_findings:
            key = str(item.get("finding_type") or "informational")
            type_counts[key] = type_counts.get(key, 0) + 1

        titles = "; ".join(item["title"] for item in actionable[:4])
        result_detail = (
            f"{len(actionable)} actionable finding(s) and {len(section_notes)} security note(s) were generated from {available_count} available applicable evidence source(s)."
            + (f" Main actionable findings: {titles}." if actionable else " No section-specific action is required.")
        )
        states: dict[str, int] = {}
        for check in checks:
            states[check["status"]] = states.get(check["status"], 0) + 1
        result_technical = (
            f"Evidence availability: {available_count}/{len(applicable_checks)} applicable configured sources; "
            f"{len(checks) - len(applicable_checks)} not applicable. Evidence states: {states}. "
            f"Finding types: {type_counts or {'informational': 0}}."
        )

        sections.append({
            "slug": slug,
            "title": definition["title"],
            "short_title": definition["short_title"],
            "question": definition["question"],
            "status": status,
            "simple_explanation": definition["simple"],
            "simple_result": simple_result,
            "detailed_explanation": definition["detailed"],
            "detailed_result": result_detail,
            "technical_explanation": definition["technical"],
            "technical_result": result_technical,
            "findings": section_findings,
            "actionable_findings": actionable,
            "security_notes": section_notes,
            "checks": checks,
            "available_evidence": available_count,
            "configured_evidence": len(applicable_checks),
            "not_applicable_evidence": sum(1 for item in checks if not item["applicable"]),
            "optional_available_evidence": optional_available,
            "optional_configured_evidence": len(optional_checks),
            "counts": {
                severity: sum(1 for item in section_findings if item.get("severity") == severity)
                for severity in ("critical", "high", "medium", "low", "info")
            },
            "type_counts": type_counts,
        })
    return sections


def _dict_is_actionable(item: dict[str, Any]) -> bool:
    if item.get("compromise_indicator"):
        return True
    finding_type = str(item.get("finding_type") or "informational")
    return finding_type in ACTIONABLE_TYPES and str(item.get("severity") or "info") in {"low", "medium", "high", "critical"}


def _dict_is_security_note(item: dict[str, Any]) -> bool:
    if _dict_is_actionable(item):
        return False
    finding_id = str(item.get("finding_id") or "")
    # Positive platform identity and successful measured-boot observations belong
    # in section results, not in the residual-risk notes list.
    if finding_id in {"heads-platform", "heads-boot-model", "heads-measurements-present"}:
        return False
    return str(item.get("finding_type") or "informational") in {
        "informational", "compatibility-issue", "reliability-issue", "unknown"
    }


def rebuild_assessment_sections(report: dict[str, Any], assessment: dict[str, Any]) -> dict[str, Any]:
    findings = list(assessment.get("findings", []))
    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(str(item.get("severity")), 0), str(item.get("title", "")).lower()))
    assessment["findings"] = findings
    actionable = [item for item in findings if _dict_is_actionable(item)]
    notes = [item for item in findings if _dict_is_security_note(item)]
    assessment["actionable_findings"] = actionable
    assessment["security_notes"] = notes
    assessment["counts"] = {
        severity: sum(1 for item in actionable if item.get("severity") == severity)
        for severity in ("critical", "high", "medium", "low")
    }
    assessment["note_count"] = len(notes)
    type_counts: dict[str, int] = {}
    for item in actionable:
        key = str(item.get("finding_type") or "informational")
        type_counts[key] = type_counts.get(key, 0) + 1
    assessment["type_counts"] = type_counts
    sections = build_sections(report, findings)
    assessment["sections"] = sections

    # If there are no actionable or compromise findings, only make the overall
    # result Unknown when an important security area itself could not be
    # assessed. Optional inventory/maintenance sections do not downgrade the
    # overall result merely because some evidence is unavailable.
    if assessment.get("status") == "good":
        conclusion_sections = {
            "firmware-baseline", "firmware-protection", "secure-boot",
            "tpm-measured-boot", "kernel-runtime", "host-integrity",
            "storage-memory",
        }
        unknown_sections = [
            section for section in sections
            if section.get("slug") in conclusion_sections and section.get("status") == "unknown"
        ]
        if unknown_sections:
            assessment["status"] = "unknown"
            assessment["headline"] = "One or more security areas could not be assessed"
            names = ", ".join(str(section.get("short_title") or section.get("title")) for section in unknown_sections)
            assessment["explanation"] = (
                "No direct compromise indicator was found, but the available local evidence was insufficient "
                f"for: {names}. Unknown is not treated as a security failure."
            )
    return assessment




def _cpu_vulnerability_summary(report: dict[str, Any]) -> dict[str, Any]:
    records = (report.get("artifacts", {}) or {}).get("cpu_vulnerabilities", []) or []
    vulnerable: list[dict[str, str]] = []
    mitigated: list[dict[str, str]] = []
    unknown: list[dict[str, str]] = []
    for item in records:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "unknown")
        value = str(item.get("value") or "").strip()
        if not value:
            continue
        lower = value.lower()
        record = {"name": name, "value": value}
        if lower.startswith("not affected"):
            mitigated.append(record)
        elif "vulnerable" in lower:
            vulnerable.append(record)
        elif lower.startswith("mitigation"):
            mitigated.append(record)
        else:
            unknown.append(record)
    return {"vulnerable": vulnerable, "mitigated": mitigated, "unknown": unknown}


def _kernel_commandline_security(report: dict[str, Any]) -> list[dict[str, str]]:
    text = _stdout(report, "proc_cmdline").strip()
    if not text:
        return []
    findings: list[dict[str, str]] = []
    for token in text.split():
        lower = token.lower()
        if lower == "mitigations=off":
            findings.append({"token": token, "class": "cpu-mitigations", "impact": "high", "meaning": "CPU vulnerability mitigations are globally disabled"})
        elif lower in {"nospectre_v1", "nospectre_v2", "nopti", "nosmap", "nosmep"}:
            findings.append({"token": token, "class": "kernel-mitigation", "impact": "medium", "meaning": "A kernel or CPU protection is explicitly disabled"})
        elif lower.startswith(("spectre_v2=off", "spec_store_bypass_disable=off", "mds=off", "tsx_async_abort=off", "l1tf=off", "retbleed=off")):
            findings.append({"token": token, "class": "cpu-mitigation", "impact": "medium", "meaning": "A CPU vulnerability mitigation is explicitly disabled"})
        elif lower in {"iommu=off", "intel_iommu=off", "amd_iommu=off"}:
            findings.append({"token": token, "class": "iommu", "impact": "contextual", "meaning": "IOMMU/DMA remapping is explicitly disabled"})
        elif lower == "ima_appraise=off":
            findings.append({"token": token, "class": "ima", "impact": "contextual", "meaning": "IMA appraisal is explicitly disabled"})
    return findings


def _secure_boot_sources(report: dict[str, Any], attrs: list[dict[str, Any]]) -> dict[str, str]:
    states: dict[str, str] = {}
    mok = _combined(report, "secure_boot_state").lower()
    if "secureboot enabled" in mok or "secure boot enabled" in mok:
        states["mokutil"] = "enabled"
    elif "secureboot disabled" in mok or "secure boot disabled" in mok:
        states["mokutil"] = "disabled"
    bootctl = _combined(report, "bootctl").lower()
    if "secure boot:" in bootctl:
        if re.search(r"secure boot:\s*(enabled|active)", bootctl):
            states["bootctl"] = "enabled"
        elif re.search(r"secure boot:\s*(disabled|inactive|off)", bootctl):
            states["bootctl"] = "disabled"
    for attr in attrs:
        if str(attr.get("appstream_id") or "") != "org.fwupd.hsi.Uefi.SecureBoot":
            continue
        result = str(attr.get("result") or "").lower()
        success = str(attr.get("success_result") or "").lower()
        if result:
            states["fwupd"] = "enabled" if result == success or result in {"enabled", "valid"} else "disabled"
        break
    lockdown = _stdout(report, "kernel_lockdown").strip().lower()
    if lockdown:
        if "[none]" in lockdown or lockdown == "none":
            states["lockdown"] = "none"
        elif "[integrity]" in lockdown or "integrity" == lockdown:
            states["lockdown"] = "integrity"
        elif "[confidentiality]" in lockdown or "confidentiality" == lockdown:
            states["lockdown"] = "confidentiality"
    return states


def _thunderbolt_exposure(report: dict[str, Any]) -> dict[str, Any]:
    artifact = (report.get("artifacts", {}) or {}).get("thunderbolt_security") or {}
    if not isinstance(artifact, dict) or not artifact.get("available"):
        return {"state": "not-present", "evidence": []}
    domains = [item for item in artifact.get("domains", []) if isinstance(item, dict)]
    devices = [item for item in artifact.get("devices", []) if isinstance(item, dict)]
    evidence: list[str] = []
    risky_domains = []
    for domain in domains:
        security = str(domain.get("security") or "unknown").strip().lower()
        iommu = str(domain.get("iommu_dma_protection") or "unknown").strip()
        evidence.append(f"{domain.get('name')}: security={security}; iommu_dma_protection={iommu}")
        if security == "nopcie":
            continue
        if iommu == "1":
            continue
        if security in {"none", "unknown", ""}:
            risky_domains.append(domain)
    authorized = []
    for device in devices:
        if str(device.get("authorized") or "").strip() == "1":
            authorized.append(device)
            evidence.append(
                f"device {device.get('name')}: authorized=1; vendor={device.get('vendor_name') or 'unknown'}; name={device.get('device_name') or 'unknown'}"
            )
    if risky_domains and (authorized or any(str(item.get("security") or "").lower() == "none" for item in risky_domains)):
        return {"state": "exposed", "evidence": evidence}
    if domains:
        return {"state": "protected-or-controlled", "evidence": evidence}
    return {"state": "unknown", "evidence": evidence}


def _integrity_framework_state(report: dict[str, Any]) -> dict[str, Any]:
    artifact = (report.get("artifacts", {}) or {}).get("integrity_frameworks") or {}
    if not isinstance(artifact, dict):
        return {"ima": False, "ipe": False}
    ima = artifact.get("ima") if isinstance(artifact.get("ima"), dict) else {}
    ipe = artifact.get("ipe") if isinstance(artifact.get("ipe"), dict) else {}
    return {
        "ima": bool(ima.get("available")),
        "ima_policy": str(ima.get("policy") or ""),
        "ipe": bool(ipe.get("available")),
        "ipe_policies": list(ipe.get("policies") or []),
    }


def _processor_artifact(report: dict[str, Any]) -> dict[str, Any]:
    value = (report.get("artifacts", {}) or {}).get("platform_security_processors") or {}
    return value if isinstance(value, dict) else {}


def _cpu_vendor_from_report(report: dict[str, Any]) -> str:
    """Return the CPU vendor from collected lscpu JSON when available."""
    raw = str((report.get("commands", {}).get("lscpu_json") or {}).get("stdout") or "")
    if raw:
        try:
            data = json.loads(raw)
        except (TypeError, ValueError):
            data = None
        rows = data.get("lscpu") if isinstance(data, dict) else None
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                field_name = str(row.get("field") or "").strip().rstrip(":").lower()
                if field_name in {"vendor id", "vendor_id"}:
                    return str(row.get("data") or "").strip()
    return ""


def _intel_me_state(report: dict[str, Any]) -> dict[str, Any]:
    artifact = _processor_artifact(report)
    intel = artifact.get("intel_mei") if isinstance(artifact.get("intel_mei"), dict) else {}
    return intel


def _intel_me_evidence(intel: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    tool = intel.get("intelmetool") if isinstance(intel.get("intelmetool"), dict) else {}
    for line in tool.get("evidence", []) or []:
        if line:
            evidence.append(f"intelmetool: {line}")
    for line in tool.get("failure_evidence", []) or []:
        if line:
            evidence.append(f"intelmetool: {line}")
    context = tool.get("privilege_context") if isinstance(tool.get("privilege_context"), dict) else {}
    lockdown = context.get("kernel_lockdown") if isinstance(context.get("kernel_lockdown"), dict) else {}
    if lockdown.get("active"):
        evidence.append(f"Kernel lockdown mode: {lockdown.get('active')}")
    caps = context.get("capabilities") if isinstance(context.get("capabilities"), dict) else {}
    if caps.get("effective") is not None:
        evidence.append(f"CAP_SYS_RAWIO effective: {'yes' if caps.get('effective') else 'no'}")
    if caps.get("bounding") is not None:
        evidence.append(f"CAP_SYS_RAWIO in bounding set: {'yes' if caps.get('bounding') else 'no'}")
    for item in intel.get("pci_evidence", []) or []:
        if isinstance(item, dict):
            desc = str(item.get("description") or "").strip()
            bdf = str(item.get("bdf") or "").strip()
            if desc:
                evidence.append(f"PCI {bdf}: {desc}" if bdf else desc)
    journal = intel.get("journal") if isinstance(intel.get("journal"), dict) else {}
    for line in journal.get("evidence", []) or []:
        if line:
            evidence.append(str(line))
    return evidence[:20]


def _amd_psp_direct_failures(report: dict[str, Any]) -> list[dict[str, str]]:
    """Return explicit insecure AMD PSP values exported by the running platform."""
    artifact = _processor_artifact(report)
    amd = artifact.get("amd_psp") if isinstance(artifact.get("amd_psp"), dict) else {}
    failures: list[dict[str, str]] = []
    labels = {
        "fused_part": "platform fused state",
        "debug_lock_on": "debug lock",
        "anti_rollback_status": "rollback protection",
        "boot_integrity": "platform secure boot",
    }
    false_values = {"0", "n", "no", "false", "off", "disabled"}
    for device in amd.get("devices", []) or []:
        if not isinstance(device, dict):
            continue
        attrs = device.get("attributes") if isinstance(device.get("attributes"), dict) else {}
        for field, label in labels.items():
            value = str(attrs.get(field) or "").strip()
            if field in attrs and value.lower() in false_values:
                failures.append({
                    "bdf": str(device.get("bdf") or "AMD PSP"),
                    "field": field,
                    "label": label,
                    "value": value,
                })
    return failures


def _amd_psp_evidence_line(item: dict[str, str]) -> str:
    return f"{item.get('bdf') or 'AMD PSP'}: {item.get('label') or item.get('field')} ({item.get('field')})={item.get('value')}"


def _amd_tsme_active(report: dict[str, Any]) -> bool:
    artifact = _processor_artifact(report)
    amd = artifact.get("amd_psp") if isinstance(artifact.get("amd_psp"), dict) else {}
    true_values = {"1", "y", "yes", "true", "on", "enabled"}
    for device in amd.get("devices", []) or []:
        if not isinstance(device, dict):
            continue
        attrs = device.get("attributes") if isinstance(device.get("attributes"), dict) else {}
        if str(attrs.get("tsme_status") or "").strip().lower() in true_values:
            return True
    return False


def _oob_artifact(report: dict[str, Any]) -> dict[str, Any]:
    value = (report.get("artifacts", {}) or {}).get("out_of_band_management") or {}
    return value if isinstance(value, dict) else {}


def _memory_artifact(report: dict[str, Any]) -> dict[str, Any]:
    value = (report.get("artifacts", {}) or {}).get("memory_protection") or {}
    return value if isinstance(value, dict) else {}


def _system_memory_encryption_active(report: dict[str, Any]) -> bool:
    memory = _memory_artifact(report)
    system_memory = memory.get("system_memory") if isinstance(memory.get("system_memory"), dict) else {}
    if system_memory.get("active") is True or system_memory.get("amd_sme_kernel_active") is True:
        return True
    amd_tsme = system_memory.get("amd_tsme") if isinstance(system_memory.get("amd_tsme"), dict) else {}
    intel_tme = system_memory.get("intel_tme") if isinstance(system_memory.get("intel_tme"), dict) else {}
    return bool(amd_tsme.get("active") or intel_tme.get("active") or _amd_tsme_active(report))


def _memory_encryption_hsi(attrs: list[dict[str, Any]]) -> dict[str, Any] | None:
    for attr in attrs:
        if str(attr.get("appstream_id") or "") == "org.fwupd.hsi.EncryptedRam":
            return attr
    return None


def assess(report: dict[str, Any]) -> dict[str, Any]:
    findings: list[Finding] = []
    profile = detect_platform_profile(report)
    profile_kind = str(profile.get("kind") or "unknown")

    # Evidence availability is evaluated per section. The end-user assessment
    # deliberately does not calculate or display a global collection-coverage
    # percentage: unavailable evidence should become Unknown only where it
    # prevents a section-level conclusion.

    virt = _stdout(report, "systemd_detect_virt").strip()
    if virt and virt != "none":
        _add_unique(findings, Finding(
            "virtual-machine",
            "Running inside a virtual machine",
            "info",
            "scope",
            "The scan can assess the guest boot environment, but it cannot directly verify the physical host firmware.",
            "Run the collector on the physical host for firmware-level assurance.",
            [f"systemd-detect-virt: {virt}"],
            "high",
            detailed="Guest operating-system and virtual boot evidence can still be assessed, but physical firmware protections, host CPU microcode, and host platform security processors remain outside the guest's direct view.",
            section="identity",
            finding_type="informational",
            evidence_ids=["systemd_detect_virt", "hostnamectl", "artifact:platform_profile"],
        ))

    if _is_heads(profile):
        _add_unique(findings, Finding(
            "heads-platform",
            "Coreboot with Heads detected",
            "info",
            "scope",
            "This machine uses a coreboot/Heads trust chain rather than conventional UEFI Secure Boot.",
            "Interpret UEFI checks as not applicable and evaluate the Heads measured/verified boot evidence instead.",
            list(profile.get("evidence") or ["Heads/coreboot identified"]),
            "high",
            detailed=(
                "The platform identity and measured-boot evidence identify a coreboot/Heads system. Conventional "
                "UEFI key databases and EFI runtime services are not required for this boot model."
            ),
            technical=(
                "Platform profile coreboot-heads was selected from DMI and/or TPM event-log content. Rules for "
                "UEFI PK, KEK, db, dbx, MOK, efibootmgr, and mokutil state are therefore suppressed as not applicable."
            ),
            section="identity",
            finding_type="informational",
            evidence_ids=["dmidecode_bios", "dmidecode_full", "tpm_eventlog"],
        ))
        _add_unique(findings, Finding(
            "heads-boot-model",
            "Heads boot-chain model is active",
            "info",
            "measured-boot",
            "Boot trust should be evaluated through Heads/coreboot measurements and protected boot files, not UEFI Secure Boot.",
            "Verify Heads warnings, token/HOTP state, and signed boot configuration during physical inspection.",
            ["Detected platform profile: coreboot-heads"],
            "high",
            section="secure-boot",
            finding_type="informational",
            evidence_ids=["dmidecode_bios", "tpm_eventlog", "tpm_pcrs", "artifact:boot_file_hashes"],
        ))

    sb = _combined(report, "secure_boot_state").lower()
    if _uses_conventional_uefi_boot(profile):
        if "secureboot enabled" in sb or "secure boot enabled" in sb:
            pass
        elif "secureboot disabled" in sb or "secure boot disabled" in sb:
            _add_unique(findings, Finding(
                "secure-boot-disabled",
                "Secure Boot is disabled",
                "medium",
                "boot-protection",
                "The machine is not enforcing signed boot components. This is a protection gap, not proof of compromise.",
                "Enable Secure Boot after confirming that the installed bootloader, kernel, and required modules are signed.",
                ["mokutil --sb-state reported Secure Boot disabled"],
                "high",
            ))
        elif not _available(report, "secure_boot_state", profile):
            _add_unique(findings, Finding(
                "secure-boot-unknown",
                "Secure Boot state could not be determined",
                "low",
                "visibility",
                "The required tool may be missing or the firmware interface may not expose a usable state.",
                "Install mokutil and verify the boot mode and Secure Boot state.",
                ["No usable mokutil Secure Boot result"],
                "medium",
            ))
    elif profile_kind == "legacy-bios":
        _add_unique(findings, Finding(
            "legacy-boot",
            "System booted without UEFI runtime services",
            "medium",
            "boot-protection",
            "The application found neither UEFI runtime services nor evidence of a coreboot/Heads boot model.",
            "Confirm the intended boot mode and use UEFI Secure Boot where the platform supports it.",
            list(profile.get("evidence") or ["/sys/firmware/efi is absent"]),
            "medium",
        ))
    elif _is_unclassified_non_uefi(profile):
        _add_unique(findings, Finding(
            "boot-model-unclassified",
            "Non-UEFI boot trust model could not be fully classified",
            "info",
            "visibility",
            "UEFI runtime services are absent, but the available evidence does not justify treating the boot path as conventional legacy BIOS.",
            "Collect a full scan and review the platform-profile signals before applying UEFI or legacy-boot recommendations.",
            list(profile.get("evidence") or ["UEFI runtime services are absent"]),
            "medium",
            detailed=(
                "Firmware Audit keeps the boot interface, firmware family, and trust model separate. A missing UEFI runtime interface is therefore not enough by itself to label an unfamiliar platform as legacy BIOS."
            ),
            section="secure-boot",
            finding_type="unknown",
            evidence_ids=["artifact:platform_profile", "dmidecode_bios", "tpm_eventlog", "artifact:boot_file_hashes"],
        ))

    attrs = _fwupd_attributes(report)
    attr_by_id = _attr_map(attrs)
    failed_attrs = _failed_attrs(attrs, profile)

    # Platform-security-processor interpretation is product-family aware but
    # technology-semantic: presence is inventory; only explicit insecure states
    # become findings.  No CPU-generation or model database is used.
    direct_psp_failures = _amd_psp_direct_failures(report)
    hsi_for_field = {
        "anti_rollback_status": {"org.fwupd.hsi.Amd.RollbackProtection", "org.fwupd.hsi.Amd.PlatformRollbackProtection"},
        "boot_integrity": {"org.fwupd.hsi.Amd.PlatformSecureBoot"},
        "debug_lock_on": {"org.fwupd.hsi.PlatformDebugLocked"},
        "fused_part": set(),
    }
    uncovered_psp_failures: list[dict[str, str]] = []
    conflicting_psp_evidence: list[str] = []
    for item in direct_psp_failures:
        matching_hsi = [attr_by_id[ident] for ident in hsi_for_field.get(item.get("field", ""), set()) if ident in attr_by_id]
        if any(attr.get("state") == "pass" for attr in matching_hsi):
            conflicting_psp_evidence.append(_amd_psp_evidence_line(item))
            conflicting_psp_evidence.extend(_attr_evidence(attr) for attr in matching_hsi if attr.get("state") == "pass")
        elif not matching_hsi:
            uncovered_psp_failures.append(item)
        # A matching failed HSI is handled by the normal fwupd finding below;
        # avoid creating the same weakness twice.

    if conflicting_psp_evidence:
        _add_unique(findings, Finding(
            "amd-psp-evidence-inconsistent",
            "AMD Secure Processor security evidence is inconsistent",
            "medium",
            "integrity-signal",
            "Independent local sources disagree about an AMD Secure Processor security control.",
            "Review the raw PSP and firmware-security evidence before changing firmware settings.",
            conflicting_psp_evidence,
            "high",
            detailed="A direct processor attribute reports a disabled control while another local firmware-security source reports that same control as passing.",
            section="platform-security-processor",
            finding_type="integrity-indicator",
            evidence_ids=["fwupd_security_json", "artifact:platform_security_processors"],
        ))

    if uncovered_psp_failures:
        _add_unique(findings, Finding(
            "amd-psp-security-controls",
            "AMD Secure Processor reports disabled platform security controls",
            "medium",
            "platform-security-processor",
            "The kernel-exported AMD Secure Processor state contains one or more explicit disabled security controls that are not already represented by another local firmware-security result.",
            "Review firmware security settings and apply current platform firmware before relying on these protections.",
            [_amd_psp_evidence_line(item) for item in uncovered_psp_failures],
            "high",
            section="platform-security-processor",
            finding_type="protection-weakness",
        ))

    # Intel ME/CSME presence, host-interface visibility, and execution state are
    # intentionally separate. A failed MEI host interface does not prove that
    # the engine is absent or disabled. An explicit disabled conclusion is
    # accepted only from a chipset-aware decoder (currently intelmetool).
    intel = _intel_me_state(report)
    intel_state = str(intel.get("state") or "unobserved")
    cpu_vendor = _cpu_vendor_from_report(report)
    virt_state = _stdout(report, "systemd_detect_virt").strip()
    physical_or_unknown = not virt_state or virt_state == "none"
    intel_relevant = bool(
        cpu_vendor == "GenuineIntel"
        or intel.get("hardware_present")
        or intel.get("observable")
        or intel.get("pci_evidence")
    )
    if intel_relevant and intel_state == "disabled":
        evidence = _intel_me_evidence(intel) or ["intelmetool reported an explicit disabled Intel ME/CSME state"]
        _add_unique(findings, Finding(
            "intel-me-disabled",
            "Intel ME/CSME is reported disabled",
            "info",
            "visibility",
            "A chipset-aware probe reports the Intel Management Engine / CSME in an explicit disabled state.",
            "No action is required if this is the intended firmware configuration. Preserve this state as part of the machine baseline and re-check it after firmware changes.",
            evidence,
            "high",
            detailed="This is an inventory/security-state observation, not a compromise finding. A disabled engine is distinguished from a merely unavailable Linux MEI host interface.",
            section="platform-security-processor",
            finding_type="informational",
            evidence_ids=["intelmetool", "artifact:platform_security_processors", "kernel_journal", "lspci"],
        ))
    elif intel_relevant and physical_or_unknown and intel_state not in {"active", "host-interface-observable", "not-present"}:
        evidence = _intel_me_evidence(intel)
        if not evidence:
            evidence = ["Intel CPU/platform detected but no usable ME/CSME state interface was collected"]
        tool = intel.get("intelmetool") if isinstance(intel.get("intelmetool"), dict) else {}
        tool_state = str(tool.get("state") or "")
        if tool_state == "blocked":
            summary = "intelmetool was available but direct low-level hardware I/O was denied, so it could not establish the Intel ME/CSME state. This is a collection restriction, not evidence that the engine is absent or disabled."
            title = "Intel ME/CSME state is unresolved because intelmetool hardware access was blocked"
        elif tool_state == "inconclusive" and not intel.get("hardware_present"):
            summary = "No Intel HECI/MEI PCI function or Linux MEI host interface was observed, and intelmetool could not identify a usable ME PCI device. This is consistent with an absent, removed, firmware-hidden, or unsupported ME/CSME implementation, but the running OS cannot distinguish those states conclusively."
            title = "No Intel ME/CSME host interface was observed; engine state remains unresolved"
        elif tool_state == "inconclusive":
            summary = "intelmetool ran but could not identify a usable ME PCI device on this platform, so its output is inconclusive for Intel ME/CSME state."
            title = "Intel ME/CSME state is unresolved because intelmetool was inconclusive"
        elif intel_state == "host-interface-unavailable":
            summary = "Intel CSME/HECI hardware is present, but the Linux MEI host interface failed to initialize; the engine's actual enabled/disabled state is not established by that failure alone."
            title = "Intel ME/CSME state is unresolved because the MEI interface is unavailable"
        elif intel_state == "hardware-present-state-unknown":
            summary = "Intel CSME/HECI hardware is present, but the scan could not establish whether the security engine is active, disabled, or otherwise restricted."
            title = "Intel ME/CSME hardware is present but its state is unresolved"
        else:
            summary = "The scan could not establish the Intel ME/CSME enabled/disabled state from the available local evidence."
            title = "Intel ME/CSME state could not be established"
        _add_unique(findings, Finding(
            "intel-me-state-unknown",
            title,
            "info",
            "visibility",
            summary,
            "Keep the result as Unknown unless a chipset-aware source explicitly reports the engine disabled, active, or absent. If intelmetool is blocked by the running security environment, prefer a controlled maintenance/offline verification rather than weakening kernel security solely to make the probe run.",
            evidence,
            "high" if intel.get("hardware_present") else "medium",
            detailed="Firmware Audit deliberately does not equate MEI initialization failure, a hidden interface, or absence of /sys/class/mei entries with a disabled Intel security engine.",
            section="platform-security-processor",
            finding_type="unknown",
            evidence_ids=["intelmetool", "artifact:platform_security_processors", "kernel_journal", "lspci", "lscpu_json"],
        ))

    oob = _oob_artifact(report)
    intel_amt = oob.get("intel_amt") if isinstance(oob.get("intel_amt"), dict) else {}
    provisioned_amt = [
        item for item in (intel_amt.get("records") or [])
        if isinstance(item, dict) and item.get("provisioning_state") == "provisioned"
    ]
    if provisioned_amt:
        _add_unique(findings, Finding(
            "oob-management-provisioned",
            "Out-of-band management is provisioned",
            "info",
            "out-of-band-management",
            "A locally observable Intel AMT interface reports a provisioned out-of-band management configuration.",
            "Confirm that out-of-band management is intentionally provisioned and governed by your management-network policy.",
            [f"{item.get('name') or 'Intel AMT'}: provisioned; version={item.get('version') or 'unknown'}" for item in provisioned_amt],
            "high",
            section="out-of-band-management",
            finding_type="informational",
        ))


    dash = oob.get("dmtf_dash") if isinstance(oob.get("dmtf_dash"), dict) else {}
    if dash.get("state") == "enabled":
        _add_unique(findings, Finding(
            "oob-dash-enabled",
            "DMTF DASH management is enabled",
            "info",
            "out-of-band-management",
            "Local kernel or firmware settings report DMTF DASH out-of-band management enabled.",
            "Confirm that DASH is intentionally enabled and governed by your management-network policy.",
            list(dash.get("evidence") or ["DMTF DASH reported enabled"]),
            "high",
            section="out-of-band-management",
            finding_type="informational",
        ))

    enabled_persistence = [
        item for item in (oob.get("firmware_persistence") or [])
        if isinstance(item, dict) and item.get("state") == "firmware-enabled-agent-state-unknown"
    ]
    if enabled_persistence:
        _add_unique(findings, Finding(
            "firmware-persistence-enabled",
            "Firmware endpoint persistence capability is enabled",
            "info",
            "out-of-band-management",
            "Firmware exposes an endpoint persistence/manageability mechanism as enabled. This does not prove that an operating-system agent is installed or that the device is enrolled with a backend service.",
            "Confirm that this firmware capability matches organizational policy and, if relevant, separately verify operating-system agent/enrollment state.",
            [str(item.get("evidence") or item.get("setting") or "firmware persistence setting") for item in enabled_persistence],
            "high",
            section="out-of-band-management",
            finding_type="informational",
        ))


    # Cross-validate independent local Secure Boot sources on conventional UEFI.
    if _uses_conventional_uefi_boot(profile):
        trust_states = _secure_boot_sources(report, attrs)
        binary_states = {key: value for key, value in trust_states.items() if key in {"mokutil", "bootctl", "fwupd"} and value in {"enabled", "disabled"}}
        if len(set(binary_states.values())) > 1:
            _add_unique(findings, Finding(
                "boot-trust-inconsistent",
                "Boot-trust evidence is internally inconsistent",
                "medium",
                "integrity-signal",
                "Independent local sources disagree about whether Secure Boot is enabled.",
                "Review the raw Secure Boot, bootloader, fwupd, and firmware-variable evidence before changing the boot configuration.",
                [f"{name}: {value}" for name, value in sorted(trust_states.items())],
                "high",
                detailed="This is a consistency failure between locally collected evidence sources, not an online reputation or vendor lookup.",
                section="secure-boot",
                finding_type="integrity-indicator",
            ))

    replay = (report.get("artifacts", {}) or {}).get("tpm_eventlog_replay") or {}
    if isinstance(replay, dict) and replay.get("state") == "mismatch":
        mismatches = [item for item in replay.get("comparisons", []) if isinstance(item, dict) and not item.get("match")]
        diagnostics = replay.get("event_log_diagnostics") if isinstance(replay.get("event_log_diagnostics"), dict) else {}
        likely_truncated = bool(diagnostics.get("likely_truncated"))
        if likely_truncated:
            last_event = diagnostics.get("last_event") if isinstance(diagnostics.get("last_event"), dict) else {}
            boundary = diagnostics.get("capacity_boundary")
            delta = diagnostics.get("bytes_below_capacity_boundary")
            evidence = [
                f"event log size={diagnostics.get('raw_size')} bytes; near fixed capacity boundary={boundary} bytes; unused={delta} bytes",
                f"last parsed event={last_event.get('event_num')} PCR={last_event.get('pcr')} type={last_event.get('event_type')} summary={last_event.get('summary')}",
                f"replay mismatched PCRs={','.join(str(value) for value in diagnostics.get('mismatched_pcrs', []))}",
            ]
            _add_unique(findings, Finding(
                "tpm-eventlog-likely-truncated",
                "Measured-boot event log appears incomplete",
                "medium",
                "measurement-coverage",
                "The available TPM event log appears to have reached a fixed storage limit before measured boot completed, so some live PCR values cannot be reconstructed locally.",
                "Treat local measured-boot replay as incomplete on this boot. Firmware or bootloader event-log capacity should be reviewed if complete local attestation is required.",
                evidence,
                "high",
                compromise_indicator=False,
                detailed="The binary event log is very close to a fixed power-of-two capacity boundary, the parsed log ends during active bootloader measurement, and live PCRs continue to differ from replayed values. This pattern indicates incomplete measurement evidence rather than, by itself, compromise.",
                section="tpm-measured-boot",
                finding_type="protection-weakness",
            ))
        else:
            _add_unique(findings, Finding(
                "tpm-eventlog-replay-mismatch",
                "Measured-boot event log does not reconstruct the live TPM PCRs",
                "high",
                "integrity-signal",
                f"The locally replayed measured-boot log disagrees with {len(mismatches)} live TPM PCR value(s) in {replay.get('scope') or 'the compared range'}.",
                "Preserve the event log and PCR evidence and investigate firmware, bootloader, TPM-event-log, or tool compatibility before treating the measured-boot chain as reliable.",
                [f"{replay.get('algorithm')} PCR {item.get('pcr')}: replayed={item.get('replayed')} live={item.get('live')}" for item in mismatches[:12]],
                "high",
                compromise_indicator=True,
                detailed="tpm2_eventlog performs a local event-log replay and reports computed PCR values. Firmware event-log defects or parser compatibility problems can also cause mismatches, so an unexplained mismatch remains an investigation signal rather than automatic proof of compromise.",
                section="tpm-measured-boot",
                finding_type="integrity-indicator",
            ))

    # Aggregate all SPI write-related failures into one platform protection finding.
    spi_ids = {
        "org.fwupd.hsi.Amd.SpiWriteProtection",
        "org.fwupd.hsi.Spi.Bioswe",
        "org.fwupd.hsi.Spi.SmmBwp",
    }
    spi_failures = [attr for attr in failed_attrs if attr.get("appstream_id") in spi_ids]
    if not spi_failures:
        # Text-only fallback used by older tests/reports.
        spi_failures = [
            attr for attr in failed_attrs
            if "spi" in str(attr.get("name", "")).lower()
            and any(token in str(attr.get("name", "")).lower() for token in ("write", "flash"))
        ]
    if spi_failures:
        if _is_heads(profile):
            _add_unique(findings, Finding(
                "spi-write-protection",
                "Heads firmware update path is software-writable",
                "info",
                "firmware-protection",
                "Heads permits authenticated internal firmware updates, so conventional SPI write-blocking checks may not all pass. Heads provides tamper detection through measured and verified boot; this result is not evidence of weak integrity protection or modification.",
                "Keep the Heads verification workflow enabled and use the documented authenticated update process. Perform a separate hardware write-protection audit only when the threat model requires it.",
                [_attr_evidence(attr) for attr in spi_failures],
                "high",
                detailed=(
                    "The platform intentionally supports controlled internal firmware updates. The relevant security question is therefore whether unauthorized changes are detected and whether updates are authenticated, not whether every software write path is permanently disabled."
                ),
                technical="; ".join(_attr_evidence(attr) for attr in spi_failures),
                section="firmware-protection",
                finding_type="informational",
                evidence_ids=["fwupd_security_json", "fwupd_security_text", "tpm_eventlog"],
            ))
        else:
            _add_unique(findings, Finding(
                "spi-write-protection",
                "Firmware flash write protections are incomplete",
                "high",
                "firmware-protection",
                "Software with sufficient privilege may have more opportunity to rewrite firmware. This is a protection weakness, not evidence that modification occurred.",
                "Review the platform-specific firmware update and write-protection design, apply current firmware, and verify the result with vendor guidance or a platform-security tool.",
                [_attr_evidence(attr) for attr in spi_failures],
                "high",
                detailed=(
                    "At least one fwupd SPI protection attribute differs from its declared successful result. The writable path requires platform-specific verification."
                ),
                technical="; ".join(_attr_evidence(attr) for attr in spi_failures),
                section="firmware-protection",
                finding_type="protection-weakness",
                evidence_ids=["fwupd_security_json", "fwupd_security_text"],
            ))

    handled_ids = set(spi_ids)

    # Intel BootGuard exposes several independent policy attributes.  Aggregate
    # the protection properties so a platform is not labelled Good merely
    # because BootGuard itself and its OTP fuse are present while verified-boot
    # enforcement properties explicitly fail.  Heads/coreboot uses a different
    # trust model, so UEFI-oriented BootGuard policy is only actionable on the
    # conventional UEFI profile.
    bootguard_policy_ids = {
        "org.fwupd.hsi.IntelBootguard.Acm",
        "org.fwupd.hsi.IntelBootguard.Verified",
        "org.fwupd.hsi.IntelBootguard.Policy",
    }
    bootguard_failures = [attr for attr in failed_attrs if attr.get("appstream_id") in bootguard_policy_ids]
    if bootguard_failures and _is_physical_conventional_uefi(profile):
        _add_unique(findings, Finding(
            "intel-bootguard-policy",
            "Intel BootGuard protection policy is incomplete",
            "medium",
            "firmware-protection",
            "Intel BootGuard is present, but one or more locally reported verified-boot or error-policy protections do not match the expected secure state.",
            "Review the platform firmware configuration and current OEM firmware. Treat this as a protection weakness, not evidence that firmware was modified.",
            [_attr_evidence(attr) for attr in bootguard_failures],
            "high",
            compromise_indicator=False,
            detailed="The failed fwupd Host Security ID attributes concern BootGuard ACM protection, verified-boot enforcement, or the configured error policy. Passing BootGuard presence or fuse checks do not override explicit failures of these stronger policy properties.",
            section="firmware-protection",
            finding_type="protection-weakness",
        ))
    handled_ids.update(bootguard_policy_ids)

    # IOMMU and pre-boot DMA are parts of the same protection story.  When
    # both fail, report one finding with both evidence items rather than
    # making the machine look as though it has two independent problems.
    dma_ids = {"org.fwupd.hsi.Iommu", "org.fwupd.hsi.PrebootDma"}
    dma_failures = [attr for attr in failed_attrs if attr.get("appstream_id") in dma_ids]
    if dma_failures:
        failed_labels = [FWUPD_LABELS.get(str(attr.get("appstream_id") or ""), str(attr.get("name") or "DMA protection")) for attr in dma_failures]
        _add_unique(findings, Finding(
            "dma-isolation-protection",
            "DMA isolation protections are incomplete",
            "medium",
            "physical-security",
            "One or more protections that limit direct-memory access by peripherals are missing or disabled.",
            "Enable IOMMU and pre-boot DMA protection where supported. On stationary systems without exposed high-speed external PCIe paths, consider the physical threat model when prioritizing this finding.",
            [_attr_evidence(attr) for attr in dma_failures],
            "medium",
            detailed=(
                "IOMMU and pre-boot DMA protection are closely related controls, so Firmware Audit reports them as one condition when both are affected. "
                f"Locally failed controls: {', '.join(failed_labels)}."
            ),
            section="storage-memory",
            finding_type="data-exposure",
            evidence_ids=["fwupd_security_json", "fwupd_security_text", "iommu_kernel_log", "artifact:iommu_groups"],
        ))
    handled_ids.update(dma_ids)

    for attr in failed_attrs:
        appstream_id = str(attr.get("appstream_id") or "")
        key = f"{appstream_id} {attr.get('name')} {attr.get('result')}".lower()
        evidence = [_attr_evidence(attr)]
        if appstream_id in handled_ids:
            continue

        if appstream_id == "org.fwupd.hsi.Mei.ManufacturingMode":
            _add_unique(findings, Finding(
                "intel-me-manufacturing-mode",
                "Intel ME/CSME manufacturing mode is active",
                "high",
                "platform-security-processor",
                "The Intel platform security engine is reported in manufacturing mode rather than its expected locked production state.",
                "Apply the system manufacturer's documented firmware remediation or service procedure; do not treat this as a normal runtime setting.",
                evidence,
                "high",
                section="platform-security-processor",
                finding_type="protection-weakness",
            ))
        elif appstream_id == "org.fwupd.hsi.Mei.Version":
            _add_unique(findings, Finding(
                "intel-csme-firmware-policy",
                "Intel CSME firmware version failed the local security policy",
                "medium",
                "platform-security-processor",
                "The locally available fwupd Host Security ID policy does not consider the observed Intel CSME firmware version valid.",
                "Review the system manufacturer's current firmware and the locally cached fwupd metadata. No online lookup is performed by Firmware Audit.",
                evidence,
                "high",
                compromise_indicator=False,
                detailed="This result reports a local firmware-maintenance/security-policy failure. It does not by itself establish why the version is rejected and is not evidence that CSME or system firmware was modified.",
                section="platform-security-processor",
                finding_type="protection-weakness",
            ))
        elif appstream_id in {"org.fwupd.hsi.Amd.RollbackProtection", "org.fwupd.hsi.Amd.PlatformRollbackProtection"}:
            _add_unique(findings, Finding(
                "amd-platform-rollback-protection",
                "AMD Secure Processor rollback protection is disabled",
                "medium",
                "platform-security-processor",
                "The AMD platform reports that Secure Processor rollback protection is not enforced.",
                "Enable the platform's rollback protection where supported and apply current firmware.",
                evidence,
                "high",
                section="platform-security-processor",
                finding_type="protection-weakness",
            ))
        elif appstream_id == "org.fwupd.hsi.Amd.PlatformSecureBoot":
            _add_unique(findings, Finding(
                "amd-platform-secure-boot",
                "AMD Platform Secure Boot is disabled",
                "medium",
                "platform-security-processor",
                "The AMD Secure Processor reports that the platform firmware boot-integrity control is not enabled.",
                "Review the firmware security configuration and apply current platform firmware.",
                evidence,
                "high",
                section="platform-security-processor",
                finding_type="protection-weakness",
            ))
        elif appstream_id == "org.fwupd.hsi.EncryptedRam":
            if not _system_memory_encryption_active(report):
                _add_unique(findings, Finding(
                    "memory-encryption-not-active",
                    "System-memory encryption is not reported active",
                    "info",
                    "memory-protection",
                    "Local firmware/kernel evidence does not report whole-system RAM encryption as active. This is a capability/posture observation, not evidence of compromise.",
                    "If your threat model requires protection against physical DRAM access, enable a supported system-memory encryption mode in firmware.",
                    evidence,
                    "high",
                    section="memory-protection",
                    finding_type="informational",
                ))
        elif appstream_id == "org.fwupd.hsi.Bios.RollbackProtection" or ("rollback" in key and ".Amd." not in appstream_id):
            _add_unique(findings, Finding(
                "rollback-protection-bios",
                "Firmware rollback protection is missing or disabled",
                "medium",
                "firmware-protection",
                "An older vulnerable firmware version may be installable.",
                "Apply current firmware and enable rollback protection if the platform offers it.",
                evidence,
                "high",
            ))
        elif appstream_id in {"org.fwupd.hsi.PlatformDebugLocked", "org.fwupd.hsi.PlatformDebugEnabled"}:
            _add_unique(findings, Finding(
                "platform-debug",
                "Platform debugging is not locked",
                "high",
                "firmware-protection",
                "Debug interfaces can weaken platform isolation when left available.",
                "Disable or lock platform debugging in firmware and apply current vendor firmware.",
                evidence,
                "high",
            ))
        elif appstream_id == "org.fwupd.hsi.Uefi.BootserviceVars" and _uses_conventional_uefi_boot(profile):
            _add_unique(findings, Finding(
                "uefi-vars-unlocked",
                "UEFI boot-service variables are not locked",
                "high",
                "boot-protection",
                "Important UEFI variables may remain writable after they should have been locked.",
                "Apply vendor firmware updates and check Secure Boot and UEFI variable-protection settings.",
                evidence,
                "high",
            ))
        elif appstream_id == "org.fwupd.hsi.Uefi.Pk" and _uses_conventional_uefi_boot(profile):
            _add_unique(findings, Finding(
                "uefi-platform-key-invalid",
                "UEFI Platform Key is invalid or missing",
                "critical",
                "trust-store",
                "The top-level Secure Boot ownership key is not in the expected valid state.",
                "Preserve evidence, compare the key database with vendor defaults, and use the documented recovery procedure before changing keys.",
                evidence,
                "high",
                True,
            ))
        elif appstream_id == "org.fwupd.hsi.Uefi.Db" and _uses_conventional_uefi_boot(profile):
            _add_unique(findings, Finding(
                "uefi-db-invalid",
                "UEFI signature database is invalid",
                "critical",
                "trust-store",
                "The Secure Boot allow-list is reported invalid. This may be a broken configuration or an integrity concern.",
                "Preserve the current key output, compare it with vendor defaults, and use the vendor recovery procedure before changing keys.",
                evidence,
                "high",
                True,
            ))
        elif appstream_id == "org.fwupd.hsi.Kernel.Swap" or (not appstream_id and "swap" in key):
            # Handled once after the loop using the actual block topology.
            continue
        elif appstream_id == "org.fwupd.hsi.Kernel.Tainted":
            continue
        elif appstream_id == "org.fwupd.hsi.SuspendToRam":
            _add_unique(findings, Finding(
                "sleep-exposure",
                "Suspend-to-RAM may retain secrets in memory",
                "low",
                "physical-security",
                "The disks and swap can remain fully encrypted while the running session and active encryption keys remain in powered RAM during sleep.",
                "For high-risk travel or unattended systems, prefer shutdown or encrypted hibernation; ordinary disk removal remains protected by encryption.",
                evidence,
                "high",
                section="storage-memory",
                finding_type="informational",
                evidence_ids=["fwupd_security_json", "power_mem_sleep", "power_state"],
            ))
        elif appstream_id == "org.fwupd.hsi.SuspendToIdle":
            # Suspend-to-idle being disabled does not by itself prove memory exposure.
            continue
        elif appstream_id == "org.fwupd.hsi.Uefi.SecureBoot" and _uses_conventional_uefi_boot(profile):
            if "secureboot disabled" not in sb and "secure boot disabled" not in sb:
                _add_unique(findings, Finding(
                    "secure-boot-fwupd",
                    "Secure Boot is not in the expected enabled state",
                    "medium",
                    "boot-protection",
                    "fwupd reports that Secure Boot is disabled or unavailable. This is a protection gap, not proof of compromise.",
                    "Confirm the state with mokutil and firmware setup, then enable Secure Boot after checking signatures.",
                    evidence,
                    "high",
                ))
        elif appstream_id == "org.fwupd.hsi.Kernel.Lockdown":
            if _uses_conventional_uefi_boot(profile) and ("secureboot enabled" in sb or "secure boot enabled" in sb):
                _add_unique(findings, Finding(
                    "kernel-lockdown-disabled",
                    "Kernel lockdown is disabled despite Secure Boot",
                    "medium",
                    "operating-system",
                    "Secure Boot is enabled, but the running kernel does not appear to restrict interfaces that can undermine kernel integrity.",
                    "Use the distribution-supported signed kernel and confirm that Secure Boot lockdown is activated.",
                    evidence,
                    "high",
                    section="kernel-runtime",
                    finding_type="protection-weakness",
                ))
        elif appstream_id == "org.fwupd.hsi.Tpm.ReconstructionPcr0":
            if _is_heads(profile) and _heads_measurements_present(report):
                # fwupd's UEFI-oriented PCR0 reconstruction is not an end-user
                # finding for the Heads measurement layout. Raw fwupd evidence
                # remains available on the forensic page.
                continue
            else:
                _add_unique(findings, Finding(
                    "tpm-pcr0-reconstruction-failed",
                    "TPM PCR0 reconstruction did not validate",
                    "low",
                    "measured-boot",
                    "fwupd could not reconstruct the expected PCR0 value from the available event log.",
                    "Review the event log, PCR values, firmware updates, and platform-specific measured-boot behavior.",
                    evidence,
                    "medium",
                    section="tpm-measured-boot",
                    finding_type="unknown",
                ))
        elif appstream_id == "org.fwupd.hsi.Fwupd.Plugins":
            _add_unique(findings, Finding(
                "fwupd-plugins-tainted",
                "fwupd reports a plugin-integrity problem",
                "low",
                "evidence-integrity",
                "The firmware inventory service reports that one or more plugins are tainted or not in the expected state.",
                "Review the raw fwupd version and plugin output before relying on firmware metadata.",
                evidence,
                "high",
                section="firmware-baseline",
                finding_type="integrity-indicator",
            ))
        elif not appstream_id:
            # Text-only legacy fallback for explicit failure markers.
            legacy_name = str(attr.get("name") or "").lower()
            legacy_result = str(attr.get("result") or "").lower()
            if "uefi db" in legacy_name and "invalid" in legacy_result and _uses_conventional_uefi_boot(profile):
                _add_unique(findings, Finding(
                    "uefi-db-invalid",
                    "UEFI signature database is invalid",
                    "critical",
                    "trust-store",
                    "The Secure Boot allow-list is reported invalid.",
                    "Preserve the current key output and compare it with vendor defaults.",
                    evidence,
                    "medium",
                    True,
                ))

    # Determine swap protection directly from the active swap inventory and
    # storage topology. fwupd's Kernel.Swap attribute is intentionally ignored.
    topology = _swap_topology(report)
    swap_evidence = []
    for item in topology.get("swap_devices", []):
        chain = " -> ".join(item.get("chain", []) or [])
        swap_evidence.append(f"{item.get('target')}: {item.get('protection')}" + (f" via {chain}" if chain else ""))

    if topology.get("state") in {"encrypted", "ram-backed"}:
        # A protected swap configuration is a successful check, not a finding.
        pass
    elif topology.get("state") == "unencrypted":
        _add_unique(findings, Finding(
            "swap-unencrypted",
            "One or more active swap targets are not encrypted",
            "medium",
            "data-protection",
            "Memory pages written to an unencrypted disk-backed swap target may be recoverable from storage.",
            "Place every disk-backed swap target inside encrypted storage or use RAM-backed swap.",
            swap_evidence,
            "high",
            section="storage-memory",
            finding_type="data-exposure",
            evidence_ids=["proc_swaps", "swapon_text", "lsblk_json", "mounts", "dmsetup_tree", "artifact:swap_topology"],
        ))
    elif topology.get("state") == "unknown":
        _add_unique(findings, Finding(
            "swap-encryption-unknown",
            "Swap protection could not be determined",
            "low",
            "visibility",
            "The active swap inventory could not be mapped reliably to its backing storage.",
            "Review the active swap and storage topology in the raw evidence.",
            swap_evidence or ["Active swap topology could not be reconstructed"],
            "medium",
            section="storage-memory",
            finding_type="unknown",
            evidence_ids=["proc_swaps", "swapon_text", "lsblk_json", "mounts", "artifact:swap_topology"],
        ))

    lockdown = _stdout(report, "kernel_lockdown").lower()
    if _uses_conventional_uefi_boot(profile) and ("secureboot enabled" in sb or "secure boot enabled" in sb) and ("[none]" in lockdown or lockdown.strip() == "none"):
        _add_unique(findings, Finding(
            "kernel-lockdown-disabled",
            "Kernel lockdown is disabled despite Secure Boot",
            "medium",
            "operating-system",
            "Secure Boot is enabled, but the running kernel does not appear to restrict interfaces that can undermine kernel integrity.",
            "Use the distribution-supported signed kernel and confirm that Secure Boot lockdown is activated.",
            [f"kernel lockdown: {lockdown.strip() or 'unknown'}"],
            "medium",
            section="kernel-runtime",
            finding_type="protection-weakness",
        ))


    cpu_state = _cpu_vulnerability_summary(report)
    if cpu_state["vulnerable"]:
        if virt and virt != "none":
            cpu_recommendation = (
                "Because this system is a virtual machine, review the physical hypervisor's CPU microcode and kernel mitigations, "
                "and review the VM CPU model/configuration exposed to this guest. Also keep the guest kernel current."
            )
            cpu_detail = (
                "This result comes directly from the guest kernel's vulnerability status interface. In a VM, some mitigation and "
                "microcode state is controlled by the physical hypervisor and the virtual CPU model rather than by the guest alone. "
                "Firmware Audit does not contact a CVE service or compare against an online microcode catalog."
            )
        else:
            cpu_recommendation = "Review the local kernel and CPU microcode state and enable mitigations that are appropriate for this hardware and workload."
            cpu_detail = "This result comes directly from the kernel's local vulnerability status interface. Firmware Audit does not contact a CVE service or compare against an online microcode catalog."
        _add_unique(findings, Finding(
            "cpu-vulnerability-unmitigated",
            "The running kernel reports unmitigated processor vulnerabilities",
            "medium",
            "host-security",
            f"{len(cpu_state['vulnerable'])} processor vulnerability class(es) are reported as vulnerable by the running kernel.",
            cpu_recommendation,
            [f"{item['name']}: {item['value']}" for item in cpu_state["vulnerable"][:20]],
            "high",
            detailed=cpu_detail,
            section="kernel-runtime",
            finding_type="protection-weakness",
        ))

    cmdline_security = _kernel_commandline_security(report)
    direct_overrides = [item for item in cmdline_security if item.get("impact") in {"high", "medium"}]
    tb_state = _thunderbolt_exposure(report)
    iommu_overrides = [item for item in cmdline_security if item.get("class") == "iommu"]
    if tb_state.get("state") == "exposed":
        _add_unique(findings, Finding(
            "thunderbolt-dma-exposure",
            "External PCIe DMA protection is incomplete",
            "medium",
            "physical-security",
            "Thunderbolt/USB4 exposes external PCIe connectivity without local evidence of IOMMU DMA protection or effective port security.",
            "Enable IOMMU/DMA remapping and the platform's Thunderbolt/USB4 security controls, or disable external PCIe tunnelling when it is not required.",
            list(tb_state.get("evidence") or [])[:20],
            "high",
            section="storage-memory",
            finding_type="data-exposure",
        ))
    if iommu_overrides and tb_state.get("state") in {"exposed", "protected-or-controlled"}:
        direct_overrides.extend(iommu_overrides)

    if direct_overrides:
        _add_unique(findings, Finding(
            "security-boot-parameter",
            "Boot parameters explicitly disable security protections",
            "medium" if not any(item.get("impact") == "high" for item in direct_overrides) else "high",
            "host-security",
            "The active kernel command line contains one or more parameters that explicitly disable processor, kernel, or DMA protections.",
            "Confirm that every listed override is intentional and required; remove security-degrading parameters that are no longer necessary.",
            [f"{item['token']}: {item['meaning']}" for item in direct_overrides],
            "high",
            detailed="The rule operates on documented protection-control parameters in the active local kernel command line. It does not use an online hardening profile.",
            section="kernel-runtime",
            finding_type="protection-weakness",
        ))

    integrity_state = _integrity_framework_state(report)
    ima_override = [item for item in cmdline_security if item.get("class") == "ima"]
    if integrity_state.get("ima") and ima_override and "appraise" in str(integrity_state.get("ima_policy") or ""):
        _add_unique(findings, Finding(
            "ima-appraisal-disabled",
            "IMA appraisal policy is present but appraisal is disabled at boot",
            "medium",
            "host-security",
            "The local IMA policy contains appraisal rules while the active kernel command line explicitly disables IMA appraisal.",
            "Verify the intended IMA policy and remove ima_appraise=off if appraisal enforcement is expected.",
            [item["token"] for item in ima_override],
            "high",
            section="kernel-runtime",
            finding_type="protection-weakness",
            evidence_ids=["proc_cmdline", "artifact:integrity_frameworks"],
        ))

    taint_text = _stdout(report, "kernel_taint").strip()
    try:
        taint_value = int(taint_text)
    except ValueError:
        taint_value = 0
    taints = decode_taint(taint_value)
    journal = _stdout(report, "kernel_journal")
    journal_lower = journal.lower()
    modules = _kernel_modules(report)

    if taints:
        codes = {item["code"] for item in taints}
        evidence = [f"taint value {taint_value}: " + ", ".join(item["text"] for item in taints)]
        module_codes = codes & {"out-of-tree", "proprietary-module", "staging-driver", "live-patched"}
        module_observations = _module_observations(modules, module_codes)
        module_evidence = [_format_module_observation(item) for item in module_observations[:12]]

        if module_codes:
            managed = [item for item in module_observations if item.get("package_owner")]
            unmanaged = [item for item in module_observations if not item.get("package_owner")]
            if module_observations:
                origin_summary = ", ".join(sorted({str(item.get("origin") or "unknown") for item in module_observations}))
                summary = (
                    f"The running kernel reports non-distribution or specially built module code. "
                    f"{len(module_observations)} relevant loaded module(s) were identified from module metadata; observed origins: {origin_summary}."
                )
            else:
                summary = (
                    "The running kernel reports non-distribution, proprietary, staging, or live-patched code, "
                    "but the collected module metadata did not identify a specific responsible module."
                )
            detail = (
                "This state can result from DKMS, vendor-supplied modules, staging drivers, or live patching. "
                "It is classified from module location, package ownership, signature metadata, license metadata, "
                "and kernel taint semantics rather than from application or vendor names."
            )
            if unmanaged:
                detail += f" Package ownership could not be identified for {len(unmanaged)} relevant module(s); that is useful review context but is not proof of compromise."
            elif managed:
                detail += " The relevant modules with identified ownership are associated with packages in the local package database."
            _add_unique(findings, Finding(
                "kernel-external-module-state",
                "Non-distribution kernel module state is present",
                "low",
                "compatibility",
                summary,
                "Confirm that externally built, proprietary, staging, or live-patched kernel code is intentional. Review module origin and package ownership when it is not expected.",
                evidence + module_evidence,
                "high",
                detailed=detail,
                technical=(
                    f"Decoded module-related taint codes: {', '.join(sorted(module_codes))}. "
                    f"Relevant module records: {len(module_observations)}; package-owned: {len(managed)}; package owner not identified: {len(unmanaged)}."
                ),
                section="kernel-runtime",
                finding_type="compatibility-issue",
            ))

        if "unsigned-module" in codes:
            _add_unique(findings, Finding(
                "kernel-unsigned-module",
                "Unsigned or kernel-untrusted module code is loaded",
                "medium",
                "operating-system",
                "The kernel's unsigned-module taint flag is set, meaning at least one loaded module was unsigned or was not accepted as trusted by the running kernel's module-signing policy.",
                "Identify the module, verify its origin and signing trust, and use a distribution-signed or locally trusted build where possible.",
                evidence + module_evidence,
                "high",
                detailed=(
                    "The unsigned-module taint flag is a kernel-provided fact. A module can contain signature metadata yet still be untrusted by the running kernel, for example when a local DKMS signing key is not accepted by the active trust policy. Module names are shown only when they can be derived from collected metadata; the assessment does not rely on a product-specific allowlist."
                ),
                section="kernel-runtime",
                finding_type="protection-weakness",
            ))

        if "kernel-warning" in codes:
            warning_lines = _kernel_warning_evidence(journal)
            _add_unique(findings, Finding(
                "kernel-warning-state",
                "Kernel warning state was recorded",
                "info",
                "reliability",
                "The running kernel is tainted because it issued a warning during this boot.",
                "No security action is required from the warning taint flag alone. Review the warning and affected subsystem if there are reliability symptoms or if the event is unexpected.",
                evidence + warning_lines,
                "high",
                detailed=(
                    "A kernel warning is diagnostic evidence of an abnormal code path, but the warning taint bit by itself does not show that kernel or firmware code was modified. "
                    "The assessment does not identify or whitelist a particular driver; representative journal lines are preserved as evidence."
                ),
                section="kernel-runtime",
                finding_type="informational",
            ))

        remaining_codes = codes - module_codes - {"unsigned-module", "kernel-warning"}
        if remaining_codes:
            critical_codes = remaining_codes & {"kernel-oops", "machine-check", "soft-lockup"}
            severity = "high" if critical_codes else "medium"
            _add_unique(findings, Finding(
                "kernel-diagnostic-state",
                "Kernel diagnostic taint is set",
                severity,
                "reliability",
                "The kernel recorded one or more diagnostic conditions that should be considered during forensic analysis.",
                "Review the decoded flags and surrounding kernel journal entries.",
                evidence + _kernel_warning_evidence(journal),
                "high",
                detailed="The interpretation is based on kernel-defined taint flags and collected runtime evidence, not on a list of known applications or drivers.",
                technical=f"Remaining decoded taint codes: {', '.join(sorted(remaining_codes))}.",
                section="kernel-runtime",
                finding_type="reliability-issue",
            ))

    amd_state = (report.get("artifacts", {}) or {}).get("amd_secure_processor_state")
    if not isinstance(amd_state, dict):
        amd_state = derive_amd_secure_processor_state(report)
    if amd_state.get("state") == "initialization-needs-review":
        observed = ["CCP interface access failure was logged"]
        observed.append(f"TEE initialized: {bool(amd_state.get('tee_enabled'))}")
        observed.append(f"PSP initialized: {bool(amd_state.get('psp_enabled'))}")
        _add_unique(findings, Finding(
            "amd-secure-processor-incomplete",
            "AMD secure-processor initialization needs review",
            "low",
            "compatibility",
            "A cryptographic coprocessor access failure was recorded and the expected Secure Processor initialization messages were not both observed.",
            "Use current firmware and kernel packages. Treat this as a compatibility issue unless other evidence indicates a broader firmware failure.",
            observed,
            "high",
            section="platform-security-processor",
            finding_type="compatibility-issue",
            evidence_ids=["kernel_journal", "artifact:amd_secure_processor_state", "artifact:platform_security_processors"],
        ))
    elif amd_state.get("state") == "secure-processor-initialized-with-ccp-interface-warning":
        observed = ["CCP interface access warning was logged", "TEE initialized: True", "PSP initialized: True"]
        _add_unique(findings, Finding(
            "amd-ccp-interface-warning",
            "AMD PSP initialized with a CCP interface warning",
            "info",
            "compatibility",
            "The AMD Secure Processor and TEE initialized, but the kernel also reported that the CCP interface could not be accessed. This can be platform/kernel specific and is not by itself evidence of firmware compromise.",
            "No immediate security action is implied. Review BIOS/kernel compatibility if CCP functionality is expected or if the warning appears after a firmware or kernel change.",
            observed,
            "high",
            compromise_indicator=False,
            detailed="Successful PSP and TEE initialization prevents this warning from being treated as an initialization failure. The warning remains visible as a compatibility/security note instead of disappearing from the assessment.",
            section="platform-security-processor",
            finding_type="compatibility-issue",
            evidence_ids=["kernel_journal", "artifact:amd_secure_processor_state", "artifact:platform_security_processors"],
        ))

    signature_patterns = [
        "secure boot violation",
        "verification failed: (15) access denied",
        "bad shim signature",
        "invalid signature detected",
    ]
    matched = [pattern for pattern in signature_patterns if pattern in journal_lower]
    if matched:
        _add_unique(findings, Finding(
            "boot-signature-failure",
            "Boot-component signature verification failed",
            "high",
            "integrity-signal",
            "The kernel log contains a signature-verification failure. This may be an expected blocked component, but it requires examination.",
            "Inspect the surrounding boot log, identify the rejected component, and preserve the evidence before making changes.",
            matched,
            "medium",
            True,
        ))

    updates_text = _combined(report, "fwupd_updates_json").lower()
    if updates_text and not any(token in updates_text for token in ("no updatable devices", "no updates available", '"devices":[]', '"releases":[]')):
        updates_json = _parse_json_output(report, "fwupd_updates_json")
        likely_has_update = False
        if updates_json is not None:
            for obj in _walk_json(updates_json):
                if obj.get("Releases") not in (None, []):
                    likely_has_update = True
                    break
        if likely_has_update:
            _add_unique(findings, Finding(
                "firmware-updates-available",
                "Firmware updates appear to be available",
                "medium",
                "maintenance",
                "The vendor or LVFS may provide newer firmware containing security or reliability fixes.",
                "Review and install official firmware updates using the vendor-supported process.",
                ["fwupdmgr reported available release data"],
                "medium",
            ))

    newer_kernel = _newer_installed_kernel(report)
    if newer_kernel:
        running_kernel, newest_kernel = newer_kernel
        _add_unique(findings, Finding(
            "newer-installed-kernel",
            "A newer installed kernel is not currently running",
            "info",
            "maintenance",
            f"The machine is running kernel {running_kernel}, while newer installed kernel {newest_kernel} is available locally. This often means a reboot is pending, but the older kernel may also have been selected deliberately.",
            "If the newer kernel was installed as part of a normal update, reboot when operationally appropriate and confirm the expected kernel starts. If the older kernel is intentional, no change is required.",
            [f"running kernel: {running_kernel}", f"newest installed kernel: {newest_kernel}"],
            "high",
            detailed="This comparison uses only local installed-kernel package/module information. Firmware Audit does not contact distribution repositories and therefore does not claim that the newest available online kernel is installed.",
            section="updates",
            finding_type="informational",
            evidence_ids=["system:kernel"],
        ))

    if _is_heads(profile):
        _add_unique(findings, Finding(
            "heads-update-unverified",
            "Heads firmware update status was not verified by fwupd",
            "info",
            "visibility",
            "fwupd is not treated as an authoritative source for the installed Heads firmware release status.",
            "Compare the installed Dasharo/Heads version with the release channel and update procedure for the exact hardware model.",
            ["Detected coreboot-heads platform", "Local fwupd metadata does not establish the latest Heads release"],
            "high",
            section="updates",
            finding_type="unknown",
            evidence_ids=["dmidecode_bios", "fwupd_updates_json", "fwupd_devices_json"],
        ))

    if _is_heads(profile) and _heads_measurements_present(report):
        _add_unique(findings, Finding(
            "heads-measurements-present",
            "Coreboot/Heads TPM measurements were collected",
            "info",
            "measured-boot",
            "The parsed event log contains coreboot CBFS/FMAP measurements suitable for event-log replay or external attestation.",
            "Preserve the binary event log and PCR values and compare them after intentional firmware or boot changes.",
            ["tpm2_eventlog output contains CBFS/FMAP measurements"],
            "high",
            section="tpm-measured-boot",
            finding_type="informational",
            evidence_ids=["tpm_eventlog", "tpm_pcrs", "artifact:tpm_eventlog"],
        ))


    package_analysis = (report.get("artifacts", {}) or {}).get("package_verify_analysis")
    if isinstance(package_analysis, dict):
        package_records = [item for item in package_analysis.get("records", []) if isinstance(item, dict)]
        security_drift = [item for item in package_records if item.get("classification") == "security_relevant"]
        other_drift = [item for item in package_records if item.get("classification") in {"other_drift", "unparsed"}]
        config_drift = [item for item in package_records if item.get("classification") == "configuration"]
        ignored_drift = [item for item in package_records if item.get("classification") == "ignored"]
        package_backend_available = bool(package_analysis.get("available", True))
    else:
        security_drift = []
        other_drift = []
        config_drift = []
        ignored_drift = []
        package_backend_available = False

    if not package_backend_available:
        _add_unique(findings, Finding(
            "package-verification-unavailable",
            "Package-file verification is unavailable",
            "info",
            "host-integrity",
            "The collector could not verify installed files against the local package-manager database on this system.",
            "Install or enable a supported package-verification backend, or review package integrity with the platform's native tools.",
            ["No supported package-file verification result was collected"],
            "high",
            section="host-integrity",
            finding_type="unknown",
            evidence_ids=["dpkg_verify", "artifact:package_verify_analysis"],
        ))

    if security_drift:
        evidence = []
        for item in security_drift[:100]:
            path = str(item.get("path") or item.get("raw") or "unknown path")
            role = str(item.get("file_role") or "security-sensitive package file")
            digest = str(item.get("sha256") or "")
            owner = str(item.get("package_owner") or "")
            suffix = (f"; package={owner}" if owner else "") + (f"; sha256={digest}" if digest else "")
            evidence.append(f"{path}: {role}" + suffix)
        _add_unique(findings, Finding(
            "package-files-modified",
            "Security-sensitive installed files differ from package metadata",
            "medium",
            "host-integrity",
            f"{len(security_drift)} changed or missing package-owned file(s) can affect executable code, libraries, startup behavior, kernel code, or boot components.",
            "Review the listed paths and restore unexplained changes from trusted distribution packages. Local package metadata detects drift but does not by itself prove malicious modification.",
            evidence,
            "high",
            detailed=(
                "Only security-relevant package drift is elevated. Locally modified package configuration, documentation, registered diversions, and ordinary non-executable data do not create an alarm."
            ),
            technical=(
                f"Security-relevant records: {len(security_drift)}; other unexplained records: {len(other_drift)}; "
                f"local configuration records: {len(config_drift)}; ignored records: {len(ignored_drift)}."
            ),
            section="host-integrity",
            finding_type="integrity-indicator",
            evidence_ids=["dpkg_verify", "artifact:package_verify_analysis", "dpkg_diversions", "dpkg_statoverrides"],
        ))
    if other_drift:
        _add_unique(findings, Finding(
            "package-noncritical-drift",
            "Other package-owned files have local differences",
            "info",
            "host-integrity",
            f"{len(other_drift)} package-owned file(s) differ from local package metadata, but they were not classified as executable, library, kernel, boot, authentication, or startup code.",
            "No immediate security action is required. Review the raw paths if these local changes are unexpected.",
            [str(item.get("path") or item.get("raw") or "unknown path") for item in other_drift[:50]],
            "medium",
            section="host-integrity",
            finding_type="informational",
            evidence_ids=["dpkg_verify", "artifact:package_verify_analysis"],
        ))

    preload_entries = _ld_preload_entries(report)
    if preload_entries:
        _add_unique(findings, Finding(
            "dynamic-loader-preload",
            "System-wide dynamic-loader preloading is configured",
            "medium",
            "host-integrity",
            "/etc/ld.so.preload contains active library entries. This can be legitimate, but it is also a powerful process-injection and persistence mechanism.",
            "Verify every listed library, its package ownership and hash, and remove entries that are not explicitly required.",
            preload_entries,
            "high",
            section="host-integrity",
            finding_type="integrity-indicator",
            evidence_ids=["artifact:host_persistence_files"],
        ))

    aide = _command(report, "aide_check")
    if aide.get("status") == "collected" and int(aide.get("returncode") or 0) in range(1, 8):
        _add_unique(findings, Finding(
            "aide-differences",
            "AIDE reported filesystem differences",
            "medium",
            "host-integrity",
            "The optional AIDE reference database reports added, removed, or changed filesystem objects.",
            "Review the AIDE summary and confirm every reported object before updating its database.",
            [line for line in str(aide.get("stdout") or "").splitlines() if line.strip()][-100:],
            "medium",
            section="host-integrity",
            finding_type="integrity-indicator",
            evidence_ids=["aide_check"],
        ))

    tpm_devices = report.get("artifacts", {}).get("tpm_devices", [])
    if not tpm_devices and not _available(report, "tpm_properties", profile):
        if _is_vm(profile):
            tpm_title = "Virtual TPM was not exposed to the guest"
            tpm_summary = "The guest has no visible /dev/tpm* device, so guest measured boot and TPM-backed attestation cannot be established from this scan."
            tpm_recommendation = "If guest measured boot or attestation is required, configure a vTPM in the hypervisor and rerun the scan."
            tpm_evidence = ["No guest /dev/tpm* device and no TPM capability output"]
        else:
            tpm_title = "TPM was not observed"
            tpm_summary = "Measured boot and hardware-backed attestation may be unavailable, disabled, or simply not visible to the collector."
            tpm_recommendation = "Check firmware TPM settings and confirm that tpm2-tools can access the local TPM device."
            tpm_evidence = ["No /dev/tpm* device and no TPM capability output"]
        _add_unique(findings, Finding(
            "tpm-not-observed",
            tpm_title,
            "low",
            "measured-boot",
            tpm_summary,
            tpm_recommendation,
            tpm_evidence,
            "medium",
        ))


    if _is_vm(profile):
        # Host firmware write protection and physical OOB management are outside a normal
        # guest's trust boundary. Suppress any guest-visible proxy findings rather than
        # letting them imply a conclusion about the physical hypervisor host.
        findings = [
            item for item in findings
            if (item.section or CATEGORY_TO_SECTION.get(item.category, "firmware-baseline"))
            not in {"firmware-protection", "out-of-band-management"}
        ]

    findings.sort(key=lambda item: (-SEVERITY_ORDER[item.severity], item.title.lower()))
    compromise = [item for item in findings if item.compromise_indicator]
    actionable = [
        item for item in findings
        if (item.finding_type or _finding_type(item.category, item.compromise_indicator)) in ACTIONABLE_TYPES
        and item.severity in {"low", "medium", "high", "critical"}
    ]

    if compromise:
        status = "investigate"
        headline = "Potential integrity indicators require investigation"
        explanation = "The scan found signals that may reflect a trust-store or signature problem. They are not automatic proof of malicious firmware, but evidence should be preserved and reviewed."
    elif actionable:
        status = "attention"
        headline = "Security improvements require attention"
        explanation = "The scan did not find direct evidence of firmware compromise. It identified one or more meaningful conditions that can be acted on or require investigation."
    else:
        status = "good"
        headline = "No obvious compromise indicators were found"
        explanation = "The checks did not reveal a clear integrity problem. This is not proof that firmware is clean; sophisticated firmware compromise cannot be ruled out from the running operating system alone."

    assessment = {
        "status": status,
        "headline": headline,
        "explanation": explanation,
        "generated_from_report": report.get("report_id"),
        "platform_profile": profile,
        "findings": [finding.to_dict() for finding in findings],
        "taint": {"value": taint_value, "decoded": taints},
        "limitations": [
            "A running operating system cannot conclusively prove that its underlying firmware is clean.",
            "DMI strings, firmware version strings, and OS-visible logs can be incomplete or misleading.",
            "Runtime DMI and ACPI hashes are not a hash of the complete installed SPI flash image.",
            "Heads-specific token state and signing-key ownership are not verified unless explicitly collected.",
            "High-assurance verification may require TPM attestation, vendor recovery, or an external SPI-flash read.",
        ],
    }
    return rebuild_assessment_sections(report, assessment)
