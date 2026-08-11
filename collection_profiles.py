"""Collection-only security capability profiles.

These profiles describe which evidence the collector preserves.  They do not
score the machine and do not claim that a capability is enabled merely because
an evidence source was available.
"""

from __future__ import annotations

from typing import Any


CONVENTIONAL_UEFI_PROFILE_ID = "conventional-uefi-dasharo-like-v1"

CONVENTIONAL_UEFI_CHECKS: list[dict[str, Any]] = [
    {
        "id": "firmware-write-resistance",
        "title": "Firmware write resistance",
        "dasharo_feature": "SPI controller and chipset write protections",
        "purpose": "Collect evidence about whether privileged software can rewrite critical firmware regions.",
        "sources": ["fwupd HSI", "Linux firmware attributes"],
        "evidence_ids": [
            "fwupd_security_json", "fwupd_security_text", "fwupd_bios_settings_json",
            "artifact:firmware_attributes",
        ],
        "limitation": "Linux-only collection does not test an external hardware write-protect pin or attempt a flash write.",
    },
    {
        "id": "hardware-flash-protection",
        "title": "Hardware flash protection",
        "dasharo_feature": "Hardware-protected flash region",
        "purpose": "Preserve any Linux-visible evidence of protected flash regions and firmware update policy.",
        "sources": ["fwupd HSI", "fwupd device metadata"],
        "evidence_ids": ["fwupd_security_json", "fwupd_devices_json"],
        "limitation": "A hardware WP pin and external-programmer resistance cannot be proven from a normal Linux scan.",
    },
    {
        "id": "hardware-verified-firmware-boot",
        "title": "Hardware-verified firmware boot",
        "dasharo_feature": "Intel Boot Guard or equivalent verified boot",
        "purpose": "Collect CPU-vendor and fwupd evidence for Intel Boot Guard or AMD Platform Secure Boot.",
        "sources": ["fwupd HSI", "SMBIOS", "lscpu"],
        "evidence_ids": ["fwupd_security_json", "fwupd_security_text", "lscpu_json", "dmidecode_bios"],
        "limitation": "The collector records fwupd/kernel-visible state; it does not independently inspect fused keys.",
    },
    {
        "id": "measured-boot",
        "title": "TPM measured boot",
        "dasharo_feature": "Measured boot",
        "purpose": "Collect TPM capabilities, PCR banks, and the binary and parsed measured-boot event log.",
        "sources": ["Linux TPM resource manager", "tpm2-tools", "fwupd HSI"],
        "evidence_ids": [
            "tpm_properties", "tpm_algorithms", "tpm_pcrs", "tpm_eventlog",
            "artifact:tpm_eventlog", "fwupd_security_json",
        ],
        "limitation": "PCR values require event-log replay or external attestation before they become integrity conclusions.",
    },
    {
        "id": "uefi-secure-boot",
        "title": "UEFI Secure Boot",
        "dasharo_feature": "Secure Boot",
        "purpose": "Collect Secure Boot state, UEFI trust databases, boot entries, EFI variables, and kernel lockdown.",
        "sources": ["mokutil", "efivarfs", "efibootmgr", "systemd bootctl", "Linux lockdown"],
        "evidence_ids": [
            "secure_boot_state", "mok_pk", "mok_kek", "mok_db", "mok_dbx", "mok_enrolled",
            "efibootmgr", "bootctl", "kernel_lockdown", "efi_platform_size", "artifact:efi_variables",
        ],
        "limitation": "Collection does not execute an unsigned boot component to test rejection.",
    },
    {
        "id": "smm-firmware-isolation",
        "title": "SMM firmware isolation",
        "dasharo_feature": "SMM BIOS protection",
        "purpose": "Collect fwupd HSI attributes related to SMM BIOS write protection and platform isolation.",
        "sources": ["fwupd HSI"],
        "evidence_ids": ["fwupd_security_json", "fwupd_security_text"],
        "limitation": "No CHIPSEC driver is loaded; low-level SMRAM and SMM code checks are outside this simple profile.",
    },
    {
        "id": "early-dma-protection",
        "title": "Early DMA protection",
        "dasharo_feature": "Pre-boot DMA protection",
        "purpose": "Collect fwupd pre-boot DMA attributes, ACPI tables, Linux IOMMU groups, and relevant kernel messages.",
        "sources": ["fwupd HSI", "Linux IOMMU sysfs", "kernel journal", "ACPI DMAR/IVRS"],
        "evidence_ids": [
            "fwupd_security_json", "iommu_kernel_log", "artifact:iommu_groups",
            "artifact:firmware_runtime_hashes",
        ],
        "limitation": "Linux IOMMU activation alone does not prove protection was active before the OS started.",
    },
    {
        "id": "authenticated-firmware-updates",
        "title": "Authenticated firmware updates",
        "dasharo_feature": "Signed firmware updates",
        "purpose": "Collect update-capable devices, release metadata, ESRT entries, and configured remotes.",
        "sources": ["fwupd", "Linux UEFI ESRT sysfs"],
        "evidence_ids": [
            "fwupd_devices_json", "fwupd_updates_json", "fwupd_remotes_json",
            "fwupd_topology_json", "artifact:esrt_entries",
        ],
        "limitation": "The scan does not install a deliberately invalid capsule to prove rejection.",
    },
    {
        "id": "rollback-protection",
        "title": "Firmware rollback protection",
        "dasharo_feature": "Firmware downgrade restrictions",
        "purpose": "Preserve fwupd HSI, device flags, lowest-version metadata, and firmware-exposed BIOS settings.",
        "sources": ["fwupd HSI", "fwupd device metadata", "fwupd BIOS settings"],
        "evidence_ids": ["fwupd_security_json", "fwupd_devices_json", "fwupd_bios_settings_json"],
        "limitation": "No downgrade is attempted; absence of metadata is not proof that downgrade protection is absent.",
    },
    {
        "id": "controlled-boot-policy",
        "title": "Controlled boot policy",
        "dasharo_feature": "Controlled boot menu, USB boot, and network boot",
        "purpose": "Collect boot order, boot entries, and firmware settings exposed through fwupd or Linux sysfs.",
        "sources": ["efibootmgr", "fwupd BIOS settings", "Linux firmware-attributes sysfs"],
        "evidence_ids": ["efibootmgr", "fwupd_bios_settings_json", "artifact:firmware_attributes"],
        "limitation": "Vendors expose different settings; a missing setting is recorded as unavailable rather than disabled.",
    },
    {
        "id": "firmware-recovery",
        "title": "Firmware recovery capability",
        "dasharo_feature": "Signed recovery image or dual-bank recovery",
        "purpose": "Collect recovery-related device flags, ESRT metadata, and firmware settings.",
        "sources": ["fwupd device metadata", "Linux UEFI ESRT sysfs", "fwupd BIOS settings"],
        "evidence_ids": [
            "fwupd_devices_json", "fwupd_bios_settings_json", "artifact:esrt_entries",
        ],
        "limitation": "A normal running-OS scan cannot prove that recovery survives corruption or power loss.",
    },
    {
        "id": "release-metadata-provenance",
        "title": "Release metadata and provenance",
        "dasharo_feature": "Transparent releases, hashes, and provenance",
        "purpose": "Record fwupd versions, configured metadata remotes, hardware IDs, and cached releases.",
        "sources": ["fwupd JSON interfaces"],
        "evidence_ids": [
            "fwupd_version", "fwupd_remotes_json", "fwupd_hwids_json", "fwupd_updates_json",
        ],
        "limitation": "No metadata refresh is performed, so cached release information may be stale.",
    },
    {
        "id": "tpm-presence-and-state",
        "title": "TPM presence and state",
        "dasharo_feature": "TPM ownership and presence",
        "purpose": "Collect TPM device nodes, fixed properties, algorithms, and PCR availability.",
        "sources": ["Linux TPM devices", "tpm2-tools", "fwupd"],
        "evidence_ids": [
            "artifact:tpm_devices", "tpm_properties", "tpm_algorithms", "tpm_pcrs", "fwupd_devices_json",
        ],
        "limitation": "The collector does not clear, provision, or take ownership of the TPM.",
    },
    {
        "id": "peripheral-firmware",
        "title": "Peripheral firmware coverage",
        "dasharo_feature": "Firmware security beyond the main BIOS",
        "purpose": "Inventory firmware-visible devices and correlate them with PCI and USB topology.",
        "sources": ["fwupd device topology", "PCI sysfs/tools", "USB sysfs/tools"],
        "evidence_ids": [
            "fwupd_devices_json", "fwupd_topology_json", "lspci", "lspci_verbose", "lsusb", "lsusb_tree",
        ],
        "limitation": "Devices absent from fwupd may still contain firmware; absence from the list is not proof of absence.",
    },
]


def _evidence_state(report: dict[str, Any], evidence_id: str) -> str:
    if evidence_id.startswith("artifact:"):
        name = evidence_id.split(":", 1)[1]
        artifacts = report.get("artifacts", {}) or {}
        if name not in artifacts:
            return "not_collected"
        value = artifacts.get(name)
        if value in (None, [], {}):
            return "collected_empty"
        return "collected"
    command = (report.get("commands", {}) or {}).get(evidence_id)
    if not isinstance(command, dict):
        return "not_collected"
    return str(command.get("status") or "unknown")


def build_conventional_uefi_collection(report: dict[str, Any]) -> dict[str, Any]:
    """Build a collection manifest without evaluating the security result."""
    profile = (report.get("artifacts", {}) or {}).get("platform_profile", {}) or {}
    kind = str(profile.get("kind") if isinstance(profile, dict) else profile or "unknown")
    if isinstance(profile, dict) and profile.get("runtime_interface"):
        applicable = (
            profile.get("runtime_interface") == "uefi"
            and profile.get("boot_trust_model") != "heads"
            and kind != "virtual-machine"
        )
    else:
        applicable = kind == "uefi"
    checks: list[dict[str, Any]] = []
    for definition in CONVENTIONAL_UEFI_CHECKS:
        states = {evidence_id: _evidence_state(report, evidence_id) for evidence_id in definition["evidence_ids"]}
        successful = sum(1 for state in states.values() if state in {"collected", "collected_empty"})
        if not applicable:
            collection_state = "not_applicable"
        elif successful == len(states):
            collection_state = "collected"
        elif successful:
            collection_state = "partial"
        else:
            collection_state = "unavailable"
        checks.append({**definition, "collection_state": collection_state, "evidence_states": states})
    os_release = str((((report.get("commands", {}) or {}).get("os_release") or {}).get("stdout") or "")).strip()
    pretty_name = ""
    for line in os_release.splitlines():
        if line.startswith("PRETTY_NAME="):
            pretty_name = line.split("=", 1)[1].strip().strip('"')
            break
    return {
        "profile_id": CONVENTIONAL_UEFI_PROFILE_ID,
        "mode": "collection-only",
        "target_environment": pretty_name or "unknown",
        "network_access_performed": False,
        "platform_profile": kind,
        "applicable": applicable,
        "interpretation": (
            "Evidence was collected for later interpretation. No check is marked pass or fail by this profile."
            if applicable
            else "This profile is intended for conventional UEFI systems and is not applicable to the detected platform."
        ),
        "checks": checks,
    }
