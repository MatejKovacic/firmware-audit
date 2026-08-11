"""Shared information architecture for Firmware Audit reports."""

from __future__ import annotations

from typing import Any


SECTION_ORDER = [
    "identity",
    "firmware-baseline",
    "firmware-protection",
    "platform-security-processor",
    "out-of-band-management",
    "secure-boot",
    "tpm-measured-boot",
    "kernel-runtime",
    "host-integrity",
    "memory-protection",
    "storage-memory",
    "device-firmware",
    "updates",
]


SECTIONS: dict[str, dict[str, Any]] = {
    "identity": {
        "title": "Machine and firmware identity",
        "short_title": "Identity",
        "question": "What machine is this, and what firmware does it report?",
        "simple": "Identifies the computer, its BIOS/UEFI version, processor, TPM, and attached hardware.",
        "detailed": (
            "This inventory establishes the platform being examined and records the versions and identifiers "
            "reported by firmware and the running system. It can expose inconsistencies and unexpected hardware, but it does "
            "not independently prove that the reported firmware is genuine."
        ),
        "technical": (
            "Sources include SMBIOS/DMI, sysfs, fwupd device GUIDs, PCI and USB identifiers, ESRT-visible "
            "devices, and operating-system identity. DMI strings originate below the OS trust boundary and are "
            "therefore evidence to preserve, not an independent root of trust."
        ),
        "commands": [
            "locale_effective", "locale_host_config", "os_release", "uname", "hostnamectl",
            "systemd_detect_virt", "dmidecode_full", "dmidecode_bios", "dmidecode_system",
            "dmidecode_baseboard", "lspci", "lspci_verbose", "lsusb", "lsusb_tree",
        ],
        "artifacts": ["firmware_runtime_hashes", "platform_profile"],
        "optional_commands": ["lscpu_json", "fwupd_hwids_json"],
        "optional_artifacts": ["platform_boot_markers", "virtualization_kind"],
    },
    "firmware-baseline": {
        "title": "Current firmware and boot evidence",
        "short_title": "Firmware evidence",
        "question": "What firmware-adjacent evidence is visible now?",
        "simple": "Records current boot files, EFI variables, TPM event-log data, and OS-visible firmware tables.",
        "detailed": (
            "This section preserves a current snapshot of important firmware-adjacent evidence. It does not compare "
            "the data with an earlier report and does not claim that the snapshot is a full SPI-flash image."
        ),
        "technical": (
            "Whole SPI images contain machine-specific and mutable regions. The collected DMI and ACPI hashes only "
            "fingerprint OS-visible runtime tables, while boot-file and EFI-variable hashes describe the current state."
        ),
        "commands": ["dmidecode_bios", "mok_pk", "mok_kek", "mok_db", "mok_dbx", "mok_enrolled"],
        "artifacts": ["boot_file_hashes", "efi_variables", "tpm_eventlog", "firmware_runtime_hashes"],
    },
    "firmware-protection": {
        "title": "Firmware modification protections",
        "short_title": "Write protections",
        "question": "How difficult is it to rewrite the firmware?",
        "simple": "Checks protections intended to stop privileged software from modifying or downgrading firmware.",
        "detailed": (
            "Failures here are protection weaknesses, not proof that firmware has already been modified. The "
            "section covers SPI flash protection, rollback controls, platform debug locks, signed capsule updates, "
            "and other hardware-specific safeguards reported by fwupd."
        ),
        "technical": (
            "fwupd HSI attributes are interpreted individually. Where available, results should be corroborated "
            "with vendor documentation or a platform-specific tool such as CHIPSEC. Unsupported attributes are "
            "kept distinct from explicit failures."
        ),
        "commands": ["fwupd_version", "fwupd_security_json", "fwupd_security_text", "kernel_journal"],
        "artifacts": [],
        "optional_commands": ["fwupd_bios_settings_json"],
        "optional_artifacts": ["firmware_attributes", "conventional_uefi_collection"],
    },
    "platform-security-processor": {
        "title": "Platform security processor",
        "short_title": "Security processor",
        "question": "What privileged platform security processor is present, and is its observable security state healthy?",
        "simple": "Detects platform security processors such as Intel ME/CSME/SPS and AMD Secure Processor, plus locally exposed trusted-execution, GPU-security, embedded-controller, and equivalent technologies.",
        "detailed": (
            "Presence of a platform security processor is inventory, not a security warning. The assessment records locally observable firmware state and only elevates explicit insecure states such as manufacturing mode, unlocked debugging, or disabled rollback protection."
        ),
        "technical": (
            "Evidence is derived from kernel-exposed MEI/PCI interfaces, coreboot intelmetool when available on Intel systems, PSP/TEE and GPU-security messages, embedded-controller interfaces, locally cached fwupd data, and PCI inventory. Missing or failed host interfaces are not interpreted as proof that a coprocessor is absent; explicit disabled state is reported only when a supported source states it. If intelmetool is blocked from direct hardware I/O, the scanner records the collection restriction and relevant lockdown/capability context instead of interpreting the failure as an ME state."
        ),
        "commands": ["fwupd_security_json", "fwupd_devices_json", "lspci", "lspci_verbose", "kernel_journal"],
        "artifacts": ["platform_security_processors"],
        "optional_commands": ["intelmetool", "proc_self_status", "kernel_lockdown", "lscpu_json", "systemd_detect_virt"],
        "optional_artifacts": [],
    },
    "out-of-band-management": {
        "title": "Out-of-band management",
        "short_title": "OOB management",
        "question": "Does the machine expose an independent management subsystem?",
        "simple": "Detects BMC/IPMI, Intel AMT, NIC-integrated management functions, DMTF DASH, and firmware endpoint-persistence controls without probing networks.",
        "detailed": (
            "Independent management controllers can operate outside the main operating system and may have their own network or console capabilities. Their presence is informational; unexpected provisioning or insecure state can require review."
        ),
        "technical": (
            "Sources include SMBIOS management-controller records, local IPMI interfaces, PCI multifunction topology, kernel management-driver state, firmware attributes, local ipmitool output, MCHI evidence, and fwupd inventory. The collector performs no network discovery."
        ),
        "commands": ["dmidecode_ipmi", "dmidecode_mchi", "lspci", "kernel_journal"],
        "artifacts": ["out_of_band_management"],
        "optional_commands": ["ipmitool_mc_info"],
        "optional_artifacts": ["firmware_attributes"],
    },
    "secure-boot": {
        "title": "Secure Boot and boot-chain trust",
        "short_title": "Secure Boot",
        "question": "Are startup components authorized by the configured trust chain?",
        "simple": "Checks Secure Boot, trusted and revoked certificates, MOK keys, boot entries, and kernel lockdown.",
        "detailed": (
            "The section distinguishes normal OEM, Microsoft, distribution, and locally enrolled keys from "
            "unexpected changes. An unfamiliar certificate is not automatically malicious, and an expired "
            "certificate may remain present during a planned transition."
        ),
        "technical": (
            "Evidence includes UEFI PK, KEK, db and dbx, MOK lists, SBAT-related fwupd data, EFI boot entries, "
            "bootloader status, signature failures in the kernel journal, and kernel lockdown state."
        ),
        "commands": [
            "secure_boot_state", "mok_pk", "mok_kek", "mok_db", "mok_dbx", "mok_enrolled",
            "efibootmgr", "bootctl", "kernel_lockdown", "kernel_journal",
        ],
        "artifacts": ["efi_variables", "boot_file_hashes", "platform_profile"],
        "optional_commands": ["efi_platform_size"],
        "optional_artifacts": ["esrt_entries"],
    },
    "tpm-measured-boot": {
        "title": "TPM and measured boot",
        "short_title": "TPM / measured boot",
        "question": "What did the platform measure during startup?",
        "simple": "Records TPM capabilities, PCR values, and the measured-boot event log when available.",
        "detailed": (
            "PCR values are not malware-scan results. They become useful when reconstructed from the event log, "
            "replayed against the event log or evaluated by an attestation service."
        ),
        "technical": (
            "The collector preserves PCR banks, TPM fixed properties, supported algorithms, the parsed event log, "
            "and the original binary event log when size limits allow. fwupd PCR0 reconstruction is recorded as "
            "a separate platform capability."
        ),
        "commands": ["tpm_properties", "tpm_algorithms", "tpm_pcrs", "tpm_eventlog", "fwupd_security_text"],
        "artifacts": ["tpm_devices", "tpm_eventlog"],
        "optional_artifacts": ["tpm_eventlog_replay"],
    },
    "kernel-runtime": {
        "title": "Kernel and runtime integrity",
        "short_title": "Kernel runtime",
        "question": "Did the running system load unusual code or enter an abnormal state?",
        "simple": "Decodes kernel taint, module signatures, security modes, and important kernel warnings.",
        "detailed": (
            "Kernel taint is decoded bit by bit. Loaded modules are classified from their path, package ownership, "
            "signature metadata, license metadata, and kernel-defined taint semantics. The rules do not depend on "
            "a list of known applications or driver vendors."
        ),
        "technical": (
            "Sources include /proc/sys/kernel/tainted, loaded module metadata and signers, the active kernel command line, "
            "kernel CPU-vulnerability status, active LSMs, module/kexec enforcement state, local IMA/IPE state, "
            "and the complete current-boot journal and warning-level logs."
        ),
        "commands": [
            "proc_cmdline", "kernel_lockdown", "kernel_taint", "lsmod", "kernel_journal",
            "warning_journal", "apparmor", "selinux",
        ],
        "artifacts": ["kernel_taint", "loaded_module_metadata", "cpu_vulnerabilities"],
        "optional_commands": ["security_lsm", "modules_disabled", "kexec_load_disabled", "module_sig_enforce"],
        "optional_artifacts": ["integrity_frameworks", "kernel_enforcement_state"],
    },
    "host-integrity": {
        "title": "Installed files and persistence",
        "short_title": "Installed files",
        "question": "Are installed files or persistence mechanisms suspicious?",
        "simple": "Checks installed package files, startup mechanisms, privileged files, initramfs images, and service configuration.",
        "detailed": (
            "These checks examine the current host state for package-file modifications and powerful persistence "
            "mechanisms. Intentional administration can produce the same observations, so raw evidence remains visible."
        ),
        "technical": (
            "Sources include dpkg --verify, the installed package inventory, systemd unit and timer inventories, "
            "setuid/setgid executables, hashes of persistence-related files, executables in non-package and temporary "
            "paths, initramfs hashes, loaded module metadata, and optional AIDE output."
        ),
        "commands": [
            "dpkg_verify", "dpkg_package_inventory", "dpkg_diversions", "dpkg_statoverrides", "systemd_service_files", "systemd_timer_files",
            "systemd_running_services", "systemd_timers", "suid_sgid_files",
        ],
        "artifacts": [
            "host_persistence_files", "host_executable_inventory", "initramfs_hashes", "package_verify_analysis",
        ],
        "optional_commands": ["aide_check"],
        "optional_artifacts": [],
    },
    "memory-protection": {
        "title": "Hardware memory protection",
        "short_title": "Memory protection",
        "question": "What hardware memory-encryption or confidential-memory protections are supported and active?",
        "simple": "Distinguishes whole-system memory encryption from confidential-VM technologies and records locally observable activation state.",
        "detailed": (
            "System-memory encryption such as AMD SME or Intel TME protects a different threat surface from VM-focused technologies such as AMD SEV or Intel TDX. Support alone is not treated as equivalent to active protection."
        ),
        "technical": (
            "Evidence comes from CPU feature flags, architecture-defined memory-encryption capability leaves, optional read-only local MSR state, kernel-exported transparent-memory-encryption state, firmware attributes, local KVM/SEV interfaces, and fwupd HSI when available. No vendor or vulnerability service is queried."
        ),
        "commands": ["fwupd_security_json", "kernel_journal", "proc_cmdline"],
        "artifacts": ["memory_protection"],
        "optional_commands": ["lscpu_json", "cpuid_amd_memory_encryption", "msr_amd_syscfg", "msr_amd_sev_status"],
        "optional_artifacts": [],
    },
    "storage-memory": {
        "title": "Disk, memory, and physical-access protection",
        "short_title": "Data exposure",
        "question": "Can secrets be exposed through storage, swap, sleep, or DMA?",
        "simple": "Checks encryption topology, active swap, sleep-state exposure, IOMMU, and pre-boot DMA protection.",
        "detailed": (
            "The complete block-device dependency tree is evaluated so swap inside encrypted storage is not mislabeled as "
            "unencrypted. Findings in this section concern data exposure and physical attacks, not direct evidence "
            "of BIOS compromise."
        ),
        "technical": (
            "Evidence includes the active swap inventory, block-device and mounted-filesystem topology, encrypted mappings, "
            "sleep and DMA attributes, and IOMMU state. Swap encryption is determined independently of fwupd."
        ),
        "commands": ["lsblk_json", "swapon_text", "proc_swaps", "dmsetup_tree", "mounts", "power_mem_sleep", "power_state", "fwupd_security_json", "fwupd_security_text"],
        "artifacts": ["swap_topology"],
        "optional_commands": ["iommu_kernel_log"],
        "optional_artifacts": ["iommu_groups", "thunderbolt_security"],
    },
    "device-firmware": {
        "title": "Device firmware and peripheral security",
        "short_title": "Device firmware",
        "question": "What firmware exists outside the motherboard BIOS?",
        "simple": "Inventories firmware in SSDs, TPMs, modems, cameras, fingerprint readers, GPUs, docks, and other devices.",
        "detailed": (
            "Persistence and vulnerabilities are not limited to system firmware. This section records update "
            "support, payload signing, current versions, minimum versions, and device changes."
        ),
        "technical": (
            "fwupd device JSON is correlated with PCI and USB identities. An unsigned update payload describes the "
            "vendor update mechanism and is not automatically evidence that the installed firmware is malicious."
        ),
        "commands": ["fwupd_devices_json", "lspci", "lspci_verbose", "lsusb", "lsusb_tree"],
        "artifacts": [],
        "optional_commands": ["fwupd_topology_json"],
    },
    "updates": {
        "title": "Updates and known maintenance status",
        "short_title": "Updates",
        "question": "Are official firmware updates available or failing?",
        "simple": "Checks locally available update metadata and currently applicable firmware releases.",
        "detailed": (
            "Local observations are kept separate from external vendor verification. Offline scans cannot prove "
            "that an installed version is the newest available version."
        ),
        "technical": (
            "Sources include fwupd releases, device minimum versions, current device state, dbx/SBAT data, and "
            "the fwupd daemon and plugin versions. External CVE or vendor checks are intentionally not inferred "
            "without a configured online data source."
        ),
        "commands": ["fwupd_version", "fwupd_updates_json", "fwupd_devices_json"],
        "artifacts": [],
        "optional_commands": ["fwupd_remotes_json"],
        "optional_artifacts": ["esrt_entries"],
    },

}


CATEGORY_TO_SECTION = {
    "scope": "identity",
    "visibility": "firmware-baseline",
    "evidence-integrity": "firmware-baseline",
    "firmware-protection": "firmware-protection",
    "host-security": "firmware-protection",
    "boot-protection": "secure-boot",
    "trust-store": "secure-boot",
    "integrity-signal": "secure-boot",
    "measured-boot": "tpm-measured-boot",
    "platform-security-processor": "platform-security-processor",
    "out-of-band-management": "out-of-band-management",
    "memory-protection": "memory-protection",
    "operating-system": "kernel-runtime",
    "compatibility": "kernel-runtime",
    "reliability": "kernel-runtime",
    "host-integrity": "host-integrity",
    "data-protection": "storage-memory",
    "physical-security": "storage-memory",
    "device-firmware": "device-firmware",
    "maintenance": "updates",
}


COMMAND_SECTION_MAP = {
    command: slug
    for slug, definition in SECTIONS.items()
    for command in [*definition.get("commands", []), *definition.get("optional_commands", [])]
}


def section_for_command(name: str) -> str:
    if name.startswith("cryptsetup_status_"):
        return "storage-memory"
    return COMMAND_SECTION_MAP.get(name, "identity")
