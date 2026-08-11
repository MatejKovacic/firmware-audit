import json
import unittest

from assessment import assess, decode_taint, detect_platform_profile


def command(stdout="", status="collected", stderr=""):
    return {"stdout": stdout, "stderr": stderr, "status": status}


class AssessmentTests(unittest.TestCase):
    def base_report(self):
        return {
            "schema_version": 10,
            "report_id": "test-report",
            "system": {
                "kernel": {
                    "running_release": "6.12.0-amd64",
                    "installed_releases": ["6.12.0-amd64"],
                }
            },
            "commands": {
                "os_release": command('PRETTY_NAME="Debian GNU/Linux 13 (trixie)"'),
                "uname": command("Linux test 6.12.0-amd64"),
                "dmidecode_bios": command("Vendor: Example\nVersion: 1.2.3"),
                "fwupd_security_text": command("Host Security ID: HSI:1\n"),
                "fwupd_security_json": command("", status="failed"),
                "secure_boot_state": command("SecureBoot enabled"),
                "kernel_taint": command("0"),
                "kernel_journal": command("secureboot: Secure boot enabled"),
                "lsblk_json": command('{"blockdevices": []}'),
                "lspci": command("00:00.0 Host bridge"),
                "systemd_detect_virt": command("none"),
                "fwupd_updates_json": command('{"Devices": []}'),
                "tpm_properties": command("TPM2_PT_MANUFACTURER"),
                "dpkg_verify": command("", status="collected_empty"),
                "dpkg_package_inventory": command("base-files\t13.0\tii "),
                "dpkg_diversions": command("", status="collected_empty"),
                "dpkg_statoverrides": command("", status="collected_empty"),
                "systemd_service_files": command("ssh.service enabled"),
                "systemd_timer_files": command("apt-daily.timer enabled"),
                "systemd_running_services": command("ssh.service loaded active running"),
                "systemd_timers": command("apt-daily.timer"),
                "suid_sgid_files": command("4755\troot\troot\t/usr/bin/sudo"),
            },
            "artifacts": {
                "uefi_mode": True,
                "tpm_devices": ["/dev/tpmrm0"],
                "host_persistence_files": [],
                "host_executable_inventory": [],
                "initramfs_hashes": [],
                "package_verify_analysis": {
                    "backend": "dpkg", "available": True,
                    "counts": {"configuration": 0, "ignored": 0, "security_relevant": 0, "other_drift": 0, "unparsed": 0},
                    "records": [],
                },
            },
        }

    def set_fwupd_attributes(self, report, attributes, events=None):
        report["commands"]["fwupd_security_json"] = command(json.dumps({
            "SecurityAttributes": attributes,
            "SecurityEvents": events or [],
        }))

    def test_taint_4096_is_out_of_tree(self):
        decoded = decode_taint(4096)
        self.assertEqual([item["code"] for item in decoded], ["out-of-tree"])

    def test_spi_is_protection_gap_not_compromise(self):
        report = self.base_report()
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.Amd.SpiWriteProtection",
            "Name": "Translated name",
            "HsiResult": "not-enabled",
            "HsiResultSuccess": "enabled",
            "Flags": ["action-contact-oem"],
        }])
        report["commands"]["kernel_taint"] = command("4096")
        result = assess(report)
        ids = {item["finding_id"] for item in result["findings"]}
        self.assertIn("spi-write-protection", ids)
        self.assertIn("kernel-external-module-state", ids)
        self.assertEqual(result["status"], "attention")
        self.assertFalse(any(item["compromise_indicator"] for item in result["findings"]))

    def test_luks_topology_overrides_fwupd_swap_warning(self):
        report = self.base_report()
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.Kernel.Swap",
            "Name": "Swap",
            "HsiResult": "not-encrypted",
            "HsiResultSuccess": "encrypted",
            "Flags": ["runtime-issue"],
        }])
        report["commands"]["lsblk_json"] = command(json.dumps({
            "blockdevices": [{
                "name": "disk",
                "children": [{
                    "name": "cryptroot",
                    "type": "crypt",
                    "fstype": "LVM2_member",
                    "children": [{
                        "name": "vg-swap",
                        "type": "lvm",
                        "fstype": "swap",
                        "mountpoint": "[SWAP]",
                    }],
                }],
            }],
        }))
        result = assess(report)
        ids = {item["finding_id"] for item in result["findings"]}
        self.assertNotIn("swap-encrypted", ids)
        self.assertNotIn("swap-unencrypted", ids)
        storage = next(item for item in result["sections"] if item["slug"] == "storage-memory")
        self.assertEqual(storage["status"], "good")
        self.assertIn("swap storage is encrypted", storage["simple_result"].lower())


    def test_heads_pcr0_reconstruction_is_not_end_user_finding(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["dmidecode_bios"] = command("Vendor: Dasharo\nVersion: Dasharo (coreboot+heads) v0.9.0")
        report["commands"]["tpm_eventlog"] = command("CBFS: bootblock\nFMAP: FMAP")
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.Tpm.ReconstructionPcr0",
            "HsiResult": "not-valid",
            "HsiResultSuccess": "valid",
            "Flags": ["runtime-issue"],
        }])
        ids = {item["finding_id"] for item in assess(report)["findings"]}
        self.assertNotIn("heads-pcr0-fwupd-incompatible", ids)
        self.assertNotIn("tpm-pcr0-reconstruction-failed", ids)

    def test_amd_ccp_warning_is_preserved_when_psp_and_tee_initialize(self):
        report = self.base_report()
        report["schema_version"] = 16
        report["commands"]["kernel_journal"] = command(
            "ccp: unable to access the device: you might be running a broken BIOS.\n"
            "ccp: tee enabled\nccp: psp enabled"
        )
        result = assess(report)
        ids = {item["finding_id"] for item in result["findings"]}
        self.assertNotIn("amd-secure-processor-incomplete", ids)
        self.assertIn("amd-ccp-interface-warning", ids)
        finding = next(item for item in result["findings"] if item["finding_id"] == "amd-ccp-interface-warning")
        self.assertEqual(finding["finding_type"], "compatibility-issue")
        self.assertEqual(finding["severity"], "info")

    def test_invalid_uefi_db_is_integrity_indicator(self):
        report = self.base_report()
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.Uefi.Db",
            "Name": "Db UEFI",
            "HsiResult": "not-valid",
            "HsiResultSuccess": "valid",
            "Flags": ["runtime-issue"],
        }])
        result = assess(report)
        self.assertEqual(result["status"], "investigate")
        self.assertTrue(any(item["compromise_indicator"] for item in result["findings"]))

    def test_historical_fwupd_failure_is_not_current_finding(self):
        report = self.base_report()
        self.set_fwupd_attributes(
            report,
            [{
                "AppstreamId": "org.fwupd.hsi.Uefi.Db",
                "Name": "Db UEFI",
                "HsiResult": "valid",
                "HsiResultSuccess": "valid",
                "Flags": ["success"],
            }],
            events=[{
                "AppstreamId": "org.fwupd.hsi.Uefi.Db",
                "Name": "Db UEFI",
                "HsiResult": "not-valid",
                "Flags": ["runtime-issue"],
            }],
        )
        ids = {item["finding_id"] for item in assess(report)["findings"]}
        self.assertNotIn("uefi-db-invalid", ids)

    def test_not_tainted_fwupd_plugin_result_is_success(self):
        report = self.base_report()
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.Fwupd.Plugins",
            "Name": "Vstavki fwupd",
            "HsiResult": "not-tainted",
            "HsiResultSuccess": "not-tainted",
            "Flags": ["success", "runtime-issue"],
        }])
        ids = {item["finding_id"] for item in assess(report)["findings"]}
        self.assertNotIn("fwupd-plugins-tainted", ids)

    def test_heads_profile_suppresses_uefi_failures(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["dmidecode_bios"] = command("Vendor: Dasharo\nVersion: Dasharo (coreboot+heads) v0.9.0")
        report["commands"]["secure_boot_state"] = command("", status="not_applicable", stderr="EFI variables are not supported")
        report["commands"]["tpm_eventlog"] = command("PCRIndex: 2\nEvent: 464d41503a20464d4150\nEvent: 434246533a20626f6f74626c6f636b")
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.Uefi.SecureBoot",
            "Name": "UEFI secure boot",
            "HsiResult": "not-enabled",
            "HsiResultSuccess": "enabled",
            "Flags": ["missing-data"],
        }])
        result = assess(report)
        ids = {item["finding_id"] for item in result["findings"]}
        self.assertEqual(result["platform_profile"]["kind"], "coreboot-heads")
        self.assertIn("heads-boot-model", ids)
        self.assertNotIn("secure-boot-fwupd", ids)
        self.assertNotIn("legacy-boot", ids)
        secure_section = next(item for item in result["sections"] if item["slug"] == "secure-boot")
        self.assertEqual(secure_section["title"], "Heads boot-chain trust")

    def test_dasharo_heads_is_detected_from_independent_signals_without_product_allowlist(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["systemd_detect_virt"] = command("none")
        report["commands"]["dmidecode_bios"] = command("Vendor: 3mdeb\nVersion: Dasharo release")
        report["commands"]["tpm_eventlog"] = command(
            'Event: "464d41503a20464d4150"\nEvent: "434246533a20626f6f74626c6f636b"'
        )
        report["artifacts"]["boot_file_hashes"] = [
            {"path": "/boot/kexec_hashes.txt"},
            {"path": "/boot/kexec.sig"},
            {"path": "/boot/kexec_hotp_counter"},
            {"path": "/boot/kexec_rollback.txt"},
            {"path": "/boot/grub/i386-pc/linux.mod"},
        ]
        profile = detect_platform_profile(report)
        self.assertEqual(profile["kind"], "coreboot-heads")
        self.assertEqual(profile["firmware_family"], "coreboot")
        self.assertEqual(profile["boot_trust_model"], "heads")
        self.assertIn("tpm-cbfs-fmap", {item["id"] for item in profile["signals"]})
        result = assess(report)
        ids = {item["finding_id"] for item in result["findings"]}
        self.assertNotIn("legacy-boot", ids)

    def test_partial_scan_can_detect_heads_from_system_context_and_cheap_markers(self):
        report = self.base_report()
        report["system"]["hardware"] = {
            "bios_vendor": "3mdeb",
            "bios_version": "Dasharo release",
            "product_name": "generic-laptop",
        }
        report["artifacts"]["uefi_mode"] = False
        report["artifacts"]["virtualization_kind"] = "none"
        report["artifacts"]["platform_boot_markers"] = {
            "existing_paths": [
                "/boot/kexec_hashes.txt",
                "/boot/kexec.sig",
                "/boot/kexec_hotp_counter",
                "/boot/kexec_rollback.txt",
            ]
        }
        report["artifacts"].pop("boot_file_hashes", None)
        report["commands"].pop("tpm_eventlog", None)
        report["commands"].pop("systemd_detect_virt", None)
        profile = detect_platform_profile(report)
        self.assertEqual(profile["kind"], "coreboot-heads")
        self.assertEqual(profile["boot_trust_model"], "heads")
        self.assertIn("heads-kexec-signature", {item["id"] for item in profile["signals"]})

    def test_non_uefi_without_positive_legacy_evidence_remains_unclassified(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["systemd_detect_virt"] = command("none")
        report["commands"]["dmidecode_bios"] = command("Vendor: Example\nVersion: custom")
        report["artifacts"]["boot_file_hashes"] = []
        profile = detect_platform_profile(report)
        self.assertEqual(profile["kind"], "non-uefi-unknown")
        result = assess(report)
        ids = {item["finding_id"] for item in result["findings"]}
        self.assertIn("boot-model-unclassified", ids)
        self.assertNotIn("legacy-boot", ids)
        secure = next(item for item in result["sections"] if item["slug"] == "secure-boot")
        self.assertEqual(secure["status"], "unknown")

    def test_positive_grub_pc_evidence_can_classify_physical_legacy_boot(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["systemd_detect_virt"] = command("none")
        report["artifacts"]["boot_file_hashes"] = [{"path": "/boot/grub/i386-pc/linux.mod"}]
        profile = detect_platform_profile(report)
        self.assertEqual(profile["kind"], "legacy-bios")
        ids = {item["finding_id"] for item in assess(report)["findings"]}
        self.assertIn("legacy-boot", ids)

    def test_virtualization_remains_top_level_boundary_even_with_heads_guest_signals(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["systemd_detect_virt"] = command("kvm")
        report["commands"]["dmidecode_bios"] = command("Version: coreboot Heads")
        report["commands"]["tpm_eventlog"] = command('Event: "464d4150"\nEvent: "43424653"')
        profile = detect_platform_profile(report)
        self.assertEqual(profile["kind"], "virtual-machine")
        self.assertEqual(profile["boot_trust_model"], "heads")
        result = assess(report)
        firmware = next(item for item in result["sections"] if item["slug"] == "firmware-protection")
        self.assertEqual(firmware["status"], "not_applicable")
        secure = next(item for item in result["sections"] if item["slug"] == "secure-boot")
        self.assertEqual(secure["title"], "Heads boot-chain trust")

    def test_uefi_vm_secure_boot_state_is_actually_assessed(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = True
        report["commands"]["systemd_detect_virt"] = command("kvm")
        report["commands"]["secure_boot_state"] = command("SecureBoot disabled")
        result = assess(report)
        ids = {item["finding_id"] for item in result["findings"]}
        self.assertIn("secure-boot-disabled", ids)
        secure = next(item for item in result["sections"] if item["slug"] == "secure-boot")
        self.assertEqual(secure["status"], "attention")

    def test_vm_missing_tpm_recommends_vtpm_not_package_install(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["artifacts"]["tpm_devices"] = []
        report["commands"]["systemd_detect_virt"] = command("kvm")
        report["commands"]["tpm_properties"] = command("", status="not_applicable")
        finding = next(item for item in assess(report)["findings"] if item["finding_id"] == "tpm-not-observed")
        self.assertIn("vtpm", finding["recommendation"].lower())
        self.assertNotIn("install tpm2-tools", finding["recommendation"].lower())

    def test_unavailable_package_backend_makes_host_integrity_unknown(self):
        report = self.base_report()
        report["artifacts"]["package_verify_analysis"] = {"backend": "dpkg", "available": False, "records": []}
        result = assess(report)
        note_ids = {item["finding_id"] for item in result["security_notes"]}
        self.assertIn("package-verification-unavailable", note_ids)
        host = next(item for item in result["sections"] if item["slug"] == "host-integrity")
        self.assertEqual(host["status"], "unknown")

    def test_kernel_warning_is_generic_reliability_note(self):
        report = self.base_report()
        report["commands"]["kernel_taint"] = command("512")
        report["commands"]["kernel_journal"] = command("example_driver 0000:00:02.0: drm_WARN_ON(example_condition)")
        finding = next(item for item in assess(report)["findings"] if item["finding_id"] == "kernel-warning-state")
        self.assertEqual(finding["title"], "Kernel warning state was recorded")
        self.assertEqual(finding["finding_type"], "informational")
        self.assertEqual(finding["severity"], "info")
        self.assertFalse(finding["compromise_indicator"])
        self.assertIn("does not identify or whitelist a particular driver", finding["detailed"])

    def test_combined_taint_flags_produce_independent_observations(self):
        report = self.base_report()
        report["commands"]["kernel_taint"] = command(str(4096 + 512))
        report["commands"]["kernel_journal"] = command("example_driver: WARNING: example condition")
        report["artifacts"]["loaded_module_metadata"] = [{
            "name": "exampledrv",
            "filename": "/lib/modules/6.12.0/updates/dkms/exampledrv.ko",
            "origin": "external-dkms",
            "package_owner": "example-driver-dkms",
            "package_managed": True,
            "signer": "Local module signing key",
            "license": "GPL",
        }]
        ids = {item["finding_id"] for item in assess(report)["findings"]}
        self.assertIn("kernel-external-module-state", ids)
        self.assertIn("kernel-warning-state", ids)

    def test_out_of_tree_module_uses_product_neutral_explanation(self):
        report = self.base_report()
        report["commands"]["kernel_taint"] = command("4096")
        report["artifacts"]["loaded_module_metadata"] = [{
            "name": "exampledrv",
            "filename": "/lib/modules/6.12.0/updates/dkms/exampledrv.ko",
            "origin": "external-dkms",
            "package_owner": "example-driver-dkms",
            "package_managed": True,
            "signer": "Local module signing key",
            "license": "GPL",
        }]
        finding = next(item for item in assess(report)["findings"] if item["finding_id"] == "kernel-external-module-state")
        self.assertEqual(finding["title"], "Non-distribution kernel module state is present")
        self.assertEqual(finding["finding_type"], "compatibility-issue")
        self.assertIn("external-dkms", finding["simple"])
        self.assertIn("package=example-driver-dkms", " ".join(finding["evidence"]))
        self.assertNotIn("VirtualBox", finding["simple"] + finding["detailed"] + finding["technical"])


    def test_newer_installed_kernel_is_informational_note(self):
        report = self.base_report()
        baseline_status = assess(self.base_report())["status"]
        report["system"]["kernel"] = {
            "running_release": "6.8.0-136-generic",
            "installed_releases": ["6.8.0-136-generic", "6.8.0-137-generic"],
        }
        result = assess(report)
        note = next(item for item in result["security_notes"] if item["finding_id"] == "newer-installed-kernel")
        self.assertEqual(note["severity"], "info")
        self.assertEqual(note["finding_type"], "informational")
        self.assertNotIn("newer-installed-kernel", {item["finding_id"] for item in result["actionable_findings"]})
        self.assertEqual(result["status"], baseline_status)

    def test_running_newest_kernel_has_no_pending_reboot_note(self):
        report = self.base_report()
        report["system"]["kernel"] = {
            "running_release": "6.8.0-137-generic",
            "installed_releases": ["6.8.0-136-generic", "6.8.0-137-generic"],
        }
        ids = {item["finding_id"] for item in assess(report)["findings"]}
        self.assertNotIn("newer-installed-kernel", ids)

    def test_same_kernel_version_different_flavor_is_not_called_newer(self):
        report = self.base_report()
        report["system"]["kernel"] = {
            "running_release": "6.8.0-137-generic",
            "installed_releases": ["6.8.0-137-generic", "6.8.0-137-lowlatency"],
        }
        ids = {item["finding_id"] for item in assess(report)["findings"]}
        self.assertNotIn("newer-installed-kernel", ids)

    def test_iommu_and_preboot_dma_failures_are_consolidated(self):
        report = self.base_report()
        self.set_fwupd_attributes(report, [
            {
                "AppstreamId": "org.fwupd.hsi.Iommu",
                "HsiResult": "not-enabled",
                "HsiResultSuccess": "enabled",
                "Flags": ["action-config-fw"],
            },
            {
                "AppstreamId": "org.fwupd.hsi.PrebootDma",
                "HsiResult": "not-enabled",
                "HsiResultSuccess": "enabled",
                "Flags": ["action-config-fw"],
            },
        ])
        result = assess(report)
        dma = [item for item in result["findings"] if item["finding_id"] == "dma-isolation-protection"]
        self.assertEqual(len(dma), 1)
        self.assertEqual(len(dma[0]["evidence"]), 2)
        self.assertNotIn("dma-protection-org-fwupd-hsi-iommu", {item["finding_id"] for item in result["findings"]})

    def test_unsigned_module_wording_allows_signed_but_untrusted_module(self):
        report = self.base_report()
        report["commands"]["kernel_taint"] = command(str(1 << 13))
        report["artifacts"]["loaded_module_metadata"] = [{
            "name": "exampledrv",
            "filename": "/lib/modules/6.12.0/updates/dkms/exampledrv.ko",
            "origin": "external-dkms",
            "signer": "Local DKMS module signing key",
            "license": "GPL",
        }]
        finding = next(item for item in assess(report)["findings"] if item["finding_id"] == "kernel-unsigned-module")
        self.assertEqual(finding["title"], "Unsigned or kernel-untrusted module code is loaded")
        self.assertIn("not accepted as trusted", finding["simple"])

    def test_all_sections_have_four_layer_content(self):
        result = assess(self.base_report())
        self.assertEqual(len(result["sections"]), 13)
        slugs = {section["slug"] for section in result["sections"]}
        self.assertIn("firmware-protection", slugs)
        self.assertIn("host-integrity", slugs)
        for section in result["sections"]:
            self.assertTrue(section["simple_explanation"])
            self.assertTrue(section["detailed_explanation"])
            self.assertTrue(section["technical_explanation"])
            self.assertIn(section["status"], {"good", "attention", "investigate", "unknown", "informational", "not_applicable"})




    def test_intel_mei_failure_is_unknown_not_good(self):
        report = self.base_report()
        report["schema_version"] = 16
        report["commands"]["lscpu_json"] = command(json.dumps({"lscpu": [
            {"field": "Vendor ID:", "data": "GenuineIntel"}
        ]}))
        report["artifacts"]["platform_security_processors"] = {
            "intel_mei": {
                "observable": False,
                "hardware_present": True,
                "state": "host-interface-unavailable",
                "pci_evidence": [{"bdf": "00:16.0", "description": "Intel Corporation Meteor Lake-P CSME HECI #1"}],
                "journal": {
                    "initialization_failed": True,
                    "evidence": ["mei_me 0000:00:16.0: initialization failed."],
                },
                "intelmetool": {"state": "probe-failed", "available": True, "evidence": []},
            }
        }
        result = assess(report)
        ids = {item["finding_id"] for item in result["findings"]}
        self.assertIn("intel-me-state-unknown", ids)
        section = next(item for item in result["sections"] if item["slug"] == "platform-security-processor")
        self.assertEqual(section["status"], "unknown")
        self.assertIn("failed to initialize", section["simple_result"])

    def test_intelmetool_blocked_is_unknown_with_collection_restriction(self):
        report = self.base_report()
        report["schema_version"] = 16
        report["commands"]["lscpu_json"] = command(json.dumps({"lscpu": [
            {"field": "Vendor ID:", "data": "GenuineIntel"}
        ]}))
        report["artifacts"]["platform_security_processors"] = {
            "intel_mei": {
                "observable": False,
                "hardware_present": True,
                "state": "hardware-present-state-unknown",
                "pci_evidence": [{"bdf": "00:16.0", "description": "Intel Corporation CSME HECI #1"}],
                "intelmetool": {
                    "state": "blocked",
                    "reason": "iopl-permission-denied",
                    "available": True,
                    "usable": False,
                    "failure_evidence": ["iopl: Operation not permitted", "You need to be root."],
                    "privilege_context": {
                        "kernel_lockdown": {"active": "integrity", "enabled": True},
                        "capabilities": {"effective": True, "bounding": True},
                    },
                },
            }
        }
        result = assess(report)
        finding = next(item for item in result["findings"] if item["finding_id"] == "intel-me-state-unknown")
        self.assertIn("hardware access was blocked", finding["title"])
        self.assertIn("collection restriction", finding["simple"])
        self.assertIn("iopl: Operation not permitted", " ".join(finding["evidence"]))
        self.assertIn("Kernel lockdown mode: integrity", finding["evidence"])
        section = next(item for item in result["sections"] if item["slug"] == "platform-security-processor")
        self.assertEqual(section["status"], "unknown")
        self.assertIn("hardware I/O was denied", section["simple_result"])

    def test_intelmetool_inconclusive_is_unknown(self):
        report = self.base_report()
        report["schema_version"] = 16
        report["commands"]["lscpu_json"] = command(json.dumps({"lscpu": [
            {"field": "Vendor ID:", "data": "GenuineIntel"}
        ]}))
        report["artifacts"]["platform_security_processors"] = {
            "intel_mei": {
                "observable": False,
                "hardware_present": True,
                "state": "hardware-present-state-unknown",
                "intelmetool": {
                    "state": "inconclusive",
                    "reason": "me-pci-device-not-recognized",
                    "available": True,
                    "usable": False,
                    "failure_evidence": ["Can't find ME PCI device"],
                },
            }
        }
        result = assess(report)
        finding = next(item for item in result["findings"] if item["finding_id"] == "intel-me-state-unknown")
        self.assertIn("intelmetool was inconclusive", finding["title"])
        self.assertIn("Can't find ME PCI device", " ".join(finding["evidence"]))

    def test_intelmetool_inconclusive_without_heci_describes_absent_removed_or_hidden_possibilities(self):
        report = self.base_report()
        report["schema_version"] = 16
        report["commands"]["lscpu_json"] = command(json.dumps({"lscpu": [
            {"field": "Vendor ID:", "data": "GenuineIntel"}
        ]}))
        report["artifacts"]["platform_security_processors"] = {
            "intel_mei": {
                "observable": False,
                "hardware_present": False,
                "state": "unobserved",
                "intelmetool": {
                    "state": "inconclusive",
                    "reason": "me-pci-device-not-recognized",
                    "available": True,
                    "usable": False,
                    "failure_evidence": ["Can't find ME PCI device"],
                },
            }
        }
        finding = next(item for item in assess(report)["findings"] if item["finding_id"] == "intel-me-state-unknown")
        self.assertIn("no intel me/csme host interface", finding["title"].lower())
        self.assertIn("removed", finding["summary"].lower())
        self.assertIn("firmware-hidden", finding["summary"].lower())
        self.assertNotIn("disabled", finding["title"].lower())

    def test_intelmetool_disabled_state_is_informational(self):
        report = self.base_report()
        report["schema_version"] = 16
        report["commands"]["lscpu_json"] = command(json.dumps({"lscpu": [
            {"field": "Vendor ID:", "data": "GenuineIntel"}
        ]}))
        report["artifacts"]["platform_security_processors"] = {
            "intel_mei": {
                "observable": False,
                "hardware_present": True,
                "state": "disabled",
                "state_source": "intelmetool",
                "intelmetool": {
                    "state": "disabled",
                    "available": True,
                    "evidence": [
                        "ME: Current Working State : Disabled",
                        "ME: Current Operation Mode : Soft Temporary Disable",
                    ],
                },
            }
        }
        result = assess(report)
        ids = {item["finding_id"] for item in result["findings"]}
        self.assertIn("intel-me-disabled", ids)
        self.assertNotIn("intel-me-state-unknown", ids)
        section = next(item for item in result["sections"] if item["slug"] == "platform-security-processor")
        self.assertEqual(section["status"], "good")
        self.assertIn("reported disabled", section["simple_result"])

    def test_intel_me_manufacturing_mode_is_actionable_security_processor_finding(self):
        report = self.base_report()
        report["artifacts"]["platform_security_processors"] = {"intel_mei": {"observable": True, "devices": [{"name": "mei0"}]}}
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.Mei.ManufacturingMode",
            "HsiResult": "enabled",
            "HsiResultSuccess": "not-enabled",
            "Flags": ["action-contact-oem"],
        }])
        result = assess(report)
        finding = next(item for item in result["findings"] if item["finding_id"] == "intel-me-manufacturing-mode")
        self.assertEqual(finding["section"], "platform-security-processor")
        self.assertEqual(finding["finding_type"], "protection-weakness")
        self.assertEqual(result["status"], "attention")

    def test_amd_psp_direct_sysfs_failure_is_used_without_fwupd_hsi(self):
        report = self.base_report()
        report["artifacts"]["platform_security_processors"] = {
            "amd_psp": {
                "observable": True,
                "devices": [{"bdf": "0000:04:00.2", "attributes": {"anti_rollback_status": "0", "debug_lock_on": "1"}}],
            }
        }
        result = assess(report)
        finding = next(item for item in result["findings"] if item["finding_id"] == "amd-psp-security-controls")
        self.assertEqual(finding["section"], "platform-security-processor")
        self.assertIn("rollback protection", " ".join(finding["evidence"]))

    def test_provisioned_amt_is_informational_note(self):
        report = self.base_report()
        report["artifacts"]["out_of_band_management"] = {
            "intel_amt": {
                "detected": True,
                "records": [{"name": "AMT [provisioned]", "version": "16.1", "provisioning_state": "provisioned"}],
            },
            "bmc": {"detected": False, "interfaces": []},
        }
        result = assess(report)
        note = next(item for item in result["security_notes"] if item["finding_id"] == "oob-management-provisioned")
        self.assertEqual(note["section"], "out-of-band-management")
        self.assertEqual(note["finding_type"], "informational")
        self.assertNotIn(note, result["actionable_findings"])

    def test_intel_bootguard_policy_failures_are_attention(self):
        report = self.base_report()
        self.set_fwupd_attributes(report, [
            {
                "AppstreamId": "org.fwupd.hsi.IntelBootguard.Enabled",
                "Name": "Intel BootGuard",
                "HsiResult": "enabled",
                "HsiResultSuccess": "enabled",
                "Flags": ["success"],
            },
            {
                "AppstreamId": "org.fwupd.hsi.IntelBootguard.Acm",
                "Name": "Intel BootGuard ACM protected",
                "HsiResult": "not-valid",
                "HsiResultSuccess": "valid",
                "Flags": ["action-contact-oem"],
            },
            {
                "AppstreamId": "org.fwupd.hsi.IntelBootguard.Verified",
                "Name": "Intel BootGuard verified boot",
                "HsiResult": "not-valid",
                "HsiResultSuccess": "valid",
                "Flags": ["action-contact-oem"],
            },
            {
                "AppstreamId": "org.fwupd.hsi.IntelBootguard.Policy",
                "Name": "Intel BootGuard error policy",
                "HsiResult": "not-valid",
                "HsiResultSuccess": "valid",
                "Flags": ["action-contact-oem"],
            },
        ])
        result = assess(report)
        finding = next(item for item in result["actionable_findings"] if item["finding_id"] == "intel-bootguard-policy")
        self.assertEqual(finding["section"], "firmware-protection")
        self.assertEqual(finding["severity"], "medium")
        self.assertFalse(finding["compromise_indicator"])
        self.assertEqual(len(finding["evidence"]), 3)
        self.assertEqual(result["status"], "attention")

    def test_intel_bootguard_policy_is_not_actionable_for_heads(self):
        report = self.base_report()
        report["commands"]["dmidecode_bios"] = command("Vendor: coreboot\nVersion: Heads-test")
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.IntelBootguard.Verified",
            "Name": "Intel BootGuard verified boot",
            "HsiResult": "not-valid",
            "HsiResultSuccess": "valid",
            "Flags": ["action-contact-oem"],
        }])
        result = assess(report)
        self.assertNotIn("intel-bootguard-policy", {item["finding_id"] for item in result["actionable_findings"]})

    def test_invalid_intel_csme_version_is_actionable_local_policy_failure(self):
        report = self.base_report()
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.Mei.Version",
            "Name": "csme v0:15.0.0.1320",
            "HsiResult": "not-valid",
            "HsiResultSuccess": "valid",
            "Flags": ["action-contact-oem"],
        }])
        result = assess(report)
        finding = next(item for item in result["actionable_findings"] if item["finding_id"] == "intel-csme-firmware-policy")
        self.assertEqual(finding["section"], "platform-security-processor")
        self.assertEqual(finding["severity"], "medium")
        self.assertFalse(finding["compromise_indicator"])
        self.assertIn("15.0.0.1320", " ".join(finding["evidence"]))
        self.assertEqual(result["status"], "attention")

    def test_supported_but_inactive_intel_tme_is_described_as_inactive(self):
        report = self.base_report()
        report["schema_version"] = 16
        report["artifacts"]["memory_protection"] = {
            "capabilities": {"intel_tme": True},
            "system_memory": {
                "active": False,
                "intel_tme": {"supported": True, "active": False, "state": "supported-not-enabled"},
            },
        }
        result = assess(report)
        section = next(item for item in result["sections"] if item["slug"] == "memory-protection")
        self.assertIn("supported but is not reported active", section["simple_result"])

    def test_encrypted_ram_hsi_failure_is_note_not_alarm(self):
        report = self.base_report()
        report["artifacts"]["memory_protection"] = {"capabilities": {"amd_sme": True}, "system_memory": {"amd_sme_kernel_active": False}}
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.EncryptedRam",
            "HsiResult": "not-encrypted",
            "HsiResultSuccess": "encrypted",
            "Flags": ["action-config-fw"],
        }])
        result = assess(report)
        note = next(item for item in result["security_notes"] if item["finding_id"] == "memory-encryption-not-active")
        self.assertEqual(note["section"], "memory-protection")
        self.assertEqual(note["finding_type"], "informational")
        self.assertNotEqual(result["status"], "attention")

    def test_dpkg_missing_documentation_is_not_automatic_alarm(self):
        report = self.base_report()
        report["commands"]["dpkg_verify"] = command("missing     /usr/share/doc/example/changelog.gz")
        ids = {item["finding_id"] for item in assess(report)["findings"]}
        self.assertNotIn("package-files-modified", ids)

    def test_missing_kernel_version_directory_is_not_host_integrity_alarm(self):
        report = self.base_report()
        report["commands"]["dpkg_verify"] = command("missing     /lib/modules/5.19.0-42-generic")
        result = assess(report)
        self.assertNotIn("package-files-modified", {item["finding_id"] for item in result["actionable_findings"]})

    def test_dpkg_security_sensitive_change_is_host_integrity_finding(self):
        report = self.base_report()
        report["commands"]["dpkg_verify"] = command("??5??????   /usr/bin/example")
        report["artifacts"]["package_verify_analysis"] = {
            "backend": "dpkg", "available": True,
            "records": [{"path": "/usr/bin/example", "classification": "security_relevant", "security_relevant": True, "file_role": "program executable"}],
        }
        finding = next(item for item in assess(report)["actionable_findings"] if item["finding_id"] == "package-files-modified")
        self.assertEqual(finding["section"], "host-integrity")
        self.assertEqual(finding["finding_type"], "integrity-indicator")

    def test_dpkg_non_executable_data_drift_is_note_not_alarm(self):
        report = self.base_report()
        report["commands"]["dpkg_verify"] = command("??5??????   /usr/share/example/data.db")
        report["artifacts"]["package_verify_analysis"] = {
            "backend": "dpkg", "available": True,
            "records": [{"path": "/usr/share/example/data.db", "classification": "other_drift", "security_relevant": False}],
        }
        result = assess(report)
        self.assertNotIn("package-files-modified", {item["finding_id"] for item in result["actionable_findings"]})
        self.assertIn("package-noncritical-drift", {item["finding_id"] for item in result["security_notes"]})

    def test_suspend_to_ram_is_note_not_alarm(self):
        report = self.base_report()
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.SuspendToRam",
            "HsiResult": "enabled",
            "HsiResultSuccess": "not-enabled",
            "Flags": ["runtime-issue"],
        }])
        result = assess(report)
        self.assertNotIn("sleep-exposure", {item["finding_id"] for item in result["actionable_findings"]})
        self.assertIn("sleep-exposure", {item["finding_id"] for item in result["security_notes"]})

    def test_dpkg_conffile_change_is_not_automatic_alarm(self):
        report = self.base_report()
        report["commands"]["dpkg_verify"] = command("??5?????? c /etc/example.conf")
        ids = {item["finding_id"] for item in assess(report)["findings"]}
        self.assertNotIn("package-files-modified", ids)

    def test_ld_so_preload_is_reported(self):
        report = self.base_report()
        report["artifacts"]["host_persistence_files"] = [{"path": "/etc/ld.so.preload", "text": "/opt/libhook.so\n", "sha256": "x"}]
        ids = {item["finding_id"] for item in assess(report)["findings"]}
        self.assertIn("dynamic-loader-preload", ids)

    def test_finding_has_type_section_and_explanation_layers(self):
        report = self.base_report()
        report["commands"]["fwupd_security_text"] = command("✘ SPI Write Protection: Disabled")
        result = assess(report)
        finding = next(item for item in result["findings"] if item["finding_id"] == "spi-write-protection")
        self.assertEqual(finding["section"], "firmware-protection")
        self.assertEqual(finding["finding_type"], "protection-weakness")
        self.assertTrue(finding["simple"])
        self.assertTrue(finding["detailed"])
        self.assertTrue(finding["technical"])
        self.assertTrue(finding["evidence_ids"])


    def test_tpm_replay_mismatch_is_investigate(self):
        report = self.base_report()
        report["artifacts"]["tpm_eventlog_replay"] = {
            "state": "mismatch", "algorithm": "sha256", "scope": "PCR 0-7",
            "comparisons": [{"pcr": 0, "live": "11", "replayed": "22", "match": False}],
        }
        result = assess(report)
        self.assertEqual(result["status"], "investigate")
        self.assertIn("tpm-eventlog-replay-mismatch", {item["finding_id"] for item in result["actionable_findings"]})

    def test_likely_truncated_tpm_eventlog_is_attention_not_investigate(self):
        report = self.base_report()
        report["artifacts"]["tpm_eventlog_replay"] = {
            "state": "mismatch", "algorithm": "sha256", "scope": "PCR 0-7",
            "comparisons": [
                {"pcr": 4, "live": "11", "replayed": "22", "match": False},
                {"pcr": 5, "live": "33", "replayed": "44", "match": False},
            ],
            "event_log_diagnostics": {
                "raw_size": 65524,
                "capacity_boundary": 65536,
                "bytes_below_capacity_boundary": 12,
                "near_capacity_boundary": True,
                "ends_during_bootloader_activity": True,
                "likely_truncated": True,
                "mismatched_pcrs": [4, 5, 8, 9],
                "last_event": {
                    "event_num": 127, "pcr": 8, "event_type": "EV_IPL",
                    "summary": "grub_cmd: insmod part_gpt",
                },
            },
        }
        result = assess(report)
        self.assertEqual(result["status"], "attention")
        ids = {item["finding_id"] for item in result["actionable_findings"]}
        self.assertIn("tpm-eventlog-likely-truncated", ids)
        self.assertNotIn("tpm-eventlog-replay-mismatch", ids)
        finding = next(item for item in result["actionable_findings"] if item["finding_id"] == "tpm-eventlog-likely-truncated")
        self.assertFalse(finding["compromise_indicator"])
        self.assertIn("65524", " ".join(finding["evidence"]))

    def test_cpu_vulnerable_state_is_actionable_offline(self):
        report = self.base_report()
        report["artifacts"]["cpu_vulnerabilities"] = [
            {"name": "example", "value": "Vulnerable: mitigation disabled"},
            {"name": "safe", "value": "Mitigation: enabled"},
        ]
        finding = next(item for item in assess(report)["actionable_findings"] if item["finding_id"] == "cpu-vulnerability-unmitigated")
        self.assertIn("example", " ".join(finding["evidence"]))

    def test_vm_cpu_vulnerability_recommendation_points_to_hypervisor(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["systemd_detect_virt"] = command("kvm")
        report["artifacts"]["cpu_vulnerabilities"] = [
            {"name": "mds", "value": "Vulnerable: no microcode; SMT Host state unknown"},
        ]
        finding = next(item for item in assess(report)["actionable_findings"] if item["finding_id"] == "cpu-vulnerability-unmitigated")
        self.assertIn("hypervisor", finding["recommendation"].lower())
        self.assertIn("vm cpu model", finding["recommendation"].lower())

    def test_virtual_machine_scope_note_does_not_make_identity_unknown(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["systemd_detect_virt"] = command("kvm")
        result = assess(report)
        note = next(item for item in result["security_notes"] if item["finding_id"] == "virtual-machine")
        self.assertEqual(note["finding_type"], "informational")
        identity = next(item for item in result["sections"] if item["slug"] == "identity")
        self.assertEqual(identity["status"], "good")

    def test_non_uefi_vm_secure_boot_and_host_security_processor_are_not_applicable(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["systemd_detect_virt"] = command("kvm")
        report["commands"]["secure_boot_state"] = command("", status="not_applicable")
        result = assess(report)
        secure = next(item for item in result["sections"] if item["slug"] == "secure-boot")
        processor = next(item for item in result["sections"] if item["slug"] == "platform-security-processor")
        self.assertEqual(secure["status"], "not_applicable")
        self.assertIn("not applicable", secure["simple_result"].lower())
        self.assertEqual(processor["status"], "not_applicable")
        self.assertIn("physical host", processor["simple_result"].lower())

    def test_uefi_vm_keeps_guest_uefi_checks_but_host_security_processor_is_not_applicable(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = True
        report["commands"]["systemd_detect_virt"] = command("kvm")
        profile = detect_platform_profile(report)
        self.assertEqual(profile["kind"], "virtual-machine")
        self.assertEqual(profile["boot_mode"], "uefi")
        result = assess(report)
        secure = next(item for item in result["sections"] if item["slug"] == "secure-boot")
        processor = next(item for item in result["sections"] if item["slug"] == "platform-security-processor")
        self.assertNotEqual(secure["status"], "not_applicable")
        self.assertEqual(processor["status"], "not_applicable")
        self.assertIn("physical host", processor["simple_result"].lower())

    def test_vm_physical_write_protection_and_oob_are_not_applicable(self):
        report = self.base_report()
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["systemd_detect_virt"] = command("kvm")
        self.set_fwupd_attributes(report, [{
            "AppstreamId": "org.fwupd.hsi.Spi.Bioswe",
            "HsiResult": "not-locked",
            "HsiResultSuccess": "locked",
            "Flags": ["action-config-fw"],
        }])
        result = assess(report)
        firmware = next(item for item in result["sections"] if item["slug"] == "firmware-protection")
        oob = next(item for item in result["sections"] if item["slug"] == "out-of-band-management")
        self.assertEqual(firmware["status"], "not_applicable")
        self.assertIn("physical host", firmware["simple_result"].lower())
        self.assertEqual(oob["status"], "not_applicable")
        self.assertIn("physical host", oob["simple_result"].lower())
        self.assertNotIn("spi-write-protection", {item["finding_id"] for item in result["findings"]})

    def test_vm_memory_wording_is_guest_scoped(self):
        report = self.base_report()
        report["schema_version"] = 16
        report["artifacts"]["uefi_mode"] = False
        report["commands"]["systemd_detect_virt"] = command("kvm")
        report["artifacts"]["memory_protection"] = {
            "capabilities": {},
            "system_memory": {},
            "confidential_vm": {},
        }
        result = assess(report)
        memory = next(item for item in result["sections"] if item["slug"] == "memory-protection")
        self.assertIn("guest-visible", memory["simple_result"].lower())
        self.assertIn("physical host", memory["simple_result"].lower())

    def test_partial_cpu_mitigation_with_vulnerable_qualifier_remains_actionable(self):
        report = self.base_report()
        report["artifacts"]["cpu_vulnerabilities"] = [
            {"name": "mds", "value": "Mitigation: Clear CPU buffers; SMT vulnerable"},
        ]
        ids = {item["finding_id"] for item in assess(report)["actionable_findings"]}
        self.assertIn("cpu-vulnerability-unmitigated", ids)

    def test_mitigations_off_is_actionable(self):
        report = self.base_report()
        report["commands"]["proc_cmdline"] = command("root=/dev/mapper/root ro mitigations=off quiet")
        ids = {item["finding_id"] for item in assess(report)["actionable_findings"]}
        self.assertIn("security-boot-parameter", ids)

    def test_thunderbolt_iommu_protection_avoids_alarm(self):
        report = self.base_report()
        report["artifacts"]["thunderbolt_security"] = {
            "available": True,
            "domains": [{"name": "domain0", "security": "user", "iommu_dma_protection": "1"}],
            "devices": [{"name": "0-1", "authorized": "1", "device_name": "dock"}],
        }
        ids = {item["finding_id"] for item in assess(report)["actionable_findings"]}
        self.assertNotIn("thunderbolt-dma-exposure", ids)

    def test_unprotected_authorized_thunderbolt_is_actionable(self):
        report = self.base_report()
        report["artifacts"]["thunderbolt_security"] = {
            "available": True,
            "domains": [{"name": "domain0", "security": "none", "iommu_dma_protection": "0"}],
            "devices": [{"name": "0-1", "authorized": "1", "device_name": "dock"}],
        }
        ids = {item["finding_id"] for item in assess(report)["actionable_findings"]}
        self.assertIn("thunderbolt-dma-exposure", ids)

    def test_secure_boot_sources_disagree(self):
        report = self.base_report()
        report["commands"]["bootctl"] = command("Secure Boot: disabled")
        ids = {item["finding_id"] for item in assess(report)["actionable_findings"]}
        self.assertIn("boot-trust-inconsistent", ids)

    def test_missing_ima_is_not_a_failure(self):
        report = self.base_report()
        report["artifacts"]["integrity_frameworks"] = {"ima": {"available": False}, "ipe": {"available": False}}
        ids = {item["finding_id"] for item in assess(report)["actionable_findings"]}
        self.assertNotIn("ima-appraisal-disabled", ids)


if __name__ == "__main__":
    unittest.main()



def test_legacy_new_sections_are_unknown_not_not_applicable():
    report = AssessmentTests().base_report()
    report["schema_version"] = 9
    result = assess(report)
    by_slug = {item["slug"]: item for item in result["sections"]}
    for slug in ("platform-security-processor", "out-of-band-management", "memory-protection"):
        assert by_slug[slug]["status"] == "unknown"
        assert "not collected by the Firmware Audit version" in by_slug[slug]["simple_result"]


def test_amd_psp_direct_failure_is_not_suppressed_by_unrelated_hsi():
    helper = AssessmentTests()
    report = helper.base_report()
    report["artifacts"]["platform_security_processors"] = {
        "amd_psp": {
            "observable": True,
            "devices": [{"bdf": "0000:03:00.2", "attributes": {"fused_part": "0", "anti_rollback_status": "0"}}],
        }
    }
    helper.set_fwupd_attributes(report, [{
        "AppstreamId": "org.fwupd.hsi.Amd.RollbackProtection",
        "HsiResult": "enabled",
        "HsiResultSuccess": "enabled",
        "Flags": ["success"],
    }])
    result = assess(report)
    assert any(item["finding_id"] == "amd-psp-security-controls" for item in result["findings"])
    assert any(item["finding_id"] == "amd-psp-evidence-inconsistent" for item in result["findings"])


def test_amd_tsme_direct_state_counts_as_active_memory_encryption():
    report = AssessmentTests().base_report()
    report["schema_version"] = 12
    report["artifacts"]["platform_security_processors"] = {
        "amd_psp": {"observable": True, "devices": [{"bdf": "0000:03:00.2", "attributes": {"tsme_status": "1"}}]}
    }
    report["artifacts"]["memory_protection"] = {"capabilities": {}, "system_memory": {}}
    result = assess(report)
    section = next(item for item in result["sections"] if item["slug"] == "memory-protection")
    assert section["simple_result"] == "Hardware-backed system-memory encryption is reported active."


def test_tsme_active_gets_specific_memory_protection_summary():
    helper = AssessmentTests()
    report = helper.base_report()
    report["schema_version"] = 13
    report["artifacts"]["platform_security_processors"] = {
        "amd_psp": {"observable": True, "devices": [{"bdf": "0000:08:00.2", "attributes": {"tsme_status": "1"}}]}
    }
    report["artifacts"]["memory_protection"] = {
        "capabilities": {"amd_sme": True, "amd_sev": True, "amd_sev_es": True, "amd_sev_snp": False},
        "system_memory": {
            "active": True,
            "amd_sme_kernel_active": False,
            "amd_sme": {"supported": True, "linux_managed_active": False, "state": "supported-os-not-active-tsme-active"},
            "amd_tsme": {"active": True, "state": "active-transparent"},
        },
        "confidential_vm": {"amd_sev": {"supported": True, "host_enabled": False, "state": "supported-host-disabled"}},
    }
    result = assess(report)
    section = next(item for item in result["sections"] if item["slug"] == "memory-protection")
    assert "AMD Transparent SME (TSME) is active" in section["simple_result"]
    assert "OS-managed SME is supported" in section["simple_result"]


def test_active_tsme_overrides_failed_fwupd_encrypted_ram_note():
    helper = AssessmentTests()
    report = helper.base_report()
    report["schema_version"] = 13
    report["artifacts"]["memory_protection"] = {
        "capabilities": {"amd_sme": True},
        "system_memory": {"active": True, "amd_tsme": {"active": True, "state": "active-transparent"}},
    }
    helper.set_fwupd_attributes(report, [{
        "AppstreamId": "org.fwupd.hsi.EncryptedRam",
        "HsiResult": "not-encrypted",
        "HsiResultSuccess": "encrypted",
        "Flags": ["action-config-fw"],
    }])
    result = assess(report)
    assert "memory-encryption-not-active" not in {item["finding_id"] for item in result["security_notes"]}


def test_enabled_firmware_persistence_is_security_note_not_alarm():
    report = AssessmentTests().base_report()
    report["schema_version"] = 13
    report["artifacts"]["out_of_band_management"] = {
        "bmc": {"detected": False, "interfaces": []},
        "intel_amt": {"detected": False, "records": []},
        "firmware_persistence": [{
            "setting": "AbsolutePersistenceModuleActivation",
            "state": "firmware-enabled-agent-state-unknown",
            "evidence": "thinklmi/AbsolutePersistenceModuleActivation=Enable",
        }],
    }
    result = assess(report)
    note = next(item for item in result["security_notes"] if item["finding_id"] == "firmware-persistence-enabled")
    assert note["finding_type"] == "informational"
    assert note not in result["actionable_findings"]


def test_enabled_dash_is_security_note_not_alarm():
    report = AssessmentTests().base_report()
    report["schema_version"] = 13
    report["artifacts"]["out_of_band_management"] = {
        "bmc": {"detected": False, "interfaces": []},
        "intel_amt": {"detected": False, "records": []},
        "dmtf_dash": {"detected": True, "state": "enabled", "evidence": ["DASH enabled"]},
    }
    result = assess(report)
    note = next(item for item in result["security_notes"] if item["finding_id"] == "oob-dash-enabled")
    assert note["finding_type"] == "informational"
    assert note not in result["actionable_findings"]
