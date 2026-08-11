from __future__ import annotations

import unittest

import collector
from collection_profiles import CONVENTIONAL_UEFI_CHECKS, build_conventional_uefi_collection
from sections import SECTIONS, section_for_command


class ConventionalUefiCollectionTests(unittest.TestCase):
    def test_profile_has_dasharo_like_capability_areas(self) -> None:
        ids = {item["id"] for item in CONVENTIONAL_UEFI_CHECKS}
        self.assertEqual(len(CONVENTIONAL_UEFI_CHECKS), 14)
        self.assertIn("firmware-write-resistance", ids)
        self.assertIn("hardware-verified-firmware-boot", ids)
        self.assertIn("measured-boot", ids)
        self.assertIn("uefi-secure-boot", ids)
        self.assertIn("early-dma-protection", ids)
        self.assertIn("authenticated-firmware-updates", ids)
        self.assertIn("firmware-recovery", ids)

    def test_uefi_profile_is_collection_only(self) -> None:
        report = {
            "commands": {
                "fwupd_security_json": {"status": "collected"},
                "fwupd_security_text": {"status": "collected"},
            },
            "artifacts": {"platform_profile": {"kind": "uefi"}},
        }
        result = build_conventional_uefi_collection(report)
        self.assertTrue(result["applicable"])
        self.assertEqual(result["mode"], "collection-only")
        self.assertFalse(result["network_access_performed"])
        self.assertTrue(all("collection_state" in item for item in result["checks"]))
        self.assertFalse(any("result" in item or "severity" in item for item in result["checks"]))

    def test_coreboot_with_uefi_runtime_can_use_uefi_collection_manifest(self) -> None:
        report = {
            "commands": {},
            "artifacts": {
                "platform_profile": {
                    "kind": "coreboot",
                    "runtime_interface": "uefi",
                    "boot_trust_model": "uefi",
                    "firmware_family": "coreboot",
                }
            },
        }
        result = build_conventional_uefi_collection(report)
        self.assertTrue(result["applicable"])

    def test_heads_profile_is_not_applicable(self) -> None:
        report = {"commands": {}, "artifacts": {"platform_profile": {"kind": "coreboot-heads"}}}
        result = build_conventional_uefi_collection(report)
        self.assertFalse(result["applicable"])
        self.assertTrue(all(item["collection_state"] == "not_applicable" for item in result["checks"]))

    def test_new_collection_commands_are_read_only_and_offline(self) -> None:
        argv = {spec.name: spec.argv for spec in collector.COMMANDS}
        self.assertEqual(argv["fwupd_bios_settings_json"][:2], ("fwupdmgr", "get-bios-settings"))
        self.assertEqual(argv["fwupd_remotes_json"][:2], ("fwupdmgr", "get-remotes"))
        self.assertEqual(argv["fwupd_topology_json"][:2], ("fwupdmgr", "get-topology"))
        self.assertNotIn(("fwupdmgr", "refresh"), [spec.argv[:2] for spec in collector.COMMANDS])
        forbidden = {"update", "install", "downgrade", "set-bios-setting", "security-fix", "security-undo"}
        for spec in collector.COMMANDS:
            self.assertFalse(forbidden.intersection(spec.argv), spec.name)

    def test_swap_collection_does_not_request_unsupported_swapon_json(self) -> None:
        argv = {spec.name: spec.argv for spec in collector.COMMANDS}
        self.assertNotIn("swapon_json", argv)
        self.assertEqual(argv["swapon_text"][:2], ("swapon", "--show"))
        self.assertIn("swapon_text", SECTIONS["storage-memory"]["commands"])
        self.assertNotIn("swapon_json", SECTIONS["storage-memory"]["commands"])

    def test_optional_evidence_is_assigned_to_sections(self) -> None:
        self.assertEqual(section_for_command("fwupd_bios_settings_json"), "firmware-protection")
        self.assertEqual(section_for_command("iommu_kernel_log"), "storage-memory")
        self.assertIn("iommu_groups", SECTIONS["storage-memory"]["optional_artifacts"])
        self.assertIn("conventional_uefi_collection", SECTIONS["firmware-protection"]["optional_artifacts"])


if __name__ == "__main__":
    unittest.main()
