from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import collector
from report_format import (
    REPORT_FORMAT_NAME,
    REPORT_FORMAT_VERSION,
    _cpu_model,
    _installed_kernel_releases,
    build_report,
    build_results,
)
from sections import SECTION_ORDER


class ReportFormatTests(unittest.TestCase):
    def test_profiles_support_fast_and_expensive_schedules(self) -> None:
        self.assertEqual(collector.PROFILES["full"], SECTION_ORDER)
        self.assertNotIn("host-integrity", collector.PROFILES["daily"])
        self.assertEqual(collector.PROFILES["integrity"], ["host-integrity"])

    def test_selected_area_command_plan_avoids_host_integrity_work(self) -> None:
        specs, requested_by = collector.command_plan(["memory-protection"])
        names = {spec.name for spec in specs}
        self.assertIn("cpuid_amd_memory_encryption", names)
        self.assertIn("lspci", names)  # support dependency for platform security processor
        self.assertNotIn("dpkg_verify", names)
        self.assertNotIn("suid_sgid_files", names)
        self.assertIn("memory-protection", requested_by["lspci"])


    def test_live_intel_command_plan_skips_amd_only_probes(self) -> None:
        specs, requested_by = collector.command_plan(["memory-protection"], cpu_vendor="GenuineIntel")
        names = {spec.name for spec in specs}
        self.assertNotIn("cpuid_amd_memory_encryption", names)
        self.assertNotIn("msr_amd_syscfg", names)
        self.assertNotIn("msr_amd_sev_status", names)
        self.assertNotIn("cpuid_amd_memory_encryption", requested_by)
        self.assertIn("fwupd_security_json", names)

    def test_live_intel_command_plan_includes_intelmetool(self) -> None:
        specs, requested_by = collector.command_plan(["platform-security-processor"], cpu_vendor="GenuineIntel")
        names = {spec.name for spec in specs}
        self.assertIn("intelmetool", names)
        self.assertIn("intelmetool", requested_by)
        self.assertIn("proc_self_status", names)
        self.assertIn("kernel_lockdown", names)
        self.assertIn("proc_self_status", requested_by)

    def test_virtual_machine_command_plan_skips_host_direct_intel_probes(self) -> None:
        specs, requested_by = collector.command_plan(
            ["platform-security-processor"],
            cpu_vendor="GenuineIntel",
            virtualization_kind="kvm",
        )
        names = {spec.name for spec in specs}
        self.assertNotIn("intelmetool", names)
        self.assertNotIn("proc_self_status", names)
        self.assertNotIn("intelmetool", requested_by)
        self.assertNotIn("proc_self_status", requested_by)
        self.assertIn("systemd_detect_virt", names)

    def test_live_amd_command_plan_skips_intelmetool(self) -> None:
        specs, requested_by = collector.command_plan(["platform-security-processor"], cpu_vendor="AuthenticAMD")
        names = {spec.name for spec in specs}
        self.assertNotIn("intelmetool", names)
        self.assertNotIn("intelmetool", requested_by)
        self.assertNotIn("proc_self_status", names)
        self.assertNotIn("proc_self_status", requested_by)

    def test_live_amd_command_plan_keeps_amd_only_probes(self) -> None:
        specs, _ = collector.command_plan(["memory-protection"], cpu_vendor="AuthenticAMD")
        names = {spec.name for spec in specs}
        self.assertIn("cpuid_amd_memory_encryption", names)
        self.assertIn("msr_amd_syscfg", names)
        self.assertIn("msr_amd_sev_status", names)

    def test_partial_results_include_only_requested_areas(self) -> None:
        assessment = {
            "status": "attention",
            "headline": "full headline",
            "explanation": "full explanation",
            "sections": [
                {"slug": "identity", "title": "Identity", "short_title": "Identity", "question": "q", "status": "good", "simple_result": "ok", "simple_explanation": "ok", "actionable_findings": [], "security_notes": [], "checks": []},
                {"slug": "host-integrity", "title": "Host", "short_title": "Host", "question": "q", "status": "attention", "simple_result": "bad", "simple_explanation": "bad", "actionable_findings": [{"section": "host-integrity", "title": "x"}], "security_notes": [], "checks": []},
            ],
            "findings": [{"section": "host-integrity", "title": "x"}],
            "security_notes": [],
            "platform_profile": {"kind": "uefi"},
        }
        results = build_results(assessment, ["identity"], scope="partial")
        self.assertEqual([area["slug"] for area in results["areas"]], ["identity"])
        self.assertEqual(results["overall"]["status"], "good")
        self.assertEqual(results["findings"], [])


    def test_overall_good_can_have_partial_coverage(self) -> None:
        assessment = {
            "status": "unknown",
            "headline": "legacy unknown",
            "explanation": "legacy unknown",
            "sections": [
                {"slug": "identity", "title": "Identity", "short_title": "Identity", "question": "q", "status": "good", "simple_result": "ok", "simple_explanation": "ok", "actionable_findings": [], "security_notes": [], "checks": []},
                {"slug": "platform-security-processor", "title": "PSP", "short_title": "Platform security processor", "question": "q", "status": "unknown", "simple_result": "unknown", "simple_explanation": "unknown", "actionable_findings": [], "security_notes": [], "checks": []},
            ],
            "findings": [], "security_notes": [], "platform_profile": {"kind": "uefi"},
        }
        results = build_results(assessment, ["identity", "platform-security-processor"], scope="partial")
        self.assertEqual(results["overall"]["status"], "good")
        self.assertEqual(results["overall"]["headline"], "No issues found in assessed areas")
        self.assertEqual(results["overall"]["coverage"]["status"], "partial")

    def test_overall_attention_can_have_partial_coverage(self) -> None:
        assessment = {
            "status": "attention", "headline": "x", "explanation": "x",
            "sections": [
                {"slug": "host-integrity", "title": "Host", "short_title": "Host", "question": "q", "status": "attention", "simple_result": "review", "simple_explanation": "review", "actionable_findings": [], "security_notes": [], "checks": []},
                {"slug": "platform-security-processor", "title": "PSP", "short_title": "Platform security processor", "question": "q", "status": "unknown", "simple_result": "unknown", "simple_explanation": "unknown", "actionable_findings": [], "security_notes": [], "checks": []},
            ],
            "findings": [], "security_notes": [], "platform_profile": {"kind": "uefi"},
        }
        results = build_results(assessment, ["host-integrity", "platform-security-processor"], scope="partial")
        self.assertEqual(results["overall"]["status"], "attention")
        self.assertEqual(results["overall"]["coverage"]["status"], "partial")

    def test_overall_unknown_requires_insufficient_coverage(self) -> None:
        assessment = {
            "status": "unknown", "headline": "x", "explanation": "x",
            "sections": [
                {"slug": "platform-security-processor", "title": "PSP", "short_title": "Platform security processor", "question": "q", "status": "unknown", "simple_result": "unknown", "simple_explanation": "unknown", "actionable_findings": [], "security_notes": [], "checks": []},
            ],
            "findings": [], "security_notes": [], "platform_profile": {"kind": "uefi"},
        }
        results = build_results(assessment, ["platform-security-processor"], scope="partial")
        self.assertEqual(results["overall"]["status"], "unknown")
        self.assertEqual(results["overall"]["coverage"]["status"], "insufficient")

    def test_overall_good_complete_coverage(self) -> None:
        assessment = {
            "status": "good", "headline": "x", "explanation": "x",
            "sections": [
                {"slug": "identity", "title": "Identity", "short_title": "Identity", "question": "q", "status": "good", "simple_result": "ok", "simple_explanation": "ok", "actionable_findings": [], "security_notes": [], "checks": []},
            ],
            "findings": [], "security_notes": [], "platform_profile": {"kind": "uefi"},
        }
        results = build_results(assessment, ["identity"], scope="partial")
        self.assertEqual(results["overall"]["status"], "good")
        self.assertEqual(results["overall"]["coverage"]["status"], "complete")

    def test_cpu_model_prefers_model_name_over_processor_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cpuinfo = Path(tmp) / "cpuinfo"
            cpuinfo.write_text(
                "processor\t: 0\n"
                "vendor_id\t: AuthenticAMD\n"
                "model name\t: AMD Ryzen 7 PRO 5850U with Radeon Graphics\n",
                encoding="utf-8",
            )
            self.assertEqual(_cpu_model(cpuinfo), "AMD Ryzen 7 PRO 5850U with Radeon Graphics")

    def test_installed_kernels_exclude_removed_dpkg_leftovers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            status = root / "status"
            modules = root / "modules"
            modules.mkdir()
            for release in ("5.19.0-21-generic", "6.1.6-060106-generic", "6.8.0-136-generic", "6.8.0-137-generic"):
                (modules / release).mkdir()
            status.write_text(
                "Package: linux-image-5.19.0-21-generic\nStatus: deinstall ok config-files\n\n"
                "Package: linux-image-6.8.0-136-generic\nStatus: install ok installed\n\n"
                "Package: linux-image-6.8.0-137-generic\nStatus: install ok installed\n\n"
                "Package: linux-image-generic\nStatus: install ok installed\n\n"
                "Package: linux-image-unsigned-6.1.6-060106-generic\nStatus: install ok installed\n",
                encoding="utf-8",
            )
            self.assertEqual(
                _installed_kernel_releases(
                    "6.8.0-136-generic",
                    modules_dir=modules,
                    dpkg_status_path=status,
                ),
                ["6.1.6-060106-generic", "6.8.0-136-generic", "6.8.0-137-generic"],
            )

    def test_installed_kernels_fall_back_to_module_directories_without_dpkg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            modules = root / "modules"
            modules.mkdir()
            (modules / "6.6.1-custom").mkdir()
            self.assertEqual(
                _installed_kernel_releases(
                    "6.6.2-running",
                    modules_dir=modules,
                    dpkg_status_path=root / "missing-status",
                ),
                ["6.6.1-custom", "6.6.2-running"],
            )

    def test_installer_cleans_legacy_units_before_package_install(self) -> None:
        text = Path("install.sh").read_text(encoding="utf-8")
        cleanup_call = text.index("cleanup_obsolete_units\n")
        apt_update = text.index("\n  apt-get update\n")
        self.assertLess(cleanup_call, apt_update)
        self.assertIn('systemctl stop "$unit"', text)
        self.assertIn('systemctl disable "$unit"', text)
        self.assertIn("systemctl daemon-reload", text)
        self.assertIn("systemctl reset-failed", text)
        self.assertIn("timers.target.wants/firmware-audit-collect.timer", text)

    def test_public_report_contract_has_system_scope_results_and_evidence(self) -> None:
        assessment = {
            "status": "good", "headline": "Good", "explanation": "Good",
            "sections": [{"slug": "identity", "title": "Identity", "short_title": "Identity", "question": "q", "status": "good", "simple_result": "ok", "simple_explanation": "ok", "actionable_findings": [], "security_notes": [], "checks": []}],
            "findings": [], "security_notes": [], "platform_profile": {"kind": "uefi"},
        }
        report = build_report(
            report_id="r", created_at="t", scanner_version="0.12.0", profile="custom",
            requested_areas=["identity"], all_areas=list(SECTION_ORDER),
            system={"id": "sha256:x", "hostname": "h", "os": {}, "kernel": {}, "hardware": {}},
            timing={"duration_ms": 1}, assessment=assessment, commands={}, artifacts={},
        )
        self.assertEqual(report["format"], {"name": REPORT_FORMAT_NAME, "version": REPORT_FORMAT_VERSION})
        self.assertEqual(report["report"]["scope"], "partial")
        self.assertIn("system", report)
        self.assertIn("results", report)
        self.assertIn("evidence", report)
        self.assertNotIn("assessment", report)
        self.assertNotIn("commands", report)
        self.assertNotIn("artifacts", report)


if __name__ == "__main__":
    unittest.main()
