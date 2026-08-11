from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import collector


class CollectorLocaleTests(unittest.TestCase):
    def test_command_environment_forces_english_utf8_locale(self) -> None:
        self.assertEqual(collector.COMMAND_ENV["LANG"], "C.UTF-8")
        self.assertEqual(collector.COMMAND_ENV["LC_ALL"], "C.UTF-8")
        self.assertEqual(collector.COMMAND_ENV["LANGUAGE"], "en")

    @patch("collector.shutil.which", return_value="/usr/bin/locale")
    @patch("collector.subprocess.Popen")
    def test_run_command_passes_fixed_environment(self, popen_mock, _which_mock) -> None:
        process = popen_mock.return_value
        process.stdout = io.BytesIO(b"LANG=C.UTF-8\nLC_ALL=C.UTF-8\n")
        process.stderr = io.BytesIO(b"")
        process.wait.return_value = 0

        result = collector.run_command(collector.CommandSpec("locale_test", ("locale",)))

        self.assertEqual(result["status"], "collected")
        self.assertEqual(popen_mock.call_args.kwargs["env"], collector.COMMAND_ENV)
        self.assertNotIn("sl_SI", popen_mock.call_args.kwargs["env"].values())

    @patch("collector.shutil.which", return_value="/usr/sbin/swapon")
    @patch("collector.subprocess.Popen")
    def test_unsupported_command_option_has_explicit_state(self, popen_mock, _which_mock) -> None:
        process = popen_mock.return_value
        process.stdout = io.BytesIO(b"")
        process.stderr = io.BytesIO(b"swapon: unrecognized option '--json'\n")
        process.wait.return_value = 1
        result = collector.run_command(collector.CommandSpec("swapon_json", ("swapon", "--json")))
        self.assertEqual(result["status"], "unsupported")

    def test_fwupd_hsi_unavailable_in_hypervisor_is_not_applicable(self) -> None:
        spec = collector.CommandSpec("fwupd_security_json", ("fwupdmgr", "security", "--json"))
        status = collector._result_status(spec, 1, '{"Error":{"Message":"HSI unavailable for unprivileged hypervisor"}}', "")
        self.assertEqual(status, "not_applicable")

    def test_missing_ipmi_device_is_not_applicable(self) -> None:
        spec = collector.CommandSpec("ipmitool_mc_info", ("ipmitool", "mc", "info"))
        status = collector._result_status(spec, 1, "", "Could not open device at /dev/ipmi0: No such file or directory")
        self.assertEqual(status, "not_applicable")

    def test_missing_msr_device_is_not_applicable(self) -> None:
        spec = collector.CommandSpec("msr_amd_syscfg", ("rdmsr", "0xc0010010"))
        status = collector._result_status(spec, 127, "", "rdmsr: open: No such file or directory")
        self.assertEqual(status, "not_applicable")

    def test_missing_tpm_device_is_not_applicable(self) -> None:
        spec = collector.CommandSpec("tpm_properties", ("tpm2_getcap", "properties-fixed"))
        stderr = (
            "Failed to open specified TCTI device file /dev/tpmrm0: No such file or directory\n"
            "Failed to open specified TCTI device file /dev/tpm0: No such file or directory\n"
        )
        self.assertEqual(collector._result_status(spec, 1, "", stderr), "not_applicable")



class CollectorForensicMetadataTests(unittest.TestCase):
    @patch("collector.shutil.which", return_value="/usr/bin/printf")
    @patch("collector.subprocess.Popen")
    def test_run_command_records_hashes_timestamps_and_section(self, popen_mock, _which_mock) -> None:
        process = popen_mock.return_value
        process.stdout = io.BytesIO(b"evidence\n")
        process.stderr = io.BytesIO(b"")
        process.wait.return_value = 0
        result = collector.run_command(collector.CommandSpec("kernel_taint", ("printf", "evidence")))
        self.assertEqual(result["section"], "kernel-runtime")
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(b"evidence\n").hexdigest())
        self.assertEqual(result["stderr_sha256"], hashlib.sha256(b"").hexdigest())
        self.assertIn("started_at", result)
        self.assertIn("finished_at", result)
        self.assertEqual(result["environment"], collector.COMMAND_ENV)

    def test_status_channel_is_high_level_only(self) -> None:
        self.assertIn("Installed files and persistence", {area for area, _ in collector.COLLECTION_AREAS.values()})
        source = Path(collector.__file__).read_text(encoding="utf-8")
        self.assertIn("status.json", source)
        self.assertIn("systemctl", Path("install.sh").read_text(encoding="utf-8"))

    def test_snapshot_mode_collects_no_history_sources(self) -> None:
        names = {spec.name for spec in collector.COMMANDS}
        self.assertNotIn("fwupd_history_json", names)
        self.assertNotIn("previous_kernel_journal", names)
        self.assertFalse(hasattr(collector, "build_baseline"))


    def test_package_drift_classifies_executable_as_security_relevant(self) -> None:
        commands = {
            "dpkg_verify": {"stdout": "??5??????   /usr/bin/python3\n"},
            "dpkg_diversions": {"stdout": ""},
            "dpkg_statoverrides": {"stdout": ""},
        }
        result = collector.collect_dpkg_verify_analysis(commands)
        self.assertEqual(result["counts"]["security_relevant"], 1)
        self.assertEqual(result["records"][0]["classification"], "security_relevant")

    def test_missing_kernel_version_directory_is_not_security_relevant(self) -> None:
        commands = {
            "dpkg_verify": {"stdout": "missing     /lib/modules/5.19.0-42-generic\n"},
            "dpkg_diversions": {"stdout": ""},
            "dpkg_statoverrides": {"stdout": ""},
        }
        result = collector.collect_dpkg_verify_analysis(commands)
        self.assertEqual(result["counts"]["security_relevant"], 0)
        self.assertEqual(result["counts"]["ignored"], 1)
        self.assertFalse(result["records"][0]["security_relevant"])
        self.assertIn("kernel package directory", result["records"][0]["file_role"])

    def test_kernel_module_file_remains_security_relevant(self) -> None:
        commands = {
            "dpkg_verify": {"stdout": "missing     /lib/modules/6.12.0/kernel/drivers/example.ko.xz\n"},
            "dpkg_diversions": {"stdout": ""},
            "dpkg_statoverrides": {"stdout": ""},
        }
        result = collector.collect_dpkg_verify_analysis(commands)
        self.assertEqual(result["counts"]["security_relevant"], 1)
        self.assertEqual(result["records"][0]["file_role"], "kernel module")

    def test_package_drift_keeps_conffile_non_actionable(self) -> None:
        commands = {
            "dpkg_verify": {"stdout": "??5?????? c /etc/example.conf\n"},
            "dpkg_diversions": {"stdout": ""},
            "dpkg_statoverrides": {"stdout": ""},
        }
        result = collector.collect_dpkg_verify_analysis(commands)
        self.assertEqual(result["counts"]["configuration"], 1)
        self.assertFalse(result["records"][0]["security_relevant"])




    def test_platform_security_processor_collects_mei_and_explicit_pluton(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mei = root / "mei"
            pci = root / "pci"
            (mei / "mei0").mkdir(parents=True)
            pci.mkdir()
            (mei / "mei0" / "fw_ver").write_text("16.1.30.2264\n", encoding="utf-8")
            (mei / "mei0" / "dev_state").write_text("ENABLED\n", encoding="utf-8")
            commands = {
                "kernel_journal": {"stdout": ""},
                "lspci": {"stdout": ""},
                "lspci_verbose": {"stdout": ""},
                "fwupd_devices_json": {"stdout": json.dumps({"Devices": [{"Name": "Microsoft Pluton Security Processor", "Vendor": "Microsoft"}]})},
            }
            result = collector.collect_platform_security_processors(commands, mei_root=mei, pci_root=pci)
            self.assertTrue(result["intel_mei"]["observable"])
            self.assertEqual(result["intel_mei"]["devices"][0]["fw_ver"], "16.1.30.2264")
            self.assertEqual(result["explicit_other"][0]["technology"], "Microsoft Pluton")

    def test_platform_security_processor_distinguishes_disabled_me_from_failed_mei(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mei = root / "mei"
            pci = root / "pci"
            mei.mkdir()
            pci.mkdir()
            commands = {
                "kernel_journal": {"stdout": (
                    "mei_me 0000:00:16.0: wait hw ready failed\n"
                    "mei_me 0000:00:16.0: initialization failed.\n"
                )},
                "lspci": {"stdout": "00:16.0 Communication controller [0780]: Intel Corporation Meteor Lake-P CSME HECI #1 [8086:7e70] (rev 20)\n"},
                "lspci_verbose": {"stdout": ""},
                "intelmetool": {
                    "status": "collected",
                    "returncode": 0,
                    "stdout": (
                        "ME: Current Working State : Disabled\n"
                        "ME: Current Operation Mode : Soft Temporary Disable\n"
                        "ME: Error Code : Disabled\n"
                    ),
                    "stderr": "",
                },
            }
            result = collector.collect_platform_security_processors(commands, mei_root=mei, pci_root=pci)
            self.assertTrue(result["intel_mei"]["hardware_present"])
            self.assertFalse(result["intel_mei"]["observable"])
            self.assertEqual(result["intel_mei"]["state"], "disabled")
            self.assertEqual(result["intel_mei"]["state_source"], "intelmetool")
            self.assertTrue(result["intel_mei"]["journal"]["initialization_failed"])

    def test_platform_security_processor_mei_failure_without_decoder_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mei = root / "mei"
            pci = root / "pci"
            mei.mkdir()
            pci.mkdir()
            commands = {
                "kernel_journal": {"stdout": "mei_me 0000:00:16.0: initialization failed.\n"},
                "lspci": {"stdout": "00:16.0 Communication controller [0780]: Intel Corporation Meteor Lake-P CSME HECI #1 [8086:7e70] (rev 20)\n"},
                "lspci_verbose": {"stdout": ""},
                "intelmetool": {"status": "failed_with_output", "returncode": 1, "stdout": "Found unsupported platform\n", "stderr": ""},
            }
            result = collector.collect_platform_security_processors(commands, mei_root=mei, pci_root=pci)
            self.assertTrue(result["intel_mei"]["hardware_present"])
            self.assertEqual(result["intel_mei"]["state"], "host-interface-unavailable")
            self.assertEqual(result["intel_mei"]["intelmetool"]["state"], "probe-failed")

    def test_platform_security_processor_intelmetool_iopl_denied_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mei = root / "mei"
            pci = root / "pci"
            mei.mkdir()
            pci.mkdir()
            commands = {
                "kernel_journal": {"stdout": ""},
                "lspci": {"stdout": "00:16.0 Communication controller [0780]: Intel Corporation CSME HECI #1 [8086:aaaa]\n"},
                "lspci_verbose": {"stdout": ""},
                "intelmetool": {
                    "status": "permission_denied",
                    "returncode": 1,
                    "effective_uid": 0,
                    "stdout": "",
                    "stderr": "iopl: Operation not permitted\nYou need to be root.\n",
                },
                "kernel_lockdown": {"stdout": "none [integrity] confidentiality\n"},
                "proc_self_status": {
                    "stdout": "CapEff:\t000001ffffffffff\nCapPrm:\t000001ffffffffff\nCapBnd:\t000001ffffffffff\nNoNewPrivs:\t0\n"
                },
            }
            result = collector.collect_platform_security_processors(commands, mei_root=mei, pci_root=pci)
            tool = result["intel_mei"]["intelmetool"]
            self.assertEqual(tool["state"], "blocked")
            self.assertEqual(tool["reason"], "iopl-permission-denied")
            self.assertFalse(tool["usable"])
            self.assertEqual(tool["effective_uid"], 0)
            self.assertEqual(tool["privilege_context"]["kernel_lockdown"]["active"], "integrity")
            self.assertTrue(tool["privilege_context"]["capabilities"]["effective"])
            self.assertIn("kernel-lockdown-active", tool["privilege_context"]["observed_restrictions"])
            self.assertTrue(tool["privilege_context"]["root_message_despite_euid0"])
            self.assertEqual(result["intel_mei"]["state"], "hardware-present-state-unknown")

    def test_platform_security_processor_intelmetool_cannot_find_me_pci_is_inconclusive(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mei = root / "mei"
            pci = root / "pci"
            mei.mkdir()
            pci.mkdir()
            commands = {
                "kernel_journal": {"stdout": ""},
                "lspci": {"stdout": "00:16.0 Communication controller [0780]: Intel Corporation Meteor Lake-P CSME HECI #1 [8086:7e70] (rev 20)\n"},
                "lspci_verbose": {"stdout": ""},
                "intelmetool": {
                    "status": "collected",
                    "returncode": 0,
                    "effective_uid": 0,
                    "stdout": "Can't find ME PCI device\n",
                    "stderr": "",
                },
            }
            result = collector.collect_platform_security_processors(commands, mei_root=mei, pci_root=pci)
            tool = result["intel_mei"]["intelmetool"]
            self.assertEqual(tool["state"], "inconclusive")
            self.assertEqual(tool["reason"], "me-pci-device-not-recognized")
            self.assertFalse(tool["usable"])
            self.assertTrue(result["intel_mei"]["hardware_present"])
            self.assertEqual(result["intel_mei"]["state"], "hardware-present-state-unknown")

    def test_platform_security_processor_collects_amd_psp_sysfs(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mei = root / "mei"
            pci = root / "pci"
            mei.mkdir()
            dev = pci / "0000:04:00.2"
            dev.mkdir(parents=True)
            (dev / "vendor").write_text("0x1022\n", encoding="utf-8")
            (dev / "anti_rollback_status").write_text("1\n", encoding="utf-8")
            (dev / "boot_integrity").write_text("1\n", encoding="utf-8")
            result = collector.collect_platform_security_processors({"kernel_journal": {"stdout": ""}}, mei_root=mei, pci_root=pci)
            self.assertTrue(result["amd_psp"]["observable"])
            attrs = result["amd_psp"]["devices"][0]["attributes"]
            self.assertEqual(attrs["anti_rollback_status"], "1")
            self.assertEqual(attrs["boot_integrity"], "1")

    def test_empty_ec_driver_directory_does_not_claim_embedded_controller(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mei = root / "mei"
            pci = root / "pci"
            ec = root / "ec"
            mei.mkdir()
            pci.mkdir()
            ec.mkdir()
            (ec / "bind").write_text("", encoding="utf-8")
            (ec / "unbind").write_text("", encoding="utf-8")
            result = collector.collect_platform_security_processors(
                {"kernel_journal": {"stdout": ""}, "lspci": {"stdout": ""}, "lspci_verbose": {"stdout": ""}},
                mei_root=mei,
                pci_root=pci,
                acpi_ec_root=ec,
            )
            self.assertEqual(result["embedded_controllers"], [])

    def test_bound_ec_device_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mei = root / "mei"
            pci = root / "pci"
            ec = root / "ec"
            target = root / "PNP0C09:00"
            mei.mkdir()
            pci.mkdir()
            ec.mkdir()
            target.mkdir()
            (ec / "PNP0C09:00").symlink_to(target, target_is_directory=True)
            result = collector.collect_platform_security_processors(
                {"kernel_journal": {"stdout": ""}, "lspci": {"stdout": ""}, "lspci_verbose": {"stdout": ""}},
                mei_root=mei,
                pci_root=pci,
                acpi_ec_root=ec,
            )
            self.assertEqual(len(result["embedded_controllers"]), 1)
            self.assertIn("PNP0C09:00", " ".join(result["embedded_controllers"][0]["evidence"]))

    def test_oob_management_detects_local_bmc_and_amt_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ipmi = root / "ipmi"
            dev = root / "dev"
            (ipmi / "ipmi0").mkdir(parents=True)
            dev.mkdir()
            commands = {
                "dmidecode_ipmi": {"stdout": "IPMI Device Information"},
                "dmidecode_mchi": {"stdout": "Management Controller Host Interface"},
                "ipmitool_mc_info": {"stdout": ""},
                "fwupd_devices_json": {"stdout": json.dumps({"Devices": [{"Name": "AMT [provisioned]", "Summary": "Hardware and firmware technology for remote out-of-band management", "Version": "16.1"}]})},
            }
            result = collector.collect_out_of_band_management(commands, ipmi_root=ipmi, dev_root=dev)
            self.assertTrue(result["bmc"]["detected"])
            self.assertTrue(result["intel_amt"]["detected"])
            self.assertEqual(result["intel_amt"]["records"][0]["provisioning_state"], "provisioned")

    def test_memory_protection_separates_capability_from_active_state(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cpuinfo = root / "cpuinfo"
            modules = root / "modules"
            dev = root / "dev"
            modules.mkdir()
            dev.mkdir()
            cpuinfo.write_text("vendor_id : AuthenticAMD\nflags : fpu sme sev sev_es\n", encoding="utf-8")
            commands = {
                "kernel_journal": {"stdout": "AMD Memory Encryption Features active: SME"},
                "proc_cmdline": {"stdout": "quiet mem_encrypt=on"},
            }
            result = collector.collect_memory_protection(commands, cpuinfo_path=cpuinfo, module_root=modules, dev_root=dev)
            self.assertTrue(result["capabilities"]["amd_sme"])
            self.assertTrue(result["capabilities"]["amd_sev"])
            self.assertTrue(result["system_memory"]["amd_sme_kernel_active"])
            self.assertTrue(result["system_memory"]["mem_encrypt_requested"])


    def test_intel_tme_not_enabled_by_bios_is_not_reported_active(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cpuinfo = root / "cpuinfo"
            modules = root / "modules"
            dev = root / "dev"
            modules.mkdir()
            dev.mkdir()
            cpuinfo.write_text("vendor_id : GenuineIntel\nflags : fpu tme\n", encoding="utf-8")
            commands = {
                "kernel_journal": {"stdout": "kernel: x86/tme: not enabled by BIOS\n"},
                "proc_cmdline": {"stdout": "quiet"},
                "cpuid_amd_memory_encryption": {
                    "stdout": "CPU:\n  0x8000001f 0x00: eax=0x0001780f ebx=0x00000000 ecx=0x00000000 edx=0x00000000\n"
                },
                "msr_amd_syscfg": {"stdout": "ffffffff\n"},
                "msr_amd_sev_status": {"stdout": "1\n"},
            }
            result = collector.collect_memory_protection(commands, cpuinfo_path=cpuinfo, module_root=modules, dev_root=dev)
            self.assertTrue(result["capabilities"]["intel_tme"])
            self.assertFalse(result["system_memory"]["intel_tme"]["active"])
            self.assertEqual(result["system_memory"]["intel_tme"]["state"], "supported-not-enabled")
            self.assertFalse(result["system_memory"]["active"])
            self.assertFalse(result["capabilities"]["amd_sme"])
            self.assertFalse(result["capabilities"]["amd_sev"])
            self.assertFalse(result["amd_cpuid_8000001f"]["applicable"])

    def test_intel_tme_positive_kernel_state_is_active(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cpuinfo = root / "cpuinfo"
            modules = root / "modules"
            dev = root / "dev"
            modules.mkdir()
            dev.mkdir()
            cpuinfo.write_text("vendor_id : GenuineIntel\nflags : fpu tme\n", encoding="utf-8")
            commands = {
                "kernel_journal": {"stdout": "kernel: x86/tme: enabled by BIOS\n"},
                "proc_cmdline": {"stdout": "quiet"},
            }
            result = collector.collect_memory_protection(commands, cpuinfo_path=cpuinfo, module_root=modules, dev_root=dev)
            self.assertTrue(result["system_memory"]["intel_tme"]["active"])
            self.assertTrue(result["system_memory"]["active"])
            self.assertIn("Intel TME", result["system_memory"]["active_technologies"])

    def test_diversion_matching_is_exact_not_substring(self) -> None:
        commands = {
            "dpkg_verify": {"stdout": "??5??????   /usr/bin/foo\n", "status": "collected"},
            "dpkg_diversions": {"stdout": "local diversion of /usr/bin/foobar to /usr/bin/foobar.distrib\n"},
            "dpkg_statoverrides": {"stdout": ""},
        }
        result = collector.collect_dpkg_verify_analysis(commands)
        self.assertEqual(result["records"][0]["classification"], "security_relevant")

    def test_exact_diversion_is_ignored(self) -> None:
        commands = {
            "dpkg_verify": {"stdout": "??5??????   /usr/bin/foo\n", "status": "collected"},
            "dpkg_diversions": {"stdout": "local diversion of /usr/bin/foo to /usr/bin/foo.distrib\n"},
            "dpkg_statoverrides": {"stdout": ""},
        }
        result = collector.collect_dpkg_verify_analysis(commands)
        self.assertEqual(result["records"][0]["classification"], "ignored")
        self.assertIn("exact registered", result["records"][0]["reason"])

    @patch("collector.shutil.which", return_value="/usr/bin/example")
    @patch("collector.subprocess.Popen")
    def test_run_command_bounds_retained_output_but_hashes_full_stream(self, popen_mock, _which_mock) -> None:
        raw = b"x" * (collector.MAX_OUTPUT_BYTES + 4096)
        process = popen_mock.return_value
        process.stdout = io.BytesIO(raw)
        process.stderr = io.BytesIO(b"")
        process.wait.return_value = 0
        result = collector.run_command(collector.CommandSpec("bounded_test", ("example",)))
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["stdout"].encode()), collector.MAX_OUTPUT_BYTES)
        self.assertEqual(result["stdout_sha256"], hashlib.sha256(raw).hexdigest())

    def test_collector_service_sees_real_host_temporary_directories(self) -> None:
        unit = Path("systemd/firmware-audit-scan.service").read_text(encoding="utf-8")
        self.assertNotIn("PrivateTmp=yes", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK", unit)

    def test_collector_service_keeps_module_tree_readable_without_module_load_capability(self) -> None:
        unit = Path("systemd/firmware-audit-scan.service").read_text(encoding="utf-8")
        self.assertIn("ProtectKernelModules=no", unit)
        self.assertNotIn("ProtectKernelModules=yes", unit)
        self.assertIn("CapabilityBoundingSet=~CAP_SYS_MODULE", unit)
        self.assertIn("SystemCallFilter=~@module", unit)

    def test_collection_status_records_scan_and_area_timing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            status = collector.CollectionStatus(Path(td) / "status.json")
            status.start()
            status.area("System identity", "Reading identity", 5)
            status.area("Memory protection", "Reading memory protection", 10)
            timing = status.timing_snapshot()
        self.assertEqual(timing["started_at"], status.started_at)
        self.assertIn("completed_at", timing)
        self.assertGreaterEqual(timing["duration_ms"], 0)
        self.assertEqual([item["area"] for item in timing["areas"]], ["System identity", "Memory protection"] )
        for item in timing["areas"]:
            self.assertIn("started_at", item)
            self.assertIn("ended_at", item)
            self.assertGreaterEqual(item["duration_ms"], 0)
            self.assertGreaterEqual(item["segments"], 1)

    def test_generic_security_inventory_does_not_treat_plain_audio_coprocessor_as_security_hardware(self) -> None:
        commands = {
            "lspci": {"stdout": "08:00.5 Multimedia controller [0480]: Advanced Micro Devices, Inc. [AMD] ACP/ACP3X/ACP6x Audio Coprocessor [1022:15e2]\n"},
            "kernel_journal": {"stdout": ""},
            "fwupd_devices_json": {"stdout": "", "status": "not_available"},
        }
        result = collector.collect_platform_security_processors(commands)
        self.assertEqual(result["generic_security_management_hardware"], [])

    def test_collector_lock_stays_inside_writable_runtime_directory(self) -> None:
        source = Path(collector.__file__).read_text(encoding="utf-8")
        self.assertIn('/run/firmware-audit/scan.lock', source)
        self.assertNotIn('/run/lock/firmware-audit-scan.lock', source)

    def test_module_origin_is_product_neutral(self) -> None:
        self.assertEqual(collector._module_origin("/lib/modules/6.12.0/updates/dkms/example.ko"), "external-dkms")
        self.assertEqual(collector._module_origin("/usr/lib/modules/6.12.0/kernel/drivers/net/example.ko.xz"), "distribution-kernel-tree")
        self.assertEqual(collector._module_origin("/lib/modules/6.12.0/extra/example.ko"), "external-tree")

    def test_scanner_writes_immutable_archive_and_current_pointer_copy(self) -> None:
        source = Path(collector.__file__).read_text(encoding="utf-8")
        self.assertIn('report_dir / f"{report_id}.json"', source)
        self.assertIn('report_dir / "current.json"', source)
        self.assertNotIn('stale.unlink()', source)


    def test_tpm_eventlog_collection_uses_bytes_read_not_pseudo_file_stat_size(self) -> None:
        source = Path(collector.__file__).read_text(encoding="utf-8")
        block = source[source.index("def collect_tpm_eventlog"):source.index("def collect_crypt_mappings")]
        self.assertIn("total_size += len(chunk)", block)
        self.assertNotIn("path.stat().st_size", block)

    def test_tpm_eventlog_replay_matches_firmware_pcrs(self) -> None:
        commands = {
            "tpm_pcrs": {"stdout": "sha256 :\n  0 : 11aa\n  1 : 22bb\n"},
            "tpm_eventlog": {"stdout": "EventNum: 1\npcrs:\n  sha256:\n    0 : 0x11aa\n    1 : 0x22bb\n"},
        }
        result = collector.derive_tpm_eventlog_replay(commands)
        self.assertEqual(result["state"], "matched")
        self.assertEqual(result["algorithm"], "sha256")
        self.assertEqual(result["matched"], 2)

    def test_tpm_eventlog_replay_detects_mismatch(self) -> None:
        commands = {
            "tpm_pcrs": {"stdout": "sha256 :\n  0 : 11aa\n"},
            "tpm_eventlog": {"stdout": "pcrs:\n  sha256:\n    0 : 0xdead\n"},
        }
        result = collector.derive_tpm_eventlog_replay(commands)
        self.assertEqual(result["state"], "mismatch")
        self.assertEqual(result["mismatched"], 1)

    def test_tpm_eventlog_replay_marks_strong_truncation_pattern(self) -> None:
        commands = {
            "tpm_pcrs": {"stdout": "sha256 :\n  4 : 1111\n  5 : 2222\n  8 : 3333\n  9 : 4444\n"},
            "tpm_eventlog": {
                "stdout": (
                    "- EventNum: 126\n  PCRIndex: 8\n  EventType: EV_IPL\n  Event:\n    String: \"grub_cmd: insmod gzio\\0\"\n"
                    "- EventNum: 127\n  PCRIndex: 8\n  EventType: EV_IPL\n  Event:\n    String: \"grub_cmd: insmod part_gpt\\0\"\n"
                    "pcrs:\n  sha256:\n    4 : 0xaaaa\n    5 : 0xbbbb\n    8 : 0xcccc\n    9 : 0xdddd\n"
                )
            },
        }
        result = collector.derive_tpm_eventlog_replay(commands, {"size": 65524})
        self.assertEqual(result["state"], "mismatch")
        self.assertEqual(result["all_mismatched"], 4)
        diag = result["event_log_diagnostics"]
        self.assertTrue(diag["near_capacity_boundary"])
        self.assertTrue(diag["ends_during_bootloader_activity"])
        self.assertTrue(diag["likely_truncated"])
        self.assertEqual(diag["capacity_boundary"], 65536)
        self.assertEqual(diag["bytes_below_capacity_boundary"], 12)
        self.assertEqual(diag["last_event"]["event_num"], 127)
        self.assertEqual(diag["mismatched_pcrs"], [4, 5, 8, 9])

    def test_near_capacity_alone_does_not_claim_truncation(self) -> None:
        commands = {
            "tpm_pcrs": {"stdout": "sha256 :\n  4 : 1111\n"},
            "tpm_eventlog": {
                "stdout": (
                    "- EventNum: 42\n  PCRIndex: 4\n  EventType: EV_EFI_BOOT_SERVICES_APPLICATION\n"
                    "pcrs:\n  sha256:\n    4 : 0xaaaa\n"
                )
            },
        }
        result = collector.derive_tpm_eventlog_replay(commands, {"size": 65524})
        self.assertFalse(result["event_log_diagnostics"]["likely_truncated"])

    def test_collector_is_network_offline_by_systemd_policy(self) -> None:
        unit = Path("systemd/firmware-audit-scan.service").read_text(encoding="utf-8")
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_NETLINK", unit)
        self.assertNotIn("AF_INET ", unit)
        source = Path(collector.__file__).read_text(encoding="utf-8")
        self.assertNotIn('"refresh"', source)
        self.assertNotIn('fwupdmgr", "update"', source)


if __name__ == "__main__":
    unittest.main()


def test_deep_amd_memory_detection_matches_tsme_reference_pattern():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        cpuinfo = root / "cpuinfo"
        modules = root / "modules"
        dev = root / "dev"
        modules.mkdir()
        dev.mkdir()
        (modules / "kvm_amd" / "parameters").mkdir(parents=True)
        (modules / "kvm_amd" / "parameters" / "sev").write_text("N\n", encoding="utf-8")
        (modules / "kvm_amd" / "parameters" / "sev_es").write_text("N\n", encoding="utf-8")
        cpuinfo.write_text("vendor_id : AuthenticAMD\nflags : fpu\n", encoding="utf-8")
        commands = {
            "kernel_journal": {"stdout": ""},
            "proc_cmdline": {"stdout": "quiet"},
            "cpuid_amd_memory_encryption": {
                "stdout": "CPU:\n   0x8000001f 0x00: eax=0x0001780f ebx=0x00000000 ecx=0x00000000 edx=0x00000000\n"
            },
            "msr_amd_syscfg": {"stdout": "740000\n"},
            "msr_amd_sev_status": {"stdout": "0\n"},
        }
        platform = {
            "amd_psp": {
                "observable": True,
                "devices": [{"bdf": "0000:08:00.2", "attributes": {"tsme_status": "1"}}],
            }
        }
        fwattrs = [
            {"provider": "thinklmi", "path": "thinklmi/attributes/TSME/current_value", "value": "Enable"},
            {"provider": "thinklmi", "path": "thinklmi/attributes/TSME/possible_values", "value": "Disable;Enable"},
        ]
        result = collector.collect_memory_protection(
            commands,
            platform_security=platform,
            firmware_attributes=fwattrs,
            cpuinfo_path=cpuinfo,
            module_root=modules,
            dev_root=dev,
        )
        assert result["capabilities"]["amd_sme"] is True
        assert result["capabilities"]["amd_sev"] is True
        assert result["capabilities"]["amd_sev_es"] is True
        assert result["capabilities"]["amd_sev_snp"] is False
        assert result["system_memory"]["amd_sme"]["memory_encryption_enable_bit23"] is False
        assert result["system_memory"]["amd_sme"]["state"] == "supported-os-not-active-tsme-active"
        assert result["system_memory"]["amd_tsme"]["state"] == "active-transparent"
        assert result["system_memory"]["active"] is True
        assert result["confidential_vm"]["amd_sev"]["state"] == "supported-host-disabled"
        assert "c_bit_warning" in result["amd_cpuid_8000001f"]


def test_nic_integrated_ipmi_and_dash_disabled_are_not_misreported_as_active_bmc():
    lspci = """02:00.0 Ethernet controller [0200]: Realtek Semiconductor Co., Ltd. RTL8111/8168 [10ec:8168]\n\tKernel driver in use: r8169\n02:00.1 Serial controller [0700]: Realtek Semiconductor Co., Ltd. RTL8111xP UART #1 [10ec:816a]\n02:00.2 Serial controller [0700]: Realtek Semiconductor Co., Ltd. RTL8111xP UART #2 [10ec:816b]\n02:00.3 IPMI Interface [0c07]: Realtek Semiconductor Co., Ltd. RTL8111xP IPMI interface [10ec:816c]\n02:00.4 USB controller [0c03]: Realtek Semiconductor Co., Ltd. RTL811x EHCI host controller [10ec:816d]\n"""
    commands = {
        "lspci": {"stdout": lspci},
        "kernel_journal": {"stdout": "ipmi_si: Unable to find any System Interface(s)\nr8169 0000:02:00.0 eth0: DASH disabled\n"},
        "dmidecode_ipmi": {"stdout": ""},
        "dmidecode_mchi": {"stdout": ""},
        "ipmitool_mc_info": {"stdout": ""},
        "fwupd_devices_json": {"stdout": ""},
    }
    fwattrs = [
        {"provider": "thinklmi", "path": "thinklmi/attributes/DashEnabled/current_value", "value": "Disable"},
        {"provider": "thinklmi", "path": "thinklmi/attributes/WirelessDashEnabled/current_value", "value": "Disable"},
    ]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        ipmi = root / "ipmi"
        dev = root / "dev"
        ipmi.mkdir()
        dev.mkdir()
        result = collector.collect_out_of_band_management(
            commands, firmware_attributes=fwattrs, ipmi_root=ipmi, dev_root=dev
        )
    assert result["bmc"]["detected"] is False
    assert result["nic_oob"]["detected"] is True
    assert result["nic_oob"]["state"] == "nic-oob-function-dormant"
    assert result["nic_oob"]["functions"][0]["network_siblings"]
    assert result["dmtf_dash"]["state"] == "disabled"


def test_firmware_endpoint_persistence_setting_is_inventory_not_agent_claim():
    commands = {
        "lspci": {"stdout": ""},
        "kernel_journal": {"stdout": ""},
        "dmidecode_ipmi": {"stdout": ""},
        "dmidecode_mchi": {"stdout": ""},
        "ipmitool_mc_info": {"stdout": ""},
        "fwupd_devices_json": {"stdout": ""},
    }
    fwattrs = [
        {"provider": "thinklmi", "path": "thinklmi/attributes/AbsolutePersistenceModuleActivation/current_value", "value": "Enable"},
        {"provider": "thinklmi", "path": "thinklmi/attributes/AbsolutePersistenceModuleActivation/possible_values", "value": "Disable;Enable;PermanentlyDisable"},
    ]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "ipmi").mkdir()
        (root / "dev").mkdir()
        result = collector.collect_out_of_band_management(
            commands, firmware_attributes=fwattrs, ipmi_root=root / "ipmi", dev_root=root / "dev"
        )
    item = result["firmware_persistence"][0]
    assert item["state"] == "firmware-enabled-agent-state-unknown"
    assert "agent" in item["state"]


def test_platform_processor_detects_amd_gpu_psp_and_embedded_controller():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        mei = root / "mei"
        pci = root / "pci"
        ec = root / "ec"
        mei.mkdir()
        pci.mkdir()
        ec.mkdir()
        commands = {
            "kernel_journal": {
                "stdout": "amdgpu 0000:08:00.0: amdgpu: Will use PSP to load VCN firmware\nACPI: EC: EC started\n"
            },
            "dmidecode_full": {"stdout": "ThinkPad Embedded Controller Program\n"},
            "lspci": {"stdout": ""},
            "lspci_verbose": {"stdout": ""},
            "fwupd_devices_json": {"stdout": ""},
        }
        result = collector.collect_platform_security_processors(
            commands, mei_root=mei, pci_root=pci, acpi_ec_root=ec
        )
    assert result["gpu_security_processors"][0]["technology"] == "AMD GPU PSP"
    assert result["embedded_controllers"][0]["technology"] == "System embedded controller"


def test_collector_does_not_chmod_existing_report_directory():
    from pathlib import Path
    source = Path(__file__).resolve().parents[1].joinpath("collector.py").read_text()
    collect_body = source[source.index("def collect(report_dir: Path,"):source.index("def main() -> int:")]
    assert "os.chmod(report_dir" not in collect_body
    assert "report_dir.mkdir(mode=0o2750" in collect_body
