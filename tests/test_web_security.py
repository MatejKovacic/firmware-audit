from __future__ import annotations

import ast
import unittest
from pathlib import Path

import run_web


class WebSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source = Path("app.py").read_text(encoding="utf-8")
        self.tree = ast.parse(self.source)

    def test_incomplete_authentication_configuration_is_fail_closed(self) -> None:
        self.assertIn("WEB_USERNAME and WEB_PASSWORD_HASH must either both be set or both be empty", self.source)
        self.assertIn("validate_auth_config()", self.source)

    def test_sensitive_response_hardening_is_configured(self) -> None:
        for header in (
            "Cache-Control", "X-Content-Type-Options", "X-Frame-Options",
            "Referrer-Policy", "Permissions-Policy", "Content-Security-Policy",
        ):
            self.assertIn(header, self.source)
        self.assertIn('response.headers["Cache-Control"] = "no-store"', self.source)

    def test_web_scan_route_and_privileged_trigger_are_removed(self) -> None:
        self.assertNotIn('@app.post("/scan")', self.source)
        self.assertNotIn("firmware-audit-request-scan", self.source)
        self.assertFalse(Path("systemd/firmware-audit-collect.path").exists())

    def test_viewer_does_not_import_scanner_assessment_logic(self) -> None:
        self.assertNotIn("from assessment import", self.source)
        self.assertNotIn("from sections import", self.source)
        template = Path("templates/_assessment.html").read_text(encoding="utf-8")
        self.assertIn("report.results", template)
        self.assertNotIn("report.assessment", template)

    def test_non_loopback_without_auth_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            run_web.validate_listener_security("0.0.0.0", "", "", False, False)
        run_web.validate_listener_security("127.0.0.1", "", "", False, False)
        run_web.validate_listener_security("0.0.0.0", "admin", "hash", True, False)
        run_web.validate_listener_security("0.0.0.0", "", "", True, True)

    def test_web_unit_has_no_write_access_to_runtime_or_reports(self) -> None:
        unit = Path("systemd/firmware-audit-web.service").read_text(encoding="utf-8")
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ReadOnlyPaths=/var/lib/firmware-audit/reports /run/firmware-audit", unit)
        self.assertNotIn("ReadWritePaths=", unit)
        self.assertIn("CapabilityBoundingSet=", unit)
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", unit)
        self.assertIn("ProtectProc=invisible", unit)
        self.assertIn("ProcSubset=pid", unit)
        self.assertIn("PrivateIPC=yes", unit)
        self.assertIn("SystemCallFilter=@system-service", unit)
        self.assertIn("SystemCallErrorNumber=EPERM", unit)

    def test_privileged_scan_units_keep_hardware_access_but_deny_mutating_kernel_classes(self) -> None:
        for name in (
            "firmware-audit-scan.service",
            "firmware-audit-scan@.service",
            "firmware-audit-daily.service",
            "firmware-audit-monthly.service",
        ):
            unit = Path("systemd", name).read_text(encoding="utf-8")
            self.assertNotIn("PrivateTmp=yes", unit)
            self.assertIn("PrivateIPC=yes", unit)
            self.assertIn("ProtectKernelLogs=yes", unit)
            self.assertIn("RestrictNamespaces=yes", unit)
            self.assertIn("SystemCallArchitectures=native", unit)
            self.assertIn("SystemCallFilter=~@module @mount @reboot", unit)
            self.assertIn("ProtectKernelModules=no", unit)
            self.assertNotIn("PrivateDevices=yes", unit)

    def test_installer_validates_preserved_listener_before_restart(self) -> None:
        installer = Path("install.sh").read_text(encoding="utf-8")
        validate_pos = installer.index("validate_or_migrate_web_config\n")
        restart_pos = installer.index("systemctl restart firmware-audit-web.service")
        self.assertLess(validate_pos, restart_pos)
        self.assertIn("nginx_proxies_to_local_dashboard", installer)
        self.assertIn("changed BIND_HOST from $bind_host to 127.0.0.1", installer)
        self.assertIn("The web service was not restarted.", installer)
        self.assertIn("ALLOW_UNAUTHENTICATED_REMOTE", installer)
        self.assertIn("BIND_PORT must be between 1 and 65535", installer)


    def test_dashboard_shows_scan_start_and_total_duration_only(self) -> None:
        index = Path("templates/index.html").read_text(encoding="utf-8")
        assessment = Path("templates/_assessment.html").read_text(encoding="utf-8")
        self.assertIn("Scan started", index)
        self.assertIn("Duration", index)
        self.assertIn("Scan started", assessment)
        self.assertIn("Duration", assessment)
        self.assertNotIn("area_segments", index)
        self.assertNotIn("area_segments", assessment)

    def test_duration_formatter_is_available_to_templates(self) -> None:
        source = Path("app.py").read_text(encoding="utf-8")
        self.assertIn("def format_duration_ms", source)
        self.assertIn('"format_duration_ms": format_duration_ms', source)

    def test_web_service_rate_limits_configuration_restart_loops(self) -> None:
        unit = Path("systemd/firmware-audit-web.service").read_text(encoding="utf-8")
        self.assertIn("StartLimitIntervalSec=60", unit)
        self.assertIn("StartLimitBurst=5", unit)

    def test_manual_uploader_is_separate_and_strongly_sandboxed(self) -> None:
        source = Path("app.py").read_text(encoding="utf-8")
        uploader = Path("uploader.py").read_text(encoding="utf-8")
        unit = Path("systemd/firmware-audit-uploader.service").read_text(encoding="utf-8")
        self.assertIn('@app.post("/upload")', source)
        self.assertIn("UPLOAD_SOCKET", source)
        self.assertNotIn("UPLOAD_KEY_FILE", source)
        self.assertNotIn("Authorization", uploader)
        self.assertIn("https", uploader)
        for directive in (
            "User=firmware-audit-uploader", "NoNewPrivileges=yes", "PrivateDevices=yes",
            "PrivateTmp=yes", "PrivateIPC=yes", "ProtectSystem=strict",
            "ProtectProc=invisible", "ProcSubset=pid", "CapabilityBoundingSet=",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            "SystemCallFilter=@system-service",
        ):
            self.assertIn(directive, unit)

    def test_upload_is_manual_and_enabled_by_default(self) -> None:
        env = Path("firmware-audit.env.example").read_text(encoding="utf-8")
        installer = Path("install.sh").read_text(encoding="utf-8")
        self.assertIn("UPLOAD_ENABLED=true", env)
        self.assertIn("No report is ever uploaded automatically", env)
        self.assertIn("replace_env_value UPLOAD_ENABLED true", installer)
        self.assertNotIn("secrets.token_urlsafe", installer)
        self.assertIn("remove_env_key UPLOAD_KEY_FILE", installer)
        self.assertIn('rm -f /etc/firmware-audit/upload.key', installer)
        self.assertIn("firmware-audit-uploader.service", installer)
        self.assertIn("csrf.key", installer)

    def test_installer_only_installs_missing_packages_and_has_account_tool_fallbacks(self) -> None:
        installer = Path("install.sh").read_text(encoding="utf-8")
        self.assertIn("package_installed()", installer)
        self.assertIn("--no-upgrade", installer)
        self.assertIn("skipping required-package installation", installer)
        self.assertIn("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", installer)
        self.assertIn("find_admin_tool()", installer)
        self.assertIn("systemd-sysusers", installer)
        self.assertIn("find_admin_tool addgroup", installer)
        self.assertIn("find_admin_tool groupadd", installer)
        self.assertIn("find_admin_tool adduser", installer)
        self.assertIn("find_admin_tool useradd", installer)
        self.assertNotIn("apt-get update\napt-get install -y --no-install-recommends", installer)

    def test_installer_discloses_missing_packages_and_requires_confirmation(self) -> None:
        installer = Path("install.sh").read_text(encoding="utf-8")
        self.assertIn("package_purpose()", installer)
        self.assertIn("The installer may install the following packages", installer)
        self.assertIn("APT will display the complete package", installer)
        self.assertIn("Continue and let APT resolve these packages? [y/N]", installer)
        self.assertIn("Confirm the APT prompt", installer)
        self.assertNotIn("apt-get install -y", installer)
        self.assertNotIn("apt-get install --assume-yes", installer)

    def test_uninstaller_preserves_by_default_and_supports_purge(self) -> None:
        uninstaller = Path("uninstall.sh").read_text(encoding="utf-8")
        installer = Path("install.sh").read_text(encoding="utf-8")
        readme = Path("README.md").read_text(encoding="utf-8")
        self.assertIn("--purge|/purge|-p", uninstaller)
        self.assertIn('if [ "$PURGE" = true ]', uninstaller)
        self.assertIn("rm -rf /var/lib/firmware-audit", uninstaller)
        self.assertIn("rm -f /etc/firmware-audit.env", uninstaller)
        self.assertIn("Distribution packages are NOT removed", uninstaller)
        self.assertNotIn("apt-get remove", uninstaller)
        self.assertNotIn("apt purge", uninstaller)
        self.assertIn('$SOURCE_DIR/uninstall.sh', installer)
        self.assertIn("sudo /opt/firmware-audit/uninstall.sh --purge", readme)
        self.assertIn("Neither normal uninstall nor purge removes Debian/Ubuntu packages", readme)

    def test_readme_lists_installer_managed_packages(self) -> None:
        readme = Path("README.md").read_text(encoding="utf-8")
        for package in (
            "python3-flask", "gunicorn", "python3-gunicorn", "fwupd", "mokutil",
            "dmidecode", "pciutils", "usbutils", "efibootmgr", "tpm2-tools",
            "cryptsetup-bin", "kmod", "util-linux", "systemd", "apparmor",
            "cpuid", "msr-tools", "ipmitool", "coreboot-utils",
        ):
            self.assertIn(f"`{package}`", readme)
        self.assertIn("user must explicitly confirm the APT prompt", readme)

    def test_installer_removes_obsolete_upload_key_and_needs_no_provisioning(self) -> None:
        installer = Path("install.sh").read_text(encoding="utf-8")
        env = Path("firmware-audit.env.example").read_text(encoding="utf-8")
        uploader = Path("uploader.py").read_text(encoding="utf-8")
        self.assertIn("remove_env_key UPLOAD_KEY_FILE", installer)
        self.assertIn('rm -f /etc/firmware-audit/upload.key', installer)
        self.assertNotIn("FIRMWARE_AUDIT_UPLOAD_KEY_FILE", installer)
        self.assertNotIn("UPLOAD_KEY_FILE=", env)
        self.assertNotIn("Authorization", uploader)


if __name__ == "__main__":
    unittest.main()
