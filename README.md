# Firmware Audit

Firmware Audit is an offline-capable firmware and host-security scanner plus a separate local web viewer for Debian and Ubuntu systems. The scanner gathers local evidence, applies deterministic rules, and writes a self-contained JSON report. The viewer renders that report; it does not execute scans and does not re-assess evidence. An optional manual uploader can send the current JSON report to an administrator-configured HTTPS receiver, but no upload occurs automatically.

## Architecture

```text
privileged scanner  ->  firmware-audit-report JSON  ->  local viewer
                         |                         ->  optional manual uploader -> HTTPS receiver
                         +-> immutable scan history
```

The scanner owns all platform-specific knowledge: firmware, TPM, package verification, platform security processors, memory protection, and other evidence interpretation. The viewer knows only generic report concepts such as area, status, finding, note, timing, system identity, and raw evidence.
 Architecture-specific capability encodings are vendor-gated: for example, AMD memory-encryption CPUID/MSR semantics are only collected and interpreted on AMD processors, while Intel TME support is kept separate from evidence that TME is actually active. For Intel ME/CSME, the scanner also separates CSME/HECI hardware presence from Linux MEI host-interface availability and from a decoded engine state; a failed or hidden host interface is not treated as proof that ME/CSME is disabled.

A scan does not require Internet access. It uses local kernel/firmware interfaces, installed tools, local package metadata, and locally cached fwupd metadata. It does not refresh firmware metadata, search manufacturer sites, call vendor APIs, query online CVE/reputation services, or use AI services.

## Stable report contract

Every report has these top-level objects:

```text
format       report-format name and version
report       scan ID, scope, selected areas, profile, scanner version, timing
system       stable machine ID, hostname, OS, running/installed kernels, hardware context
results      final interpreted overall result and per-area presentation data
evidence     raw command records and scanner artifacts
integrity    SHA-256 consistency digest of the JSON report
```

`results` is the stable viewer-facing layer. `evidence` is deliberately more implementation-specific and may evolve as scanner techniques improve. See `REPORT-FORMAT.md` and `report-format-v1.schema.json` for the contract intended for independent viewers.

The machine ID is a namespaced SHA-256 derived from a stable local hardware UUID when available, otherwise the local machine ID, without exposing the source identifier itself. Reports also record OS release information, the running kernel, installed kernel releases, machine/board identity, BIOS/UEFI identity, CPU model, and architecture so future comparison can distinguish expected upgrades from unexplained changes.

## Scan areas

List available areas:

```sh
firmware-audit-scan --list-areas
```

Current areas are:

```text
identity
firmware-baseline
firmware-protection
platform-security-processor
out-of-band-management
secure-boot
tpm-measured-boot
kernel-runtime
host-integrity
memory-protection
storage-memory
device-firmware
updates
```

A full scan:

```sh
sudo firmware-audit-scan --profile full
```

One area:

```sh
sudo firmware-audit-scan --area memory-protection
```

Several areas:

```sh
sudo firmware-audit-scan \
  --area firmware-protection \
  --area platform-security-processor \
  --area tpm-measured-boot \
  --area memory-protection
```

or:

```sh
sudo firmware-audit-scan --areas firmware-protection,tpm-measured-boot,memory-protection
```

Shared evidence dependencies are resolved automatically and a command is not intentionally rerun merely because more than one selected area needs it. Supporting evidence may therefore appear in `evidence` even when its own semantic area was not requested. Only explicitly requested areas appear in `results.areas` for a partial scan.

## Profiles

```sh
firmware-audit-scan --list-profiles
```

Three profiles are included:

- `full` — every area.
- `daily` — all normal areas except the expensive installed-files/persistence area.
- `integrity` — only installed-files/persistence.

The profiles are convenience selections, not different assessment standards. A partial report is explicitly marked `report.scope = "partial"`; unrequested areas are not shown as Unknown or Not applicable.

## Scheduling and locking

The scanner contains no scheduler. Use systemd timers, cron, or another local scheduler. A non-blocking exclusive lock at `/run/firmware-audit/scan.lock` prevents overlapping scans, including scans started by different scheduling mechanisms.

The package includes disabled example timers:

```sh
sudo systemctl enable --now firmware-audit-daily.timer
sudo systemctl enable --now firmware-audit-monthly.timer
```

The daily timer runs the `daily` profile. The monthly timer runs a complete `full` scan. Their schedules can be overridden with normal systemd drop-ins.

Run a specific area through systemd:

```sh
sudo systemctl start firmware-audit-scan@memory-protection.service
```

Run a manual full scan:

```sh
sudo systemctl start firmware-audit-scan.service
```

## Virtual machines

Firmware Audit detects common virtual-machine environments and keeps the guest/host trust boundaries separate. In a normal VM guest, physical host firmware, firmware write protection, physical out-of-band management, Intel ME/CSME, AMD PSP, and host CPU microcode are outside the guest's direct view. Those physical-host controls are therefore **Not applicable** from the guest. A legacy/SeaBIOS-style guest also reports UEFI Secure Boot as **Not applicable**; a guest that actually boots with virtual UEFI can still assess the guest's virtual Secure Boot state. Guest-visible kernel, package, storage, confidential-memory features, and virtual-device evidence are assessed normally, with memory wording explicitly avoiding conclusions about physical-host RAM protection.

Low-level Intel `intelmetool` probing is skipped inside detected VMs. If the guest kernel reports CPU vulnerability exposure, the recommendation points to the physical hypervisor's microcode/kernel mitigations and the VM CPU model in addition to the guest kernel.

## systemd sandboxing

The scanner, viewer, and optional uploader have intentionally different sandbox profiles. The web viewer has no hardware-collection role and is strongly isolated: it runs unprivileged with private temporary files/devices/IPC, a read-only filesystem view, no Linux capabilities, restricted namespaces and address families, hidden process metadata, a process-only `/proc` view, and an allow-listed system-service syscall profile.

The optional uploader is a separate unprivileged service. The viewer can only contact it over a Unix socket and cannot make the remote HTTPS connection itself. The uploader has no Linux capabilities, private devices/tmp/IPC, a read-only system view, restricted process/kernel visibility, and only the address families required for its Unix socket plus outbound HTTPS. No per-machine upload credential is used.

The collector runs as root because some read-only firmware and hardware interfaces require privileged access. It is still constrained with a read-only system filesystem (except report/runtime paths), read-only home directories, no network IP sockets, protected kernel tunables/control groups/logs, isolated IPC, restricted namespaces, native-architecture syscalls only, no module-loading capability, and denied module, mount, and reboot syscall classes.

Some apparently stronger directives are intentionally **not** used for the collector because they would create blind spots rather than meaningful protection. In particular, `PrivateDevices=yes` would hide TPM/MSR/IPMI and other device evidence; `ProcSubset=pid` would hide kernel state such as `/proc/cmdline`, kernel taint and swap information; and `PrivateTmp=yes` would hide the host `/tmp`, `/var/tmp`, and `/dev/shm` locations that the integrity/persistence inventory deliberately checks. The web viewer does not need those evidence sources, so it can use the stricter forms safely.

## Report history

Each successful scan writes an immutable timestamped report and atomically updates `current.json`:

```text
/var/lib/firmware-audit/reports/20260808T211606.335848Z-hostname.json
/var/lib/firmware-audit/reports/current.json
```

The scanner does **not** compare reports while scanning. This keeps scans deterministic and independent. The JSON format contains stable machine identity, OS/kernel context, selected-area scope, versions, hashes and evidence identifiers so a later comparator can classify changes semantically rather than treating every changed hash as suspicious.

No automatic history deletion is performed; choose retention according to local storage and comparison requirements.

## Viewer

The Flask/Gunicorn viewer reads `/var/lib/firmware-audit/reports/current.json` and verifies the report's consistency digest. It does not import `assessment.py`, does not execute scanner commands, and cannot trigger a privileged scan.

When manual upload is enabled, the dashboard shows **Upload report**. Clicking it is the only action that initiates an upload. The viewer validates a CSRF token and the current report digest, then asks the separate `firmware-audit-uploader` service over a local Unix socket to re-verify and submit the exact JSON bytes. The browser does not contact the public receiver directly.

The dashboard intentionally shows only the scan start time and total duration. Detailed per-area timing remains in the JSON under `report.timing`.

## Required tools and packages

Firmware Audit uses standard Debian/Ubuntu packages rather than private copies of low-level hardware utilities. The installer checks each package first and only asks APT to install packages that are currently missing.

The installer-managed packages are:

| Package | Used for | Requirement |
|---|---|---|
| `python3-flask` | Flask runtime for the local dashboard | Required |
| `gunicorn` | Gunicorn executable for the local dashboard | Required |
| `python3-gunicorn` | Gunicorn Python runtime | Required |
| `fwupd` | `fwupdmgr` host-security, firmware-device and cached-update evidence | Required |
| `mokutil` | UEFI Secure Boot, PK/KEK/db/dbx and MOK evidence | Required |
| `dmidecode` | SMBIOS/DMI firmware, system, board and management-controller evidence | Required |
| `pciutils` | `lspci` PCI inventory, drivers and management/security hardware evidence | Required |
| `usbutils` | `lsusb` USB inventory and topology | Required |
| `efibootmgr` | UEFI boot-entry evidence | Required |
| `tpm2-tools` | TPM properties, algorithms, PCRs and event-log parsing | Required |
| `cryptsetup-bin` | encrypted-device mapping/status evidence | Required |
| `kmod` | kernel-module inventory and metadata (`lsmod`, `modinfo`) | Required |
| `util-linux` | block-device, mount and swap inventory (`lsblk`, `findmnt`, `swapon`) | Required |
| `systemd` | systemd services/timers, journal evidence and virtualization detection | Required |
| `apparmor` | `aa-status` AppArmor state evidence | Required |
| `cpuid` | AMD memory-encryption CPUID evidence | Required |
| `msr-tools` | AMD memory-encryption MSR evidence (`rdmsr`) | Required |
| `ipmitool` | local BMC/IPMI evidence | Required |
| `coreboot-utils` | optional `intelmetool` Intel ME/CSME evidence | Optional |

Most base Debian/Ubuntu installations already contain several of these packages, especially `systemd`, `util-linux` and `kmod`. Firmware Audit does not reinstall packages that are already present.

When packages are missing, `install.sh` first prints the missing direct packages and their purpose. It then refreshes APT metadata. APT itself displays the **complete transaction, including additional package dependencies, before installation**, and the user must explicitly confirm the APT prompt. The installer does not use `-y`/`--assume-yes` for package installation. If the required-package transaction is declined, installation stops. `coreboot-utils` is optional and can be declined without preventing Firmware Audit installation.

The installer does not run `apt upgrade`, `apt full-upgrade` or `dist-upgrade`. It uses `--no-upgrade` for packages it requests. APT may still show dependency changes required to install a missing package; those changes are visible in the normal APT confirmation screen before anything is installed.

## Installation

Download `firmware-audit-v0.12.8.zip` and its checksum file into the same directory. Verification is recommended:

```sh
sha256sum -c firmware-audit-v0.12.8.zip.sha256
```

Extract and install:

```sh
unzip firmware-audit-v0.12.8.zip
cd firmware-audit
sudo ./install.sh
```

If all required packages are already installed, the installer performs no APT package installation. If packages are missing, read the list printed by Firmware Audit and then read APT's complete package transaction. Confirm the APT prompt only if you accept those package changes.

The installer then:

- creates the dedicated `firmware-audit` and `firmware-audit-uploader` service accounts if needed;
- installs the application under `/opt/firmware-audit`;
- installs the scanner command as `/usr/local/bin/firmware-audit-scan`;
- installs and enables the local viewer and manual uploader services;
- installs, but does **not** enable, the optional daily/monthly scan timers;
- starts an initial full scan in the background;
- enables the **manual** Upload report button by default. No report is uploaded until the user clicks it.

The local dashboard listens on `127.0.0.1:8088` by default. Open:

```text
http://127.0.0.1:8088/
```

Configuration is stored in:

```text
/etc/firmware-audit.env
```

Check the web service and initial scan with:

```sh
sudo systemctl status firmware-audit-web.service --no-pager
sudo systemctl status firmware-audit-scan.service --no-pager
sudo journalctl -u firmware-audit-scan.service -f
```

Reports are stored in:

```text
/var/lib/firmware-audit/reports/
```

The optional Intel ME/CSME probe uses `intelmetool` from `coreboot-utils`. If that package is declined or unavailable, the scan still runs; Intel ME/CSME state may correctly remain **Unknown** when Linux MEI evidence is insufficient.

If `intelmetool` is installed but cannot obtain low-level x86 I/O access (for example `iopl: Operation not permitted`), the scan records the probe as **blocked** and preserves kernel-lockdown and `CAP_SYS_RAWIO` context when available. This is treated as a collection limitation, never as proof that Intel ME/CSME is absent or disabled. Output such as `Can't find ME PCI device` is likewise recorded as **inconclusive**, because newer or unsupported platforms may still expose a CSME/HECI PCI function through normal PCI enumeration.

### Optional recurring scans

The timers are installed but not enabled automatically. Enable them only if wanted:

```sh
sudo systemctl enable --now firmware-audit-daily.timer
sudo systemctl enable --now firmware-audit-monthly.timer
```

### One-click manual report upload

Manual remote upload is **enabled by default**, but Firmware Audit never uploads a report automatically. The default receiver is:

```text
https://audit.telefoncek.si/api/v1/reports
```

Transmission requires an explicit click on **Upload report** in the local dashboard. No token, password, API key or per-machine upload credential is required.

The separate uploader requires an `https://` URL, validates the normal system CA trust store, refuses embedded URL credentials, does not follow redirects, re-verifies the report's canonical SHA-256 digest, and sends the original report bytes unchanged. The viewer itself remains isolated from outbound Internet access.

The public receiver is append-only: it validates the Firmware Audit format and digest before accepting a report and exposes no report-list/download/delete API.

## Upgrading

Extract the new release into a fresh directory and run its installer again:

```sh
unzip firmware-audit-v0.12.8.zip
cd firmware-audit
sudo ./install.sh
```

Existing `/etc/firmware-audit.env`, report history and CSRF state are preserved unless a release-specific migration is documented. The installer again shows any missing packages before APT is allowed to install them.

## Uninstallation

Firmware Audit includes `uninstall.sh`, and the installer also copies it to `/opt/firmware-audit/uninstall.sh`.

### Normal uninstall: preserve reports and configuration

Run:

```sh
sudo /opt/firmware-audit/uninstall.sh
```

Review the removal summary and confirm when prompted. This removes the scanner/viewer/uploader application, systemd units/timers, runtime directories and `/usr/local/bin/firmware-audit-scan`, but preserves:

```text
/var/lib/firmware-audit/
/etc/firmware-audit.env
/etc/firmware-audit/
```

The service accounts are also preserved so the retained files remain ready for a later reinstall.

### Purge: remove reports and configuration too

To permanently remove Firmware Audit **including all saved reports and configuration**, run this directly instead of the normal uninstall:

```sh
sudo /opt/firmware-audit/uninstall.sh --purge
```

`/purge` is accepted as an alias:

```sh
sudo /opt/firmware-audit/uninstall.sh /purge
```

Purge mode also attempts to remove the dedicated Firmware Audit service users/groups.

**Neither normal uninstall nor purge removes Debian/Ubuntu packages** such as `fwupd`, `tpm2-tools`, `ipmitool` or `coreboot-utils`, even if Firmware Audit originally caused APT to install them. After installation those packages may be used by the administrator or other software, so automatically removing them would be unsafe. They can be reviewed and removed separately with normal package-management tools if desired.

If Firmware Audit was already normally uninstalled and `/opt/firmware-audit/uninstall.sh` no longer exists, extract the same/newer Firmware Audit archive and run its `uninstall.sh --purge` to delete the preserved data.

## Important interpretation rules

- **Good** means no actionable problem was identified in the selected areas that could be assessed; the UI phrases this as **No issues found in assessed areas**.
- **Attention** means a meaningful weakness or review condition exists.
- **Investigate** is reserved for stronger unexplained integrity/compromise-like inconsistencies.
- **Unknown** is used as the overall security result only when there is not enough assessed evidence for a meaningful conclusion at all. Individual areas can still be Unknown.
- **Not applicable** means the control does not apply to the detected platform.
- **Assessment coverage** is reported separately as **Complete**, **Partial**, or **Insufficient**. A Good or Attention result can therefore coexist with Partial coverage.
- Security notes do not raise the overall status by themselves.

Normal operating-system and firmware updates are not inherently suspicious. Future comparison should correlate changed hashes with OS, kernel, package and firmware-version provenance rather than freeze a single old hash as permanently trusted.

`COLLECTION-CHECKS.md` defines the platform-neutral security objectives behind the implementation-specific checks.

### Local kernel maintenance note

Firmware Audit compares the running kernel release with kernel releases already installed on the machine. If a newer installed kernel is present, the Updates area records an informational note that a reboot may be pending. This is a local comparison only: the scanner does not contact distribution repositories, and an intentionally selected older kernel is not treated as a security failure.
