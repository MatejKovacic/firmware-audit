# Changelog

## 0.12.9

- Replace the single-string platform classifier with a capability-based signal model. Virtualization, firmware family, runtime boot interface, and boot trust model are kept as independent dimensions and the compatibility `kind` profile is derived from them.
- Detect coreboot from technology-level evidence including coreboot/Dasharo firmware-family strings and CBFS/FMAP TPM measurements, including the hex-encoded event strings emitted by `tpm2_eventlog`. No machine product/model allow-list is used.
- Detect Heads from either explicit Heads identity or the combination of coreboot evidence with multiple independent Heads-style signed-kexec/HOTP artifact families. This fixes Dasharo+Heads systems whose SMBIOS version does not literally contain `coreboot+heads`.
- Collect a tiny existence-only set of boot-model markers plus the virtualization preflight in every scan, so partial-area scans can retain the same platform/trust classification without hashing all of `/boot` or requiring TPM event-log collection.
- Stop treating every unknown non-UEFI bare-metal platform as conventional legacy BIOS. Positive legacy-loader evidence is required for the `legacy-bios` profile; otherwise boot trust remains Unknown rather than creating a false legacy-boot weakness.
- Make virtualization an orthogonal top-level trust boundary while retaining guest firmware/trust dimensions. UEFI virtual machines now actually evaluate guest Secure Boot state, while physical firmware/OOB/security-processor controls remain Not applicable from the guest.
- Fix no-vTPM guidance in virtual machines: recommend configuring a vTPM when guest measured boot/attestation is required instead of incorrectly suggesting that `tpm2-tools` is missing.
- Clarify Intel ME/CSME wording when neither HECI/MEI hardware nor a Linux MEI interface is observed and `intelmetool` is inconclusive: the state is consistent with absent, removed, firmware-hidden, or unsupported implementations, but remains Unknown unless a stronger local source establishes the engine state.
- Remove the unsupported `swapon --json` probe. Swap assessment already uses the portable `swapon --show` inventory, `/proc/swaps`, block topology and mount topology, so no coverage is lost.
- Add regression tests for signal-based Dasharo/Heads detection, unknown non-UEFI handling, positive legacy-loader classification, composite VM+Heads semantics, UEFI VM Secure Boot assessment, and VM vTPM guidance.
- Use the externally reviewed README as the v0.12.9 documentation baseline and retain the explicit package-install confirmation and uninstall/`--purge` instructions.
- Report format remains `firmware-audit-report` version 1; the richer platform-profile fields are additive evidence/presentation metadata.

## 0.12.8

- Complete the virtual-machine scope cleanup: physical firmware write protection and physical out-of-band management are **Not applicable** from a normal VM guest rather than reported Good, and guest memory-protection wording explicitly separates guest-visible confidential-memory features from physical-host RAM protection.
- Normalize `tpm2-tools` failures caused by absent `/dev/tpmrm0` and `/dev/tpm0` as Not applicable evidence, reducing expected no-vTPM noise while the TPM/measured-boot area can still remain Unknown when no usable TPM evidence exists.
- Add an explicitly manual **Upload report** action to the dashboard. Manual upload is enabled by default, no report is uploaded automatically, and transmission occurs only after the user clicks the button. No token/password/API key or per-machine upload credential is required.
- Keep outbound Internet access out of the web viewer. A separate unprivileged `firmware-audit-uploader` service receives a local Unix-socket request, re-verifies the current report digest, and sends the exact JSON bytes over certificate-validated HTTPS.
- Add CSRF protection to the local upload action and reject upload when the displayed report changed or fails its local integrity check.
- Require HTTPS upload URLs, refuse embedded URL credentials and redirects, cap local/remote protocol responses, and preserve the receiver's returned digest/duplicate state.
- Add a dedicated systemd sandbox for the uploader: no capabilities, private devices/tmp/IPC, protected kernel/filesystem state, hidden process metadata, restricted namespaces/syscalls, and only AF_UNIX/AF_INET/AF_INET6 networking needed for the local socket plus outbound HTTPS.
- Add regression coverage for VM Not-applicable semantics, guest-scoped memory wording, absent TPM devices, upload URL/report validation, exact-body HTTPS submission, and uploader sandbox/install behavior.
- Make the installer non-invasive with respect to package maintenance: detect already-installed dependencies, skip APT entirely when nothing is missing, use `--no-upgrade` when installing missing packages, and set a deterministic administrative PATH, prefer `systemd-sysusers` for service-account creation, and retain `addgroup`/`adduser` plus `groupadd`/`useradd` fallbacks for minimal installations.
- Force manual upload enabled on upgrades as well as fresh installs, remove obsolete per-machine upload-key settings/files from earlier development builds, and make the default `audit.telefoncek.si` receiver immediately usable after installation.
- Make package installation explicit for external testers: when dependencies are missing, print each missing package and its purpose, let APT display the complete dependency transaction, and require interactive confirmation instead of using `-y`/`--assume-yes`.
- Depend on the base `apparmor` package for `aa-status` evidence rather than requesting the unnecessary `apparmor-utils` package.
- Add `uninstall.sh` with normal uninstall and `--purge`/`/purge` modes. Normal uninstall preserves reports/configuration and service accounts; purge additionally removes those local data and accounts. Distribution packages are never removed automatically.
- Expand README installation/uninstallation documentation with the full installer-managed package/tool list, exact commands, package-change behavior, report/config retention and purge semantics.
- Report format remains `firmware-audit-report` version 1.

## 0.12.7

- Refined virtual-machine semantics: VM scope is informational rather than an Identity failure, physical platform security processors are Not applicable from normal guests, non-UEFI guests also show UEFI Secure Boot as Not applicable, and virtual-UEFI guests retain guest Secure Boot assessment. Physical host firmware is explicitly outside the guest assessment boundary.
- Skip Intel `intelmetool`/raw capability-state probing inside detected virtual machines, where guest CPUID vendor strings do not imply direct access to the physical host ME/CSME device.
- Require actual bound ACPI EC evidence (or corroborating journal/DMI evidence) before reporting a system embedded controller; the mere presence of an ACPI EC driver directory no longer counts as a device.
- Make CPU-vulnerability guidance virtualization-aware by directing VM operators to review host microcode/kernel mitigations and the VM CPU model as well as keeping the guest kernel current.
- Normalize expected platform-limitation probe results such as fwupd HSI being unavailable to an unprivileged hypervisor guest, absent IPMI device nodes, and unavailable MSR device access as Not applicable rather than generic command failures.
- Polish the dashboard with VM-scope context, clearer **What it means** / **What to do** labels, and collapsed secondary finding context so the first view is easier for non-specialists to read without removing technical evidence.
- Deepen systemd hardening for the web viewer with isolated IPC, hidden process metadata, a process-only `/proc` view, and an allow-listed system-service syscall profile.
- Deepen collector hardening without hiding evidence: isolate IPC, protect kernel logs, restrict namespaces and syscall architectures, and deny module-loading, mount, and reboot syscall classes. The collector intentionally retains host `/tmp`, `/var/tmp`, `/dev/shm`, device nodes, and full `/proc` visibility because those are evidence sources.

## 0.12.6

- Added a local maintenance note when a newer installed kernel release exists but the machine is still running an older installed kernel. This does not perform an online update check and does not change an otherwise Good overall security result.
- Consolidated failed IOMMU and pre-boot DMA fwupd checks into one DMA-isolation finding with multiple evidence items instead of counting them as independent security problems.
- Clarified the kernel unsigned-module finding to cover modules that contain signature metadata but are not accepted as trusted by the running kernel's signing policy, including locally signed DKMS-style modules.
- Passed the always-collected system/kernel context into scanner-side assessment so update interpretation can use the running and locally installed kernel releases.

## 0.12.5

- Separate the overall **security result** from **assessment coverage**. An Unknown area no longer automatically masks an otherwise meaningful Good/Attention/Investigate result.
- Add explicit coverage states: `complete`, `partial`, and `insufficient`.
- Use **No issues found in assessed areas** for a Good result so partial coverage is not presented as proof that every selected control is good.
- Keep overall `unknown` only when there is not enough assessed evidence for a meaningful security result at all.
- Display the coverage state alongside the security result in the web UI and include coverage details in report-format-v1 JSON while retaining backward-compatible format version 1.
- Add regression tests for Good+Partial, Attention+Partial, Unknown+Insufficient, and Complete coverage.

## 0.12.4

- Distinguish `intelmetool` low-level access failures from Intel ME/CSME state. `iopl: Operation not permitted` is now recorded as a **blocked** probe with reason `iopl-permission-denied`, never as evidence that ME/CSME is absent or disabled.
- Collect the scanner process capability state on Intel scans and preserve `CAP_SYS_RAWIO` effective/bounding-set context together with the active kernel-lockdown mode when an `intelmetool` probe is blocked.
- Treat `intelmetool` output such as `Can't find ME PCI device` as **inconclusive** rather than successful ME-state evidence; generic PCI/MEI evidence remains independent.
- Add assessment text that clearly describes blocked versus inconclusive Intel probing and recommends retaining **Unknown** unless a chipset-aware source explicitly establishes the state.
- Add regression tests for blocked `iopl()` access, kernel-lockdown/capability context, inconclusive ME PCI detection, and Intel-only command gating.
- Report format remains `firmware-audit-report` version 1; these are collector/assessment refinements and do not change the viewer contract.

## 0.12.3

- Added an optional Intel-only `intelmetool -m` probe as an independent chipset-aware source for Intel ME/CSME state. The Debian/Ubuntu installer attempts to install `coreboot-utils`, but a missing package does not prevent installation or scanning.
- Separated Intel CSME/HECI hardware presence, Linux MEI host-interface availability, and decoded engine state. A present HECI function with a failed or hidden MEI interface is now **Unknown**, not **Good**, unless an explicit supported decoder reports the engine disabled or absent.
- Record an explicit `intelmetool` disabled state as an informational machine-baseline observation rather than inferring disablement from raw generation-dependent firmware-status registers or MEI initialization failure.
- Preserve the AMD CCP-interface warning as an informational compatibility/security note when AMD PSP and TEE initialization both succeed, rather than silently dropping the warning.
- Added regression coverage for Intel/AMD command gating, explicit disabled Intel ME state, unresolved MEI initialization failures, and the successful-PSP CCP-warning case.
- Report format remains `firmware-audit-report` version 1; these changes refine evidence and scanner interpretation without changing the viewer contract.

## 0.12.2

- Fixed Intel Total Memory Encryption activation detection: explicit runtime evidence such as `x86/tme: not enabled by BIOS` now overrides mere CPU capability support, and supported-but-inactive TME is reported as such rather than active.
- Added strict CPU-vendor gating for architecture-specific memory-encryption semantics. AMD CPUID leaf `0x8000001f`, AMD SYSCFG/SEV MSRs, SME/SEV flags, and AMD KVM state are only interpreted on `AuthenticAMD`; live non-AMD scans no longer execute the AMD-only CPUID/MSR probes.
- Added semantic interpretation for failed Intel BootGuard ACM protection, verified-boot, and error-policy HSI attributes on conventional UEFI systems. These are aggregated into a medium Attention protection weakness and are not treated as compromise evidence.
- Added semantic interpretation for an Intel ME/CSME firmware-version HSI failure as a medium local-policy/firmware-maintenance condition with the observed fwupd name/version retained in evidence.
- Kept Heads/coreboot on its separate trust model: conventional UEFI BootGuard policy failures are not raised as actionable findings on a detected Heads platform.
- Report format remains `firmware-audit-report` version 1; the changes correct scanner interpretation and add implementation-specific evidence fields without changing the viewer contract.

## 0.12.1

- Fixed system CPU-model collection so x86 `/proc/cpuinfo` processor indexes such as `processor: 0` are not mistaken for the CPU model name.
- Fixed installed-kernel context on Debian/Ubuntu by including only kernel image packages in `install ok installed` state, while retaining the running kernel and a local module-directory fallback for non-dpkg systems. Removed (`rc`) kernel-package leftovers no longer appear as installed releases.
- Hardened v0.12 upgrade cleanup: obsolete pre-v0.12 collector timer/path/service units are stopped and disabled individually before replacement, stale wants links are removed, systemd is reloaded immediately, and failed legacy unit state is reset.
- Report format remains `firmware-audit-report` version 1; these are metadata correctness fixes, not a contract change.

## 0.12.0

- Introduced an intentional breaking report-format boundary. v0.12 reports use `format.name=firmware-audit-report` and format version 1; the v0.12 viewer does not consume pre-v0.12 JSON.
- Separated scanner assessment from presentation: the scanner writes final `results`, while the Flask viewer no longer imports or executes assessment/section logic.
- Added selectable scan areas through repeatable `--area`, comma-separated `--areas`, `--list-areas`, and named profiles.
- Added `full`, `daily`, and `integrity` profiles. `daily` excludes the expensive installed-files/persistence area; `integrity` scans only that area.
- Added automatic shared-command dependency resolution so selected areas reuse common local evidence and expensive unrelated commands are skipped.
- Added explicit full/partial scan scope; only requested areas are exposed in the presentation results of a partial report.
- Added stable namespaced machine identity plus OS release, running kernel, installed kernel releases, hardware/board, BIOS/UEFI, CPU and architecture context to every report for future semantic comparison.
- Changed report storage from snapshot-only to immutable timestamped scan files plus an atomically updated `current.json`. The scanner still performs no historical comparison itself.
- Standardized scanner locking at `/run/firmware-audit/scan.lock` so cron, systemd and manual invocations cannot overlap.
- Replaced the old collection service/timer with `firmware-audit-scan.service`, a single-area `firmware-audit-scan@.service`, and optional disabled daily/monthly timer examples.
- Kept the viewer read-only and offline scanner policy unchanged.

## 0.11.3

- Refined TPM measured-boot replay assessment so a mismatch with strong independent signs of event-log truncation is reported as **Attention** rather than a compromise-oriented **Investigate** signal.
- Added conservative event-log truncation diagnostics: actual bytes read near a fixed power-of-two capacity boundary, parsed tail ending during active bootloader measurement, and PCR mismatch correlation.
- Fixed TPM event-log size collection for securityfs pseudo-files that report `st_size=0`; the report now records the actual byte count read from `binary_bios_measurements`.
- Preserve **Investigate** for replay mismatches when the available event log does not show strong truncation evidence.
- Record all common-bank PCR comparisons alongside the primary PCR 0-7 assessment so later bootloader PCR divergence (for example PCR 8/9) can support truncation diagnosis.
- Report schema is now 15.

## 0.11.2

- Fixed false package-integrity alarms for installed kernel modules caused by the collector systemd sandbox hiding `/usr/lib/modules` (`/lib/modules` on usr-merged systems) while `dpkg --verify` was running.
- Replaced `ProtectKernelModules=yes` in the collector with a readable module tree plus explicit denial of `CAP_SYS_MODULE` and the systemd `@module` syscall class, so the collector can inspect modules but cannot load or unload them.
- Added `collection_timing` to schema 14 reports: scan start/completion timestamps, total duration, aggregated per-area active duration, and contiguous area segments.
- Simplified the dashboard timing display to scan start plus total duration; detailed area timings remain in the downloadable/raw JSON.
- Stopped classifying a generic PCI device merely because its description contains `coprocessor`, avoiding false security-processor inventory such as AMD audio coprocessors.
- Report schema is now 14.

## 0.11.1

- Fixed collector failure under the hardened systemd service when `chmod()` was attempted on the `ReadWritePaths` report-directory bind-mount root. Directory ownership and mode remain managed by systemd-tmpfiles; custom report directories receive the requested mode when created.
- Older reports that predate the Platform security processor, OOB management, and Memory protection sections now show those sections as Unknown / not collected by that report version instead of Not applicable.

## 0.11.0

- Deepened the Platform security processor area using the stronger local evidence model developed in the standalone platform-security inventory.
- Added explicit AMD TEE, AMD GPU PSP/secure-firmware-path, system embedded-controller, and generic security/management-class PCI inventory evidence.
- Deepened AMD memory-protection detection with CPUID leaf 0x8000001f, optional local SYSCFG/SEV MSR reads, PSP `tsme_status`, firmware settings, KVM controls, and `/dev/sev` correlation.
- AMD Linux-managed SME and firmware-controlled TSME are now separate states; active TSME counts as active system-memory encryption even when the Linux-managed SME path is inactive.
- AMD SEV, SEV-ES, and SEV-SNP capability is kept separate from whether the host virtualization stack enables SEV.
- Added PCI multifunction correlation for IPMI-class functions integrated with network controllers, including a dormant NIC-OOB state when no usable IPMI System Interface exists.
- Added DMTF DASH enable/disable detection from local kernel and firmware-attribute evidence.
- Added firmware endpoint-persistence/manageability detection with explicit separation between firmware enablement and unknown operating-system agent/enrollment state.
- Firmware endpoint persistence, enabled DASH, and provisioned AMT remain Security notes rather than compromise findings.
- Direct kernel-exported TSME state takes precedence over weaker negative Encrypted-RAM observations to avoid false warnings.
- Added `cpuid`, `msr-tools`, and `ipmitool` to the reference Debian/Ubuntu installation; MSR reads remain optional and no kernel module is loaded by the collector.
- Kept all added collection offline-capable and read-only; no remote management endpoint is contacted.
- Report schema is now 13.

## 0.10.0

- Added a Platform security processor area with local evidence for Intel ME/CSME/SPS-family interfaces, AMD Secure Processor/PSP, and explicitly identified equivalent security processors.
- Added direct AMD Secure Processor security-state collection for fused/production state, debug lock, rollback protection, platform secure boot, ROM Armor, TSME and version attributes when exposed by the platform.
- Added Intel ME/CSME manufacturing-mode interpretation using local platform security evidence.
- Added an Out-of-band management area for locally observable Intel AMT and BMC/IPMI interfaces; no network probing or remote discovery is performed.
- Provisioned out-of-band management is reported as a Security note rather than treated as compromise.
- Added a Memory protection area that separates hardware capability from active protection and distinguishes whole-system memory encryption from confidential-VM features.
- Added local detection for AMD SME/SEV/SEV-ES/SEV-SNP and Intel TME/TME-MK/TDX where the running platform exposes reliable evidence.
- Explicitly identified Pluton or Qualcomm secure-processing devices can be inventoried when local hardware/firmware evidence names them; the collector does not infer them from CPU model families.
- Missing host-visible PSP/MEI/security-processor interfaces are treated as unobservable state rather than proof that the underlying processor is physically absent.
- Kept all new collection offline-capable and deterministic; no manufacturer website, vendor API, web search, or remote management probe is used.
- Expanded the concise README and platform-neutral collection specification for the three new security areas.
- Report schema is now 12.

## 0.9.0

- Added offline TPM event-log replay comparison against live PCR values; firmware-range mismatches are investigation signals.
- Added cross-source Secure Boot consistency checks using independent local evidence.
- Added interpretation of local processor vulnerability/mitigation status.
- Added detection of security-degrading active kernel command-line parameters.
- Added Thunderbolt/USB4 authorization and IOMMU DMA-protection assessment from local sysfs.
- Added generic active security-module, module-loading, kexec, and module-signature enforcement collection.
- Added local IMA/IPE integrity-framework inventory without enabling or changing policy.
- Kept scans offline: no metadata refresh, web lookup, vendor API, telemetry, CVE service, or AI service is used; collector IP sockets remain blocked by systemd policy.
- Reworked README around concise purpose, covered areas, commands, installation, and usage.
- Reworked COLLECTION-CHECKS.md as a distribution-, operating-system-, package-manager-, and tool-neutral security specification.
- Report schema is now 11.

## 0.8.2

- Fixed upgrades from older configurations that used `BIND_HOST=0.0.0.0` behind a local nginx reverse proxy.
- Installer now validates preserved web settings before restarting the dashboard.
- When a local nginx proxy to the configured dashboard port is detected, the installer safely migrates the listener to `127.0.0.1` and backs up the previous environment file.
- Ambiguous remote-listener configurations now fail installation with actionable instructions instead of putting the web service into a restart loop.
- Added a systemd start-rate limit to prevent unbounded restart churn after configuration errors.

## 0.8.1

- Made the dashboard strictly read-only and removed the web-to-root scan trigger, request path unit, CSRF/session machinery, and `sudo` dependency.
- Changed `/run/firmware-audit` to root-owned, group-readable mode so the web user cannot replace collection status or create trigger files.
- Removed `PrivateTmp` from the privileged collector so `/tmp` and `/var/tmp` inventory examines the real host directories.
- Added stronger systemd sandboxing for both collector and dashboard.
- Made dashboard authentication fail closed when only one credential field is configured.
- Refuse non-loopback HTTP listeners by default; remote plain HTTP requires an explicit unsafe override.
- Added `no-store`, CSP, frame, referrer, MIME-sniffing and permissions-policy response headers.
- Replaced unbounded subprocess pipe buffering with bounded streaming capture while retaining SHA-256 of the complete command output.
- Parse dpkg diversions and statoverrides as exact paths, preventing prefix/substring false negatives.
- Expanded semantic classification of startup, service-activation, device-policy and privilege-policy package objects.
- Package verification absence now produces an Unknown host-integrity state instead of an implicit positive result.
- Removed obsolete report-history reset code, legacy report route, unused section helpers, old scan-command fallback, and stale baseline terminology.
- Renamed the dashboard's unkeyed report digest result to “Snapshot consistency” to avoid implying cryptographic authenticity.
- Replaced README with a concise overview, area/command table, installation and manual-collection instructions.
- Rewrote COLLECTION-CHECKS.md as an operating-system/distribution-neutral security-check specification.

## 0.8.0

- Removed global collection-coverage percentages and per-section evidence counters from the end-user dashboard.
- Removed the global percentage threshold from assessment status logic; missing evidence is handled at the affected section instead.
- Replaced the VirtualBox-specific out-of-tree module explanation with product-neutral module classification.
- Replaced the i915-specific kernel-warning exception with generic kernel warning interpretation.
- Loaded module metadata now records generic origin, Debian package ownership where relevant, and whether signature metadata was reported.
- Kernel module explanations are derived from kernel taint semantics, module-tree location, package ownership, signature metadata, and license metadata rather than application names.
- Kept platform-specific interpretation only where the security architecture genuinely differs, such as Heads/coreboot and conventional UEFI.
- Updated the report schema to version 9.

## 0.7.1

- Fixed a false positive where a package-owned directory under `/lib/modules/<kernel-version>` could be classified as modified kernel code.
- Package directories are now explicitly identified and never promoted to an installed-code integrity alarm.
- Under `/lib/modules`, only actual kernel module files (`*.ko` and compressed variants) and runtime module-loading metadata can raise Attention.
- Missing kernel-version directories and other non-runtime module-tree entries are treated as non-actionable package drift.

## 0.7.0

- Split end-user assessment output into actionable findings, successful section results, and neutral Security notes.
- Successful swap encryption is now a green section result and no longer creates an informational finding.
- Suspend-to-RAM residual risk is a Security note and does not raise the overall status.
- Compatibility and reliability observations no longer raise Attention by themselves.
- Added `package_verify_analysis`, which classifies `dpkg --verify` drift by file role and records local metadata and SHA-256 where practical.
- Locally modified package conffiles remain normal administration and do not create an alarm.
- Documentation, registered diversions/statoverrides, and ordinary non-executable package-data drift do not create Attention.
- Only package drift affecting executable/library/kernel/boot/authentication/startup code can raise an installed-software integrity Attention result.
- Added a dedicated Security notes table below the main assessment table.
- Updated the report schema to version 8.

## 0.6.0

- Added a live collection indicator with a spinner, percentage, current high-level area, and clickable progress log.
- Added `/status` JSON for the dashboard; the status channel contains no raw command output.
- Changed the installer to start the initial collection asynchronously.
- Added `proc_swaps` and a derived `swap_topology` artifact.
- Removed fwupd swap HSI from the swap-encryption conclusion; active swap is now mapped through the actual storage topology.
- Suppressed fwupd PCR0 reconstruction failures from normal Heads findings while retaining the raw evidence.
- Correlates AMD CCP access failures with TEE and PSP initialization; the compatibility finding is suppressed when the broader Secure Processor initialized.
- Removed confidence wording from the end-user table and renamed the internal finding field to `evidence_strength`.
- Simplified end-user terminology so the main dashboard does not name the operating-system family.
- Updated the report schema to version 7.

## 0.5.0

- Replaced report archives with a single atomic `current.json` snapshot.
- Removed previous-report loading and all baseline comparisons.
- Removed the history list and report-navigation pages from the web interface.
- Replaced the dashboard with one fully expanded assessment table.
- Removed explicit firmware-update history collection.
- Removed previous-boot kernel-journal collection.
- Removed apt and dpkg history-log collection.
- Removed the `changes` assessment section and the baseline artifact.
- Added a one-time installer migration that deletes legacy JSON reports.
- Updated the report schema to version 6.

## 0.4.0

- Added Debian-oriented host-integrity collection.
- Added package verification, systemd, privileged-file, persistence, initramfs, and optional AIDE evidence.
- Introduced the first table-based interface.

## 0.3.0

- Added collection-only Dasharo-like capability evidence for conventional UEFI systems.

## 0.2.2

- Added Heads-aware assessment logic and corrected fwupd interpretation.
