# Firmware Audit collection checks

This document defines the security questions Firmware Audit tries to answer. It is independent of a particular operating system, distribution, package manager, firmware vendor, or application product. Implementations map these objectives to trustworthy **local** evidence available on the audited platform.

## 1. Platform identity and applicability

Establish hardware, firmware, boot model, virtualization state, processor architecture, and operating environment sufficiently to determine which later checks apply.

Why: security controls must be interpreted according to the actual platform rather than assumed from a generic profile.

## 2. Firmware identity and current evidence

Record firmware identity, versions, exposed runtime tables, boot-related variables, and other locally visible firmware evidence without modifying firmware.

Why: current identity and state are necessary context for every firmware conclusion.

## 3. Firmware modification resistance

Determine whether security-critical firmware can be rewritten by privileged software and whether hardware write protections, debug locks, update authentication, recovery controls, and rollback restrictions are active where supported.

Why: weak modification resistance increases persistence and downgrade risk. A weak protection is not itself proof of modification.

## 4. Privileged platform security processors

Identify locally observable privileged platform security processors or equivalent isolated security subsystems. Also inventory related trusted-execution, peripheral security processors, and autonomous embedded controllers when they are explicitly exposed. Record operational state and security-relevant controls such as manufacturing state, debug restrictions, fused/production state, rollback resistance, firmware-verification state, and other protections when explicitly exposed.

For platform-specific processor probes, keep hardware presence, host-interface availability, and decoded processor state separate. A blocked low-level hardware-access request or an unsupported/inconclusive platform-aware probe is a collection limitation and must not be interpreted as an absent or disabled processor. Preserve relevant runtime-enforcement and process-capability context when it explains why a probe could not run.

Why: such processors can participate in platform initialization, firmware verification, trusted execution, cryptographic services, and management. Their presence is not itself a weakness; explicitly insecure or contradictory state can be relevant.

Do not infer physical absence merely because no host-visible interface is exposed. Likewise, distinguish hardware presence, host-interface availability, and decoded processor state. A failed, hidden, or unavailable host interface must remain indeterminate unless another platform-aware local source explicitly establishes that the processor is disabled, absent, or active.

## 5. Out-of-band management

Identify locally observable management subsystems capable of operating independently of the main operating environment. Distinguish a usable management controller from dormant or partial management plumbing, including management-class functions integrated into other devices. Record whether remote-management modes and firmware-resident endpoint-management or persistence capabilities are present, enabled, disabled, provisioned, or indeterminate where that state is locally observable.

Why: independent management controllers can have privileged access to the platform and may remain active outside the normal operating environment. Presence or provisioning is context, not proof of compromise.

Collection must not require network probing or remote discovery.

## 6. Boot authorization and hardware-rooted trust

Determine which trust model is active and whether early firmware and startup components are authorized according to that model. Do not force one universal mechanism onto every platform.

Why: unauthorized early components can invalidate later operating-environment controls.

## 7. Measured boot consistency

Collect trusted-platform measurement capabilities, measurement registers, and the measured-boot event log. Where local tooling can replay the event log, compare reconstructed measurements with live values.

Why: a cryptographic event log is more useful when its cumulative measurements reproduce the protected register state. An unexplained mismatch is an integrity signal requiring investigation. If independent local evidence strongly indicates that the available event log ended at a fixed storage limit before measurements completed, report the replay as incomplete evidence rather than treating truncation itself as a compromise indicator.

## 8. Cross-source trust consistency

Compare independent local observations of the same security property where possible: boot authorization state, firmware security attributes, runtime enforcement state, trusted-measurement state, and other duplicated evidence.

Why: contradictions can reveal broken configuration, incomplete enforcement, faulty instrumentation, or integrity problems that would be missed if each source were interpreted independently.

## 9. Processor vulnerability state

Record the running environment's locally reported processor vulnerability and mitigation state.

Why: effective protection matters more than simply knowing the processor model. Offline assessment must not claim that firmware or microcode is globally current unless local evidence can establish that.

## 10. Security-degrading boot configuration

Inspect active boot parameters for explicit settings that disable relevant processor, runtime, integrity, or DMA protections. Interpret contextual controls only when the affected mechanism is actually relevant to the platform.

Why: protections present in firmware or the runtime build can be intentionally disabled during startup.

## 11. Runtime privileged-code integrity

Record privileged runtime taint/state indicators, loaded privileged modules or drivers, origin, signatures, ownership where locally available, active security modules, and important diagnostic states.

Why: firmware may be intact while privileged runtime code has been changed or enforcement has been weakened.

Interpretation should be semantic: use origin, execution role, ownership, signature state, and platform-defined semantics rather than product allowlists.

## 12. Runtime integrity frameworks

Detect locally active integrity/enforcement mechanisms such as measurement, appraisal, or policy-enforcement frameworks and preserve their observable policy/state. Absence of an optional framework is not automatically a failure.

Why: when such a framework is intentionally deployed, disabled enforcement or policy contradictions can be security-relevant.

## 13. Installed-object integrity

Where trustworthy local package, image, or filesystem integrity metadata exists, compare security-relevant installed objects against it. Distinguish executable, library, kernel, boot, and startup objects from configuration, documentation, directories, caches, and explicitly registered local overrides.

Why: unexplained drift in privileged code or startup objects can indicate tampering, corruption, or unsupported local changes. Local metadata detects drift; it does not by itself prove malicious modification.

## 14. Persistence mechanisms

Inventory mechanisms capable of automatically starting privileged code or influencing privileged execution, including services, scheduled tasks, privileged executables, loaders, startup scripts, module configuration, and policy objects.

Why: persistence often uses legitimate operating mechanisms rather than obviously malicious files.

## 15. Hardware memory protection

Identify locally observable hardware-backed memory-protection capabilities and distinguish capability, firmware enablement, operating-environment activation, and transparent full-memory activation where those states can be observed independently. Separate whole-system memory protection from features intended primarily to isolate confidential virtual machines or security domains.

Why: physical-memory encryption can reduce exposure to some physical attacks, while confidential-computing capabilities address a different threat model. Support alone must not be reported as active protection.

Architecture-specific capability encodings must only be interpreted for the processor vendor and architecture that define them. A capability bit or feature advertisement must remain distinct from evidence that the protection is active.

Absence of optional memory encryption is not automatically a security failure unless an explicit policy requires it.

## 16. Storage, swap, and memory exposure

Determine the actual encryption topology of storage and active swap and record sleep states that retain secrets in memory.

Why: effective protection depends on the complete backing-storage chain, while suspend states can retain active keys in powered memory.

## 17. External DMA and peripheral-bus protection

Determine whether externally attachable DMA-capable devices are isolated by remapping or controlled by an equivalent platform security mechanism. Where external high-speed peripheral tunnelling exists, record authorization and protection state.

Why: DMA-capable peripherals can bypass normal processor-mediated memory access controls if isolation is incomplete.

## 18. Peripheral firmware

Inventory firmware-capable devices and locally observable firmware/update properties.

Why: security-relevant firmware and persistence surfaces exist outside the motherboard firmware.

## 19. Locally known maintenance state

Record locally cached update metadata, revocation or minimum-version information, and failed update state without silently refreshing online sources.

Why: an offline audit can report what the machine currently knows, but cannot prove that no newer vendor release or vulnerability exists.

## 20. Evidence availability

For each check preserve whether evidence was collected, unavailable, unsupported, not applicable, or permission-denied. Never turn missing evidence into a positive conclusion.

Why: **Unknown is different from Good**.

## 21. Evidence preservation

Preserve raw outputs, structured artifacts, hashes, timestamps, and deterministic interpretations so conclusions remain reviewable independently of explanatory prose.

Why: forensic value depends on reproducible evidence, not just a dashboard label.

## Design constraints

- Collection is read-only and non-interactive.
- Assessment is deterministic and local.
- A scan does not require Internet access.
- Manufacturer-site searches, web search, reputation services, external vulnerability feeds, telemetry, and AI services are not part of a scan.
- Locally maintained or cached evidence may be used whether it was populated during normal system maintenance or supplied by the platform.
- No product or application allowlist is required for normal interpretation.
- Platform-specific rules are used only for genuinely different trust architectures or hardware-defined semantics.
- Successful protections are results, not findings.
- Residual risks and compatibility conditions are notes, not alarms.
- A local audit cannot prove the absence of sophisticated firmware compromise.

## Snapshot identity and future comparison

Each scan should identify the audited machine and record enough execution context to support meaningful comparison between independent snapshots. This includes a stable privacy-preserving machine identifier, operating-environment version, running system-core version, architecture, and locally visible hardware/firmware identity.

A scanner should not treat every changed hash as a security failure. Future comparison should correlate a changed object with version and provenance changes where available, distinguish expected maintenance from unexplained drift, and compare only security areas that were actually collected in both snapshots.

The scanner itself may remain stateless: independently generated immutable reports can be compared by a separate component.
