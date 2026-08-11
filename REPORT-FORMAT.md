# Firmware Audit report format v1

Firmware Audit v0.12.0 introduces report format **`firmware-audit-report` version `1`** as the boundary between scanners and viewers.

A viewer must not need scanner code. It should render `results`, use `system` and `report` as context, and treat `evidence` as optional technical detail.

## Top level

- `format` — format name and integer version.
- `report` — scan identity, scope, selected areas/profile, scanner identity and timing.
- `system` — stable machine identifier and execution context.
- `results` — final scanner interpretation intended for presentation.
- `evidence` — raw command records and derived artifacts.
- `integrity` — consistency digest over canonical JSON with the `integrity` object omitted.

## Scope

`report.scope` is either `full` or `partial`.

For a partial report, `report.requested_areas` is authoritative. Unrequested areas are intentionally absent from `results.areas`; their absence must not be rendered as Unknown or Not applicable.

Supporting commands/artifacts may be present in `evidence` because a requested area needed them as a dependency.

## System identity

`system.id` is a namespaced SHA-256 identifier generated locally from a stable hardware UUID when available, otherwise a local machine identifier. The raw source identifier is not included. `system.id_source` describes which class of source was used.

`system.os`, `system.kernel`, and `system.hardware` are scan-time context for future semantic comparison. In particular, changed hashes should be interpreted alongside version changes rather than treated as suspicious in isolation.

## Results

`results.overall` contains the security `status`, `headline`, and `explanation` for the scanned scope, plus a separate `coverage` object. Coverage is `complete`, `partial`, or `insufficient`; an Unknown area therefore does not automatically mask a meaningful Good, Attention, or Investigate security result.

`results.areas` contains only requested areas and is ordered by the scanner's canonical area order. Each area includes generic viewer fields plus its actionable findings, security notes and evidence-source states.

`results.platform_profile` is scanner-generated applicability context. Consumers should primarily use `kind` for compatibility, but may also receive additive dimensions such as `runtime_interface`, `firmware_family`, `boot_trust_model`, and explainable `signals`. These fields describe why platform-specific rules applied; they are not a machine-model identity database.

Status values are:

- `good`
- `attention`
- `investigate`
- `unknown`
- `not_applicable`

A viewer should ignore unknown additional fields so compatible format-v1 extensions can be introduced without requiring a viewer release.

## Evidence evolution

`evidence.commands` and `evidence.artifacts` are intentionally scanner-oriented. Consumers that need forensic detail may use them, but should not assume every scanner version exposes identical artifacts. Stable end-user presentation should come from `results`.

## Integrity digest

`integrity.digest` is SHA-256 over UTF-8 JSON encoded with sorted keys and compact separators, with the complete top-level `integrity` object omitted. It is a file-consistency check, not an authenticity signature.
