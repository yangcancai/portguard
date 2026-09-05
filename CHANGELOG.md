# PortGuard Changelog

This document is the canonical release history for PortGuard Client and
PortGuard Server. The official website reads this file directly from GitHub,
so future release notes only need to be updated here.

## Version compatibility

PortGuard keeps the fwknop 2.6.11 SPA protocol. The table lists the recommended
server for each client release. Older clients continue to work with newer
PortGuard Server packages when they request explicit protocol/port values.

| PortGuard Client | Recommended PortGuard Server | Release status | Notes |
| --- | --- | --- | --- |
| 2.2.2+17 | 2.6.11-pg6 or later | Unreleased | Required for the client `ACCESS ANY` workflow. |
| 2.2.1+15 | 2.6.11-pg6 | Current stable pairing | Uses explicit access rules and is compatible with pg1-pg6. |
| 2.2.0+15 | fwknop 2.6.11 or PortGuard pg1+ | Legacy | Uses the standard fwknop SPA protocol. |
| 2.1.1+14 | fwknop 2.6.11 or PortGuard pg1+ | Legacy | Uses the standard fwknop SPA protocol. |
| 1.0.2+11 | fwknop 2.6.11 or PortGuard pg1+ | Legacy | Uses the standard fwknop SPA protocol. |
| 1.0.1+5 | fwknop 2.6.11 or PortGuard pg1+ | Legacy | Uses the standard fwknop SPA protocol. |
| 1.0.0+1 | fwknop 2.6.11 or PortGuard pg1+ | Legacy | Initial Flutter client. |

`ACCESS ANY` is a PortGuard extension. It requires PortGuard Client 2.2.2 and
PortGuard Server 2.6.11-pg6 or later. Use an explicit value such as `tcp/22`
with upstream fwknop or an older PortGuard release.

## Client releases

### PortGuard Client 2.2.2+17 - Unreleased

Recommended server: **PortGuard Server 2.6.11-pg6 or later**.

- Added end-to-end client support for `ACCESS ANY`, including imported config
  normalization and command execution.
- Added dedicated help for Access and Server Address fields, with security
  guidance for unrestricted access, DNS names, destination ports, and Allow IP.
- Fixed a countdown race that could execute a knock after its saved
  configuration had been deleted.
- Expanded the new help content across all supported client locales.
- Fixed iOS Rust builds by keeping Cargo and rustc on the same rustup toolchain
  and aligned the iOS deployment target with the bundled ML Kit frameworks.
- Added repeatable iOS and macOS App Store archive, signing, validation, and
  upload tooling.
- Updated Windows installer metadata and artifact names to 2.2.2.

### PortGuard Client 2.2.1+15 - 2026-07-07

Recommended server: **PortGuard Server 2.6.11-pg6**. The original client
release was tested alongside the pg1-pg4 server packages and remains compatible
with pg5 and pg6.

- Added Windows activation-code support and offline license verification.
- Added the signed Windows installer workflow, clean rebuild script, product
  metadata, and release artifact.
- Added import from copied PortGuard configuration text and strengthened QR
  payload parsing.
- Added an export-directory picker for client configuration backups.
- Added German, Spanish, French, Japanese, Korean, Portuguese, and Russian
  localizations alongside English and Chinese.
- Fixed Windows build, window, SQLite, and packaging behavior.

### PortGuard Client 2.2.0+15 - 2026-04-27

Recommended server: **fwknop 2.6.11 or any PortGuard Server pg release**.

- Added fixed IP, DNS, `resolve`, and source-address modes for Allow IP.
- Added in-app guidance explaining how Allow IP is resolved and applied.
- Added password-change support for protected local configuration.
- Refined the knock workflow, saved configuration controls, and status UI.
- Fixed password-change validation and Traditional Chinese localization.

Build milestones: `2.2.0+1` and `2.2.0+15` were both recorded on 2026-04-27.

### PortGuard Client 2.1.1+14 - 2026-04-21

Recommended server: **fwknop 2.6.11 or any PortGuard Server pg release**.

- Rebranded the Flutter application and platform assets as PortGuard.
- Redesigned the iOS, macOS, and Android configuration, QR import, theme, and
  countdown experiences.
- Added encrypted local configuration and secure import/export utilities.
- Added application-lock and security-tool screens.
- Added Android, iOS, and macOS release assets and App Store preview tooling.
- Updated Android and macOS build versions and platform integration.

Build `2.1.1+12` was recorded on 2026-03-17; build `2.1.1+14` followed on
2026-04-21.

### PortGuard Client 1.0.2+11 - 2025-06-12

Recommended server: **fwknop 2.6.11 or any PortGuard Server pg release**.

- Added cross-platform SQLite handling and Windows build support.
- Added QR decode integration and stricter Allow IP validation.
- Added Windows installer resources, close behavior, and platform fixes.
- Added basic download and page-view analytics events.
- Added Android fwknop client support and file-picker registration.

Builds `1.0.2+10` and `1.0.2+11` were recorded on 2025-06-10; Android support
was added on 2025-06-12 without another version-field change.

### PortGuard Client 1.0.1+5 - 2025-05-29

Recommended server: **fwknop 2.6.11 or any PortGuard Server pg release**.

- Added QR scanning that populates editable client configuration fields.
- Switched mobile scanning to `mobile_scanner` and added fwknoprc import.
- Added timeout countdown controls and responsive phone/iPad layouts.
- Added application icons, signing fixes, macOS packaging, and tray behavior.
- Trimmed imported fields and added source-address handling for Allow IP.

Build history: `1.0.1+1` on 2025-04-10; `+2` and `+3` on 2025-04-16; `+4`
on 2025-04-21; and `+5` on 2025-05-29.

### PortGuard Client 1.0.0+1 - 2025-03-31

Recommended server: **fwknop 2.6.11 or any PortGuard Server pg release**.

- Introduced the Flutter fwknop client application.
- Added the initial saved configuration and SPA command workflow.

## Server releases

### PortGuard Server 2.6.11-pg6 - 2026-08-02

Compatible client: **PortGuard Client 2.2.1** for explicit access rules and
**2.2.2 or later** for `ACCESS ANY`.

- Added explicit `OPEN_PORTS ANY` policy parsing and `ACCESS ANY` SPA handling.
- Added source-address-only temporary firewall rules for authorized unrestricted
  access while rejecting ANY requests unless the stanza explicitly enables it.
- Removed working default package keys and added atomic, unique Rijndael and
  HMAC key generation on first startup.
- Reworked firewall initialization to rebuild only the INPUT chain while
  preserving other chains and tables.
- Added Debian 13 network-namespace firewall testing for blocked, knocked, and
  expired access paths.
- Expanded package verification for key lifecycle, unrestricted access, and
  firewall behavior.

[View v2.6.11-pg6 on GitHub](https://github.com/yangcancai/portguard/releases/tag/v2.6.11-pg6)

### PortGuard Server 2.6.11-pg5 - 2026-07-23

Compatible client: **PortGuard Client 2.2.1**.

- Added `fwknopd -Q` client payload and QR export with section name, server,
  protocol, port, Allow IP, access rules, keys, username, and timeout.
- Added PortGuard-specific server configuration fields for exported profiles.
- Added Docker verification for both release-package and source installation.
- Added Debian and RHEL firewall persistence-path verification.
- Improved INPUT-chain initialization and package verification portability.
- Documented PortGuard-specific changes from upstream fwknop.

[View v2.6.11-pg5 on GitHub](https://github.com/yangcancai/portguard/releases/tag/v2.6.11-pg5)

### PortGuard Server 2.6.11-pg4 - 2026-07-03

Compatible client: **PortGuard Client 2.2.1**.

- Fixed OpenWrt package artifact export permissions.
- Made artifact discovery and architecture-specific naming more reliable.

[View v2.6.11-pg4 on GitHub](https://github.com/yangcancai/portguard/releases/tag/v2.6.11-pg4)

### PortGuard Server 2.6.11-pg3 - 2026-07-03

Compatible client: **PortGuard Client 2.2.1**.

- Added Debian 13 package builds.
- Added CentOS 7, CentOS Stream 8, and CentOS Stream 9 package builds.
- Added OpenWrt 24.10 package generation for x86_64, mips_24kc, and
  aarch64_cortex-a53 targets.
- Added OpenWrt init integration and release-manifest metadata.

[View v2.6.11-pg3 on GitHub](https://github.com/yangcancai/portguard/releases/tag/v2.6.11-pg3)

### PortGuard Server 2.6.11-pg2 - 2026-07-03

Compatible client: **PortGuard Client 2.2.1**.

- Fixed Rocky Linux package build dependencies and RPM generation.
- Improved RHEL-family package compatibility in CI.

[View v2.6.11-pg2 on GitHub](https://github.com/yangcancai/portguard/releases/tag/v2.6.11-pg2)

### PortGuard Server 2.6.11-pg1 - 2026-07-03

Compatible client: **PortGuard Client 2.2.1**.

- Introduced GitHub Actions release-package CI for PortGuard Server.
- Added reproducible DEB and RPM package builders.
- Added package installation and runtime verification.
- Added checksums plus `manifest.tsv` and `manifest.json` release indexes for
  automatic installer package selection.

[View v2.6.11-pg1 on GitHub](https://github.com/yangcancai/portguard/releases/tag/v2.6.11-pg1)

## Maintenance policy

- Add new client and server entries at the top of their respective sections.
- Keep the compatibility table aligned with the detailed entries.
- Use the release tag date for server releases and the committed application
  version date for client releases.
- Mark worktree-only or pre-release changes as `Unreleased` until artifacts are
  published.
