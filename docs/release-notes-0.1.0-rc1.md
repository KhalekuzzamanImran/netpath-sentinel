# NetPath Sentinel 0.1.0-rc1

This candidate includes bounded live packet streaming, conservative TCP
handshake/session analysis, Windows Npcap dependency diagnostics, Linux DEB/RPM
packaging, unprivileged desktop launch checks, and private local report-file
permissions with nested payload/stream redaction by default.

## Verification

- Windows development checks are recorded in `phase6-verification.md`.
- Ubuntu 24.04 DEB and AlmaLinux 9 RPM passed container install, CLI, unprivileged
  offscreen GUI/database creation, and uninstall checks.
- Windows live capture, native Linux VM acceptance, installer upgrade, and LAN
  acceptance remain pending as recorded in the release verification matrix.
- Commercial redistribution remains subject to the licensing checklist and
  legal review.
