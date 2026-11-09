# Release readiness

## Verified on this workspace

- Source tree and packaging configuration created.
- Linux host inspection implementation is present.
- Unit/integration tests are included.
- Native Qt shell is implemented.
- Replay-mode diagnostics execute through the workflow, stream packet events into the Qt details view, persist results, and export reports.
- Session history can reopen persisted packet timelines and findings.
- Windows installer and DEB/RPM build definitions are present.

## Pending native verification

- Windows 11 x64/Npcap capture and Inno Setup install/uninstall.
- Ubuntu/Debian package install/remove smoke test.
- AlmaLinux/Rocky/RHEL RPM install/remove smoke test.
- Privileged live capture with libpcap on a production-like interface.
- Native live capture plus active-listener execution on a production-like interface.
- PCAP fixtures for all acceptance scenarios beyond the synthetic handshake/payload fixture.

These items are deliberately not reported as passed because this workspace is Ubuntu 26.04 and no native Windows or RPM environment is available.
