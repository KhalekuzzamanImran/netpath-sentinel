# Privileges and payload privacy

NetPath Sentinel does not elevate the desktop process or install a privileged
capture helper. On Windows, live capture depends on a separately installed
Npcap runtime and the current account's configured access. The installer does
not bundle Npcap.

On Linux, live packet capture may require root or capture capabilities granted
by the administrator. The package does not apply file capabilities, change
SELinux policy, modify firewalld, or launch the Qt desktop as root. PCAP replay,
host inspection, and report review should be performed as the normal user.
Capture privilege separation remains a release blocker for deployments that
require packet capture without granting capture rights to the desktop process.

Payload previews are disabled by default. When payload capture is enabled,
packet events retain a bounded preview; the full raw payload field is excluded
from persistence and report serialization. Packet lengths, endpoints, flags,
and timing are retained as diagnostic metadata. Treat opt-in payload previews
and exported reports as sensitive operational data and apply the organization's
retention controls.

Application data is written to the current user's application-data directory.
No temporary PCAP files are created by the live capture workflow.
