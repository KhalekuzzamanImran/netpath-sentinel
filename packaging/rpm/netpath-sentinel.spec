Name: netpath-sentinel
Version: 0.1.0
Release: 1%{?dist}
Summary: Evidence-driven TCP connectivity diagnostics
License: MIT
BuildArch: x86_64
Requires: python3 >= 3.12, libpcap

%description
Native desktop TCP connectivity diagnostics and monitoring.

%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/usr/share/applications
install -m 0755 dist/linux/netpath-sentinel %{buildroot}/usr/bin/netpath-sentinel
install -m 0644 packaging/debian/netpath-sentinel.desktop %{buildroot}/usr/share/applications/netpath-sentinel.desktop

%files
/usr/bin/netpath-sentinel
/usr/share/applications/netpath-sentinel.desktop
