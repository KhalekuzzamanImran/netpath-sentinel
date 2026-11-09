Name: netpath-sentinel
Version: 0.1.0
Release: 1%{?dist}
Summary: Evidence-driven TCP connectivity diagnostics
License: MIT
BuildArch: x86_64
Requires: libpcap, glib2, dbus-libs, krb5-libs, libxkbcommon, libxkbcommon-x11
Requires: mesa-libEGL, mesa-libGL, libX11, libxcb
Requires: xcb-util-cursor, xcb-util-wm, xcb-util-keysyms, xcb-util-renderutil
Requires: xcb-util-image, xcb-util, libxcb
Source0: netpath-sentinel
Source1: netpath-sentinel-cli
Source2: netpath-sentinel.desktop
Source3: netpath-sentinel.svg

%description
Evidence-driven TCP connectivity diagnostics and monitoring desktop application.

%prep

%build

%install
install -D -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/netpath-sentinel
install -D -m 0755 %{SOURCE1} %{buildroot}%{_bindir}/netpath-sentinel-cli
install -D -m 0644 %{SOURCE2} %{buildroot}%{_datadir}/applications/netpath-sentinel.desktop
install -D -m 0644 %{SOURCE3} %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/netpath-sentinel.svg

%post
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database %{_datadir}/applications >/dev/null 2>&1 || :
fi

%postun
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database %{_datadir}/applications >/dev/null 2>&1 || :
fi

%files
%{_bindir}/netpath-sentinel
%{_bindir}/netpath-sentinel-cli
%{_datadir}/applications/netpath-sentinel.desktop
%{_datadir}/icons/hicolor/scalable/apps/netpath-sentinel.svg
