# Windows capture, Npcap, and acceptance testing

## Runtime diagnostics

NetPath Sentinel checks for the Npcap service registration, kernel driver file,
wpcap.dll, Packet.dll, and Scapy-visible Windows adapters before opening a live
capture. It reports missing runtime components with setup instructions.
Friendly adapter names are resolved to NPF device paths. The loopback adapter is
mapped to the NPF_Loopback device; ordinary Wi-Fi/Ethernet capture must not be
treated as loopback capture.

The application does not download, install, start, or elevate Npcap. When
authorized by the machine owner, install it from the [official Npcap download
page](https://npcap.com/#download), then reopen the application and check its
capture diagnostics. Npcap's admin-only installation option requires elevated
access to capture devices. The desktop itself runs without elevation.

Npcap 0.9983 and later provide `\\Device\\NPF_Loopback` for loopback capture
without the optional legacy KM-TEST loopback adapter. This application maps
Windows' `Loopback Pseudo-Interface 1` selection to that Npcap device. Confirm
the device appears in Scapy's live interface enumeration on the target host.
See the [Npcap loopback API guidance](https://npcap.com/guide/npcap-devguide.html#loopback).

Npcap licensing is separate from this project's MIT license. Nmap Project
states that Npcap is not generally redistributable with other software without
special permission. Commercial products that redistribute Npcap require an
Npcap OEM redistribution license; some organizational internal-use scenarios
have a separate license. This installer intentionally
does not bundle Npcap. See the [Npcap license](https://npcap.com/license) and
[Npcap OEM redistribution terms](https://npcap.com/oem/redist).

Inno Setup 6.7.3 compiled this installer using its non-commercial distribution.
The Inno Setup authors request that commercial users purchase a license,
including when invoking the compiler from CI. Confirm the project's intended
use and obtain the required license before commercial releases; see the
[Inno Setup commercial license terms](https://jrsoftware.org/isorder.php).

## Native loopback acceptance

After installing Npcap with loopback support on a Windows test host:

    .\.venv\Scripts\python.exe -m pytest -m windows_live -q -rs

Set NETPATH_SENTINEL_TEST_PORT to request a specific free TCP port. If it is
unset, the test reserves an available local port. The test starts live capture
and waits for Scapy's capture-socket started callback before starting a local
asyncio TCP listener/client exchange. It verifies observed packet events,
handshake, payload byte counts, persistence, findings, reports, and
listener/capture cleanup. It skips with the detected dependency reason when
Npcap is absent. It does not treat PCAP replay as live verification.

## Manual LAN test

On an authorized isolated test network, select the interface connected to the
test host, start a passive diagnostic for a chosen service port, and wait for
the capture-ready stage. From a second host, run these cases against a
controlled listener: successful connect and short non-sensitive payload;
send the configured heartbeat string; close cleanly (FIN); connect to a
confirmed closed port (refused); try a port with no listener (record the
endpoint's actual response, since timeout and refusal are different outcomes);
and stop an idle capture to verify cancellation. Do not change firewall or
routing settings. Confirm endpoints, handshake and payload events, heartbeat
state, timestamps, evidence references, and cancellation cleanup in the
timeline. Reopen the session from history and verify persistence and exported
HTML/JSON reports. Do not use production credentials or payloads. Record
adapter, Npcap version, Windows build, test endpoints, expected/actual response,
and capture limitations with the release evidence.

Live capture with elevated access and platform-specific driver configurations
still requires a native Windows release run. The desktop application does not
launch with administrative rights by default.
