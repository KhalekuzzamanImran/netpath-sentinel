# Phase 9 two-host LAN acceptance

This procedure requires two hosts on a network you are authorized to test. It
does not change firewall, routing, or host security configuration. Use a port
approved for testing and the actual interface that faces the peer. The helper
records socket outcomes separately from captured packet observations and does
not print payload contents.

## Preconditions

1. On the capture host, install and verify the platform capture dependency.
   On Windows this means a working Npcap installation and the mapped adapter.
2. On both hosts, create a disposable evidence directory. Keep the diagnostic
   database and reports private because endpoint metadata is sensitive.
3. From the capture host, select an explicit interface and choose the TCP test
   port. Do not use `0.0.0.0` as a capture interface or a peer address.
4. Run the commands from the repository root with the project environment:

   ```powershell
   .venv\Scripts\python.exe tools\lan_acceptance.py --help
   ```

   ```bash
   .venv/bin/python tools/lan_acceptance.py --help
   ```

## Controlled successful connection, payload, heartbeat, and FIN

On the destination host, bind only its authorized LAN address. Substitute the
selected address and unused port:

```text
python tools/lan_acceptance.py listen --bind <destination-LAN-IP> --port <PORT> --duration 180
```

On the capture host, start capture first. `--interface` must be the exact
interface name exposed by the application on that OS:

```text
python tools/lan_acceptance.py capture --interface "<CAPTURE-INTERFACE>" --port <PORT> --destination-ip <destination-LAN-IP> --duration 90 --data-dir ./phase9-lan-evidence
```

After the capture helper reports `capture_preparation` passed, run from the
source host:

```text
python tools/lan_acceptance.py send --host <destination-LAN-IP> --port <PORT> --mode send --payload "PHASE9-KNOWN-PAYLOAD" --heartbeat-interval 2 --heartbeat-duration 8
```

Expected packet-side evidence is SYN, SYN-ACK, ACK, payload in the source to
destination direction, then FIN/ACK termination, subject to the selected
capture point and offload behavior. The listener reports bytes, heartbeat line
count, and EOF/reset status. The capture command emits session, evidence,
finding, and terminal events as JSON. It prints final SQLite and HTML/JSON
report paths. Verify those records and report contents before marking this
scenario passed.

## Refusal and no listener

Stop the listener, then run the capture command for the selected port and probe
from the source host:

```text
python tools/lan_acceptance.py send --host <destination-LAN-IP> --port <PORT> --mode probe --expect refused
```

The helper's `refused` is a source socket result. Packet capture may observe a
SYN followed by RST/ACK, or may miss the response depending on capture point.
Do not infer that a firewall or gateway generated a packet unless it is
independently observed and attributable.

## Abrupt reset

Restart the listener and capture. From the source host, use:

```text
python tools/lan_acceptance.py send --host <destination-LAN-IP> --port <PORT> --mode reset
```

Check the listener's reset observation and captured RST flags separately.

## Cancellation and no-response attempt

For active-traffic cancellation, start the listener and capture, run repeated
authorized sends during the capture, then press Ctrl+C in the capture process.
For idle cancellation, start capture without generating traffic and press
Ctrl+C. Confirm the terminal status is cancelled, partial evidence remains,
and the capture process exits. For a no-response observation, use only an
explicitly authorized destination/port; record the source-side timeout and
whether the chosen capture point observed SYN or any response. A timeout does
not establish where packets were lost.

## Evidence checklist

Record OS/build, app version, privilege level, selected capture interface,
local and peer addresses, port, UTC interval, socket-side outcomes, captured
flags/tuple/directions, TCP session state, payload byte counts, live UI update,
database integrity, evidence references, RCA finding/confidence, and report
paths. Redact host identifiers before sharing. Never record or publish the
known payload if it contains real user data.

## Phase 9 execution status

No second authorized LAN peer was confirmed in the Phase 9 environment, so no
LAN traffic was generated or claimed. Windows Npcap loopback acceptance is
separate evidence and does not satisfy this procedure. The helper's `--help`
smoke check passed; the end-to-end two-host acceptance remains **blocked**
until an authorized peer and capture interface are supplied.
