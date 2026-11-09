# Architecture

The project is a modular monolith. Domain models and analysis are UI-independent. Application workflows orchestrate read-only inspection, capture, evidence correlation, RCA, and reports. Infrastructure owns OS-specific inspection, Scapy capture/replay, and SQLite persistence. The presentation layer is PySide6/Qt Widgets and never fabricates live observations.

Live capture runs in a worker thread with bounded 250 ms Scapy capture calls.
Normalized packets enter a fixed-capacity, thread-safe queue and the async
workflow drains that queue while capture is active. Each dequeued packet updates
the TCP tracker and is persisted. Workflow events then pass through a second
bounded worker-to-UI queue, which a GUI timer drains in batches. Queue overflow
at the capture boundary increments an explicit counter included in packet-summary
evidence. Cancellation sets a thread-safe stop event, lets the current bounded
capture call return, drains partial queued packets, and emits a terminal
cancellation event.

The Qt main thread only renders events from its bounded queue; capture and
persistence work remain in the diagnostic worker. Per-session packet retention and TCP stream
reconstruction have configured caps. Capture is bounded by duration, packet
count, queue capacity, and payload preview size. Missing capture, permission
errors, and unsupported OS functionality are represented as structured statuses
rather than converted into network conclusions.

Development uses CPython 3.12–3.14 and the committed uv.lock file. See
development-setup.md for platform setup, testing, and troubleshooting commands.
