# Architecture

The project is a modular monolith. Domain models and analysis are UI-independent. Application workflows orchestrate read-only inspection, capture, evidence correlation, RCA, and reports. Infrastructure owns OS-specific inspection, Scapy capture/replay, and SQLite persistence. The presentation layer is PySide6/Qt Widgets and never fabricates live observations.

Capture is bounded by duration, packet count, and payload preview size. Missing capture, permission errors, and unsupported OS functionality are represented as structured statuses rather than converted into network conclusions.
