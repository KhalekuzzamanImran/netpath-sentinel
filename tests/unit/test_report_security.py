import os

from netpath_sentinel.reporting.report import export_html, export_json


def test_exports_redact_nested_payload_and_stream_fields(tmp_path) -> None:
    payload = {
        "packets": [{"payload_preview_hex": "736563726574", "payload_length": 6}],
        "tcp_sessions": [{"stream_client_to_server": "736563726574", "observed_state": "established"}],
    }
    json_path = export_json(tmp_path / "report.json", payload)
    html_path = export_html(tmp_path / "report.html", "Safe <report>", payload)
    encoded = json_path.read_text()
    markup = html_path.read_text()
    assert "736563726574" not in encoded
    assert "payload_preview_hex" not in encoded
    assert "736563726574" not in markup
    assert "Safe &lt;report&gt;" in markup


def test_report_file_permissions_are_private_on_posix(tmp_path) -> None:
    if os.name == "nt":
        return
    path = export_json(tmp_path / "private" / "report.json", {"ok": True})
    assert path.stat().st_mode & 0o777 == 0o600


def test_executive_and_technical_reports_are_structured_self_contained_and_redacted(tmp_path) -> None:
    payload = {
        "session_id": "session-12",
        "metrics": {"tcp_sessions": 1, "packets_observed": 3, "retransmissions": 0, "findings": 1},
        "steps": [{"name": "Capture", "status": "passed", "purpose": "Observe TCP"}],
        "findings": [
            {
                "code": "TCP_HANDSHAKE_COMPLETE",
                "severity": "info",
                "confidence": "confirmed",
                "conclusion": "A three-way handshake was observed.",
                "supporting_evidence_ids": ["ev-1"],
                "alternatives": [],
                "limitations": ["Endpoint observation only."],
                "recommended_verification": "Review payload exchange.",
                "next_action": "Inspect application response.",
            }
        ],
        "routes": [{"destination": "0.0.0.0/0", "interface": "Wi-Fi"}],
        "packet_timeline": [{"flags": "PA", "payload_preview_hex": "736563726574"}],
    }
    executive = export_html(
        tmp_path / "executive.html", "Executive summary", payload, report_kind="executive"
    )
    technical = export_html(
        tmp_path / "technical.html", "Technical details", payload, report_kind="technical"
    )
    executive_markup = executive.read_text(encoding="utf-8")
    technical_markup = technical.read_text(encoding="utf-8")

    assert "Executive report" in executive_markup and "Key metrics" in executive_markup
    assert "Diagnostic steps" in executive_markup and "Next action" in executive_markup
    assert "Technical report" in technical_markup and "Packet timeline" in technical_markup
    assert "Routes" in technical_markup and "supporting_evidence_ids" in technical_markup
    assert "736563726574" not in executive_markup + technical_markup
    assert "<style>" in executive_markup and "https://" not in executive_markup
