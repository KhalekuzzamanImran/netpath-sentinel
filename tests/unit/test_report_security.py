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
