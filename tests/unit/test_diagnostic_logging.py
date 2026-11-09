import json

from netpath_sentinel.infrastructure import diagnostic_logging


def test_capture_diagnostic_log_is_structured_and_excludes_payload(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(diagnostic_logging, "app_data_dir", lambda: tmp_path)
    error = OSError("Npcap could not open \\Device\\NPF_Loopback")
    path = diagnostic_logging.log_exception(
        "capture_initialization_failed",
        error,
        {
            "selected_interface": "Loopback Pseudo-Interface 1",
            "error_category": "capture_initialization_error",
        },
    )

    assert path is not None and path.is_file()
    record = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert record["event"] == "capture_initialization_failed"
    assert record["diagnostics"]["selected_interface"] == "Loopback Pseudo-Interface 1"
    assert record["exception"].startswith("OSError:")
    assert "payload" not in record
    if __import__("os").name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_logging_failure_is_non_destructive_and_reported_as_unavailable(tmp_path, monkeypatch) -> None:
    target = tmp_path / "missing-parent" / "logs"

    def fail_path() -> object:
        raise PermissionError("denied")

    monkeypatch.setattr(diagnostic_logging, "diagnostic_log_path", fail_path)
    assert diagnostic_logging.log_exception("event", RuntimeError("failure"), {}) is None
    assert not target.exists()
