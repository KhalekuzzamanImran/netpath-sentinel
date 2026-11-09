import html
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def export_json(path: Path, payload: dict[str, Any], sanitize: bool = True) -> Path:
    data = _redact(payload) if sanitize else payload
    _write_private(path, json.dumps(data, indent=2, default=str))
    return path


def export_html(path: Path, title: str, payload: dict[str, Any]) -> Path:
    payload = _redact(payload)
    rows = "".join(
        f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>"
        for k, v in payload.items()
    )
    _write_private(
        path,
        f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
        f"<style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse}}th,td{{padding:.5rem;border:1px solid #ccc;text-align:left}}</style></head>"
        f"<body><h1>{html.escape(title)}</h1><table>{rows}</table></body></html>",
    )
    return path


_SENSITIVE_KEYS = {"payload", "payload_data", "payload_preview_hex", "stream_client_to_server", "stream_server_to_client"}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items() if key.lower() not in _SENSITIVE_KEYS}
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    return value


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            if os.name != "nt":
                os.chmod(temporary_name, 0o600)
            stream.write(content)
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
