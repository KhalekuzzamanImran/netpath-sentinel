import html
import json
from pathlib import Path
from typing import Any


def export_json(path: Path, payload: dict[str, Any], sanitize: bool = True) -> Path:
    data = dict(payload)
    if sanitize:
        data.pop("payload", None)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path


def export_html(path: Path, title: str, payload: dict[str, Any]) -> Path:
    rows = "".join(
        f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>"
        for k, v in payload.items()
    )
    path.write_text(
        f"<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(title)}</title>"
        f"<style>body{{font-family:system-ui;margin:2rem}}table{{border-collapse:collapse}}th,td{{padding:.5rem;border:1px solid #ccc;text-align:left}}</style></head>"
        f"<body><h1>{html.escape(title)}</h1><table>{rows}</table></body></html>",
        encoding="utf-8",
    )
    return path
