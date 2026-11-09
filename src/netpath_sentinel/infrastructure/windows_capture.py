"""Windows Npcap diagnostics and friendly-name to NPF-device mapping."""

import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

_DLL_DIRECTORY_HANDLES: list[Any] = []


class CaptureBackendError(RuntimeError):
    def __init__(self, message: str, diagnostics: dict[str, Any]) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics


def _npcap_service_registered() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\npcap",
        ):
            return True
    except (ImportError, OSError):
        return False


def _npcap_service_state() -> str:
    if sys.platform != "win32":
        return "not applicable"
    try:
        result = subprocess.run(
            ["sc.exe", "query", "npcap"],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError):
        return "query unavailable"
    if result.returncode:
        return "not installed or query denied"
    match = re.search(r"STATE\s*:\s*\d+\s+(\w+)", result.stdout, re.IGNORECASE)
    return match.group(1).lower() if match else "unknown"
def _library_paths() -> tuple[list[Path], list[Path]]:
    windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    directories = [
        windows / "System32" / "Npcap",
        windows / "System32",
        program_files / "Npcap",
    ]
    return (
        [directory / "wpcap.dll" for directory in directories],
        [directory / "Packet.dll" for directory in directories],
    )


def _prepare_npcap_runtime() -> tuple[bool, str | None, bool, str | None]:
    """Load system Npcap DLLs before Scapy initializes its libpcap backend."""
    if sys.platform != "win32":
        return False, None, False, "Npcap is only supported on Windows."
    wpcap_paths, packet_paths = _library_paths()
    wpcap = next((path for path in wpcap_paths if path.is_file()), None)
    packet = next((path for path in packet_paths if path.is_file()), None)
    if not wpcap or not packet:
        return bool(wpcap), str(wpcap) if wpcap else None, False, "Npcap DLL files are missing."

    npcap_directory = str(wpcap.parent)
    add_dll_directory = getattr(os, "add_dll_directory", None)
    if add_dll_directory and not any(
        str(getattr(handle, "path", "")).casefold() == npcap_directory.casefold()
        for handle in _DLL_DIRECTORY_HANDLES
    ):
        try:
            _DLL_DIRECTORY_HANDLES.append(add_dll_directory(npcap_directory))
        except OSError as exc:
            return True, str(wpcap), False, f"Could not add Npcap DLL directory: {exc}"
    try:
        import ctypes

        ctypes.WinDLL(str(packet))
        ctypes.WinDLL(str(wpcap))
    except (AttributeError, OSError) as exc:
        return True, str(wpcap), False, f"Could not load Npcap DLLs: {exc}"
    return True, str(wpcap), True, None


def windows_capture_diagnostics() -> dict[str, Any]:
    """Return dependency, driver, interface and permission-check status."""
    if sys.platform != "win32":
        return {
            "platform": sys.platform,
            "supported": False,
            "available": False,
            "reason": "Windows Npcap diagnostics requested on a non-Windows platform.",
            "interfaces": [],
        }

    dll_files_present, wpcap_path, dlls_loadable, dll_load_error = _prepare_npcap_runtime()
    interface_error: str | None
    try:
        from scapy.all import conf
        from scapy.arch.windows import get_windows_if_list

        adapters = [
            adapter
            for adapter in get_windows_if_list()
            if adapter.get("ips") or adapter.get("type") == 24
        ]
    except (ImportError, OSError) as exc:
        adapters = []
        interface_error = str(exc)
        pcap_backend_available = False
        pcap_backend = "unavailable"
    else:
        interface_error = None
        pcap_backend_available = bool(conf.use_pcap)
        pcap_backend = getattr(conf.L2listen, "__name__", type(conf.L2listen).__name__)

    _wpcap_paths, packet_paths = _library_paths()
    wpcap = Path(wpcap_path) if wpcap_path else None
    packet = next((path for path in packet_paths if path.is_file()), None)
    service_registered = _npcap_service_registered()
    driver_paths = [
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "drivers" / "npcap.sys",
        Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "drivers" / "npf.sys",
    ]
    driver = next((path for path in driver_paths if path.is_file()), None)
    return build_windows_capture_diagnostics(
        wpcap,
        packet,
        service_registered,
        driver,
        adapters,
        interface_error,
        _npcap_service_state(),
        dll_files_present=dll_files_present,
        dlls_loadable=dlls_loadable,
        dll_load_error=dll_load_error,
        pcap_backend_available=pcap_backend_available,
        pcap_backend=pcap_backend,
    )


def build_windows_capture_diagnostics(
    wpcap: Path | None,
    packet: Path | None,
    service_registered: bool,
    driver: Path | None,
    adapters: list[dict[str, Any]],
    interface_error: str | None = None,
    service_state: str = "not queried",
    *,
    dll_files_present: bool | None = None,
    dlls_loadable: bool = True,
    dll_load_error: str | None = None,
    pcap_backend_available: bool = True,
    pcap_backend: str = "libpcap",
) -> dict[str, Any]:
    """Build stable structured status from platform probes."""
    available = bool(
        wpcap
        and packet
        and service_registered
        and driver
        and dlls_loadable
        and pcap_backend_available
    )
    reasons: list[str] = []
    if not service_registered:
        reasons.append("Npcap service is not registered.")
    if not driver:
        reasons.append("Npcap kernel driver file was not found.")
    if not wpcap:
        reasons.append("wpcap.dll was not found.")
    if not packet:
        reasons.append("Packet.dll was not found.")
    if not dlls_loadable:
        reasons.append(dll_load_error or "Npcap DLLs could not be loaded by this process.")
    if not pcap_backend_available:
        reasons.append("Scapy could not initialize its libpcap/Npcap capture backend.")
    if interface_error:
        reasons.append(f"Windows interface enumeration failed: {interface_error}")
    return {
        "platform": "win32",
        "supported": True,
        "available": available,
        "service_registered": service_registered,
        "service_state": service_state,
        "driver_path": str(driver) if driver else None,
        "wpcap_path": str(wpcap) if wpcap else None,
        "packet_path": str(packet) if packet else None,
        "dll_files_present": bool(dll_files_present if dll_files_present is not None else wpcap and packet),
        "dlls_loadable": dlls_loadable,
        "dll_load_error": dll_load_error,
        "scapy_pcap_backend_available": pcap_backend_available,
        "capture_backend": pcap_backend,
        "capture_permissions": "not tested",
        "reason": "Npcap runtime detected." if available else " ".join(reasons),
        "interfaces": [
            {
                "name": item.get("name"),
                "description": item.get("description"),
                "guid": item.get("guid"),
                "npf_device": _npf_device(item),
                "addresses": item.get("ips", []),
            }
            for item in adapters
        ],
    }


def _npf_device(adapter: dict[str, Any]) -> str | None:
    network_name = adapter.get("network_name")
    if network_name and str(network_name).casefold().startswith(r"\device\npf_"):
        return str(network_name)
    if str(adapter.get("name", "")).casefold() in {
        "loopback",
        "loopback pseudo-interface 1",
    } or adapter.get("type") == 24:
        return r"\Device\NPF_Loopback"
    guid = adapter.get("guid")
    if not guid:
        return None
    return rf"\Device\NPF_{str(guid).strip('{}')}"


def resolve_windows_interface(name: str, adapters: list[dict[str, Any]]) -> str:
    """Resolve a UI/host adapter name to Scapy's NPF device path."""
    requested = name.strip().casefold()
    for adapter in adapters:
        candidates = (
            adapter.get("name"),
            adapter.get("description"),
            adapter.get("guid"),
            adapter.get("network_name"),
        )
        if any(value and str(value).strip().casefold() == requested for value in candidates):
            device = _npf_device(adapter)
            if device:
                return device
    if requested.startswith(r"\device\npf_"):
        for adapter in adapters:
            device = _npf_device(adapter)
            if device and device.casefold() == requested:
                return device
    raise ValueError(f"Windows capture interface {name!r} was not found.")
