from pathlib import Path
from types import SimpleNamespace

import pytest

from netpath_sentinel.infrastructure import capture
from netpath_sentinel.infrastructure.capture import packet_from_scapy
from netpath_sentinel.infrastructure.windows_capture import (
    CaptureBackendError,
    build_windows_capture_diagnostics,
    resolve_windows_interface,
)


def test_missing_npcap_dependencies_are_structured() -> None:
    diagnostics = build_windows_capture_diagnostics(
        None, None, False, None, [{"name": "Wi-Fi", "guid": "{abc}"}]
    )
    assert not diagnostics["available"]
    assert diagnostics["service_registered"] is False
    assert "wpcap.dll was not found" in diagnostics["reason"]
    assert diagnostics["interfaces"][0]["npf_device"] == r"\Device\NPF_abc"


def test_windows_friendly_interface_maps_to_npf_device() -> None:
    adapters = [
        {"name": "Wi-Fi", "description": "Intel Adapter", "guid": "{1234-abcd}"},
    ]
    assert resolve_windows_interface("Wi-Fi", adapters) == r"\Device\NPF_1234-abcd"
    assert resolve_windows_interface(
        "Loopback Pseudo-Interface 1",
        [{"name": "Loopback Pseudo-Interface 1", "type": 24}],
    ) == (
        r"\Device\NPF_Loopback"
    )
    with pytest.raises(ValueError, match="was not found"):
        resolve_windows_interface("missing", adapters)


def test_windows_interface_uses_scappy_network_name_when_available() -> None:
    adapter = {
        "name": "Loopback Pseudo-Interface 1",
        "guid": "{loopback-guid}",
        "network_name": r"\Device\NPF_Loopback",
        "type": 24,
    }
    assert resolve_windows_interface("Loopback Pseudo-Interface 1", [adapter]) == (
        r"\Device\NPF_Loopback"
    )
    assert resolve_windows_interface(r"\Device\NPF_Loopback", [adapter]) == (
        r"\Device\NPF_Loopback"
    )
    with pytest.raises(ValueError, match="was not found"):
        resolve_windows_interface(r"\Device\NPF_{not-enumerated}", [adapter])


def test_loopback_diagnostics_map_to_npcap_loopback_adapter() -> None:
    diagnostics = build_windows_capture_diagnostics(
        None,
        None,
        False,
        None,
        [{"name": "Loopback Pseudo-Interface 1", "guid": "{1234}"}],
    )
    assert diagnostics["interfaces"][0]["npf_device"] == r"\Device\NPF_Loopback"


def test_windows_capture_fails_with_actionable_error_when_npcap_missing(monkeypatch) -> None:
    monkeypatch.setattr(capture, "IS_WINDOWS", True)
    monkeypatch.setattr(
        capture,
        "windows_capture_diagnostics",
        lambda: build_windows_capture_diagnostics(
            None, None, False, None, [], "adapter probe unavailable"
        ),
    )
    with pytest.raises(CaptureBackendError, match="packet capture is unavailable") as error:
        capture.capture_live("Wi-Fi", 1, 6000, 10)
    assert error.value.diagnostics["available"] is False


def test_available_windows_capture_status_requires_all_runtime_parts() -> None:
    paths = [Path("wpcap.dll"), Path("Packet.dll"), Path("npcap.sys")]
    diagnostics = build_windows_capture_diagnostics(
        paths[0], paths[1], True, paths[2], []
    )
    assert diagnostics["available"]


def test_capture_runtime_requires_loadable_dlls_and_scapy_pcap_backend() -> None:
    paths = [Path("wpcap.dll"), Path("Packet.dll"), Path("npcap.sys")]
    diagnostics = build_windows_capture_diagnostics(
        paths[0],
        paths[1],
        True,
        paths[2],
        [],
        dlls_loadable=False,
        dll_load_error="WinError 126",
    )
    assert not diagnostics["available"]
    assert "WinError 126" in diagnostics["reason"]

    diagnostics = build_windows_capture_diagnostics(
        paths[0], paths[1], True, paths[2], [], pcap_backend_available=False
    )
    assert not diagnostics["available"]
    assert "libpcap/Npcap capture backend" in diagnostics["reason"]


def test_windows_capture_error_categories_are_actionable(monkeypatch) -> None:
    monkeypatch.setattr(capture, "IS_WINDOWS", True)
    monkeypatch.setattr(
        capture,
        "windows_capture_diagnostics",
        lambda: build_windows_capture_diagnostics(
            Path("wpcap.dll"), Path("Packet.dll"), True, Path("npcap.sys"), []
        ),
    )

    class Interfaces:
        def get_windows_if_list(self):
            return [{"name": "Loopback Pseudo-Interface 1", "type": 24}]

    class Conf:
        use_pcap = True

        class L2listen:
            pass

        class Ifaces:
            def dev_from_networkname(self, _name):
                return SimpleNamespace(
                    name="Loopback Pseudo-Interface 1",
                    description="Software Loopback Interface 1",
                    network_name=r"\Device\NPF_Loopback",
                    index=1,
                )

        ifaces = Ifaces()

    class Scapy:
        __version__ = "test"

    monkeypatch.setitem(
        __import__("sys").modules, "scapy.all", type("ScapyAll", (), {"conf": Conf})
    )
    monkeypatch.setitem(
        __import__("sys").modules,
        "scapy.arch.windows",
        type("WindowsArch", (), {"get_windows_if_list": Interfaces().get_windows_if_list}),
    )
    monkeypatch.setitem(__import__("sys").modules, "scapy", Scapy)
    monkeypatch.setattr(capture, "_is_windows_admin", lambda: False)
    monkeypatch.setattr(capture.time, "monotonic", lambda: 1.0)

    class BadSniff:
        def __call__(self, **_kwargs):
            raise PermissionError("Npcap access denied")

    monkeypatch.setitem(
        __import__("sys").modules,
        "scapy.all",
        type("ScapyAll", (), {"conf": Conf, "sniff": BadSniff()}),
    )
    with pytest.raises(CaptureBackendError, match="Npcap denied access") as error:
        capture.capture_live("Loopback Pseudo-Interface 1", 1, 6000, 10)
    assert error.value.diagnostics["error_category"] == "permission_denied"
    assert error.value.diagnostics["selected_interface"] == "Loopback Pseudo-Interface 1"
    assert error.value.diagnostics["process_is_admin"] is False


def test_packet_payload_preview_requires_explicit_capture_setting() -> None:
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    raw_packet = IP(src="192.0.2.1", dst="192.0.2.2") / TCP(sport=41000, dport=6000) / Raw(
        b"secret-test-payload"
    )
    redacted = packet_from_scapy(raw_packet)
    retained = packet_from_scapy(raw_packet, capture_payload=True)
    assert redacted is not None and retained is not None
    assert redacted.payload_length == len(b"secret-test-payload")
    assert redacted.payload_preview_hex is None
    assert redacted.payload_data == b""
    assert retained.payload_preview_hex == b"secret-test-payload".hex()
