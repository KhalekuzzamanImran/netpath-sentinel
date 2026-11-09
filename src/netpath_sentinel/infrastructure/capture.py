import queue
import struct
import sys
import threading
import time
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from getpass import getuser
from pathlib import Path
from typing import Any

from netpath_sentinel.domain.models import PacketEvent
from netpath_sentinel.infrastructure.windows_capture import (
    CaptureBackendError,
    resolve_windows_interface,
    windows_capture_diagnostics,
)

IS_WINDOWS = sys.platform == "win32"


class BoundedPacketQueue:
    """Thread-safe packet handoff with an explicit overflow counter."""

    def __init__(self, capacity: int = 512) -> None:
        if capacity < 1:
            raise ValueError("packet queue capacity must be positive")
        self._items: queue.Queue[PacketEvent] = queue.Queue(maxsize=capacity)
        self.dropped = 0

    def offer(self, packet: PacketEvent) -> None:
        try:
            self._items.put_nowait(packet)
        except queue.Full:
            self.dropped += 1

    def get(self, timeout: float = 0.1) -> PacketEvent:
        return self._items.get(timeout=timeout)

    def empty(self) -> bool:
        return self._items.empty()


def packet_from_scapy(
    packet: Any, number: int | None = None, capture_payload: bool = False
) -> PacketEvent | None:
    """Normalize IPv4/IPv6 TCP packets without assuming Ethernet framing."""
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
    except ImportError as exc:
        raise RuntimeError("Scapy is required for packet parsing") from exc
    if not packet.haslayer(TCP):
        return None
    if packet.haslayer(IP):
        network = packet[IP]
    elif packet.haslayer(IPv6):
        network = packet[IPv6]
    else:
        return None
    tcp = packet[TCP]
    payload = bytes(tcp.payload)
    flags = str(tcp.flags)
    return PacketEvent(
        timestamp=packet.time,
        src_ip=network.src,
        src_port=int(tcp.sport),
        dst_ip=network.dst,
        dst_port=int(tcp.dport),
        flags=flags,
        sequence=int(tcp.seq) if hasattr(tcp, "seq") else None,
        acknowledgement=int(tcp.ack) if hasattr(tcp, "ack") else None,
        payload_length=len(payload),
        payload_preview_hex=payload[:128].hex() if capture_payload else None,
        payload_data=payload if capture_payload else b"",
        packet_number=number,
    )


def replay_pcap(path: Path, capture_payload: bool = False) -> Iterator[PacketEvent]:
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"}:
        yield from replay_raw_pcap(path, capture_payload)
        return
    try:
        from scapy.utils import PcapReader

        with PcapReader(str(path)) as reader:
            for number, packet in enumerate(reader, start=1):
                normalized = packet_from_scapy(packet, number, capture_payload)
                if normalized:
                    yield normalized
        return
    except (ImportError, PermissionError, OSError):
        yield from replay_raw_pcap(path, capture_payload)


def replay_raw_pcap(path: Path, capture_payload: bool = False) -> Iterator[PacketEvent]:
    """Minimal offline parser for classic Ethernet/IPv4/TCP PCAP files.

    This fallback keeps replay usable when Scapy cannot initialize host interfaces.
    It intentionally rejects unsupported link types instead of guessing.
    """
    with path.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24:
            raise ValueError("invalid PCAP global header")
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            raise ValueError("unsupported PCAP format; PCAPNG requires Scapy")
        _, _, _, _, _, link_type = struct.unpack(endian + "HHIIII", header[4:])
        if link_type != 1:
            raise ValueError(f"unsupported PCAP link type {link_type}; expected Ethernet")
        number = 0
        while record := stream.read(16):
            if len(record) != 16:
                raise ValueError("truncated PCAP record header")
            seconds, micros, included, _ = struct.unpack(endian + "IIII", record)
            frame = stream.read(included)
            if len(frame) != included:
                raise ValueError("truncated PCAP packet")
            event = packet_from_ethernet_ipv4_tcp(
                frame,
                datetime.fromtimestamp(seconds + micros / 1_000_000, UTC),
                number + 1,
                capture_payload,
            )
            if event:
                number += 1
                yield event


def packet_from_ethernet_ipv4_tcp(
    frame: bytes, timestamp: datetime, number: int, capture_payload: bool = False
) -> PacketEvent | None:
    if len(frame) < 14:
        return None
    ip_start = 14
    ethertype = int.from_bytes(frame[12:14], "big")
    while ethertype in {0x8100, 0x88A8, 0x9100}:
        if len(frame) < ip_start + 4:
            return None
        ethertype = int.from_bytes(frame[ip_start + 2:ip_start + 4], "big")
        ip_start += 4
    if ethertype != 0x0800:
        return None
    if len(frame) < ip_start + 20:
        raise ValueError("truncated IPv4 header")
    version_ihl = frame[ip_start]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20:
        raise ValueError("invalid IPv4 header length")
    if len(frame) < ip_start + ip_header_length + 20:
        raise ValueError("truncated TCP header")
    if frame[ip_start + 9] != 6:
        return None
    source = ".".join(str(part) for part in frame[ip_start + 12 : ip_start + 16])
    destination = ".".join(str(part) for part in frame[ip_start + 16 : ip_start + 20])
    tcp_start = ip_start + ip_header_length
    source_port, destination_port, sequence, acknowledgement = struct.unpack(
        ">HHII", frame[tcp_start : tcp_start + 12]
    )
    data_offset = (frame[tcp_start + 12] >> 4) * 4
    if data_offset < 20 or len(frame) < tcp_start + data_offset:
        raise ValueError("invalid or truncated TCP data offset")
    flags_value = int.from_bytes(frame[tcp_start + 12 : tcp_start + 14], "big") & 0x01FF
    flag_names = [
        (0x001, "F"),
        (0x002, "S"),
        (0x004, "R"),
        (0x008, "P"),
        (0x010, "A"),
        (0x020, "U"),
        (0x040, "E"),
        (0x080, "C"),
        (0x100, "N"),
    ]
    flags = "".join(name for bit, name in flag_names if flags_value & bit)
    payload = frame[tcp_start + data_offset :]
    return PacketEvent(
        timestamp=timestamp,
        src_ip=source,
        src_port=source_port,
        dst_ip=destination,
        dst_port=destination_port,
        flags=flags,
        sequence=sequence,
        acknowledgement=acknowledgement,
        payload_length=len(payload),
        payload_preview_hex=payload[:128].hex() if capture_payload else None,
        payload_data=payload if capture_payload else b"",
        packet_number=number,
    )


def capture_live(
    interface: str, duration: int, port: int, max_packets: int, packet_filter: str | None = None,
    stop_event: threading.Event | None = None,
    packet_queue: BoundedPacketQueue | None = None,
    ready_event: threading.Event | None = None,
    capture_payload: bool = False,
) -> Iterable[PacketEvent]:
    diagnostics: dict[str, Any] | None = None
    selected_interface = interface
    if IS_WINDOWS:
        diagnostics = windows_capture_diagnostics()
        diagnostics = dict(diagnostics)
        diagnostics["selected_interface"] = selected_interface
        diagnostics["process_user"] = getuser()
        diagnostics["process_is_admin"] = _is_windows_admin()
        if not diagnostics["available"]:
            raise CaptureBackendError(
                "Windows packet capture is unavailable in this process. "
                f"{diagnostics['reason']} Npcap is installed separately and is not bundled.",
                diagnostics,
            )
        try:
            from scapy.all import conf
            from scapy.arch.windows import get_windows_if_list

            interface_names = get_windows_if_list()
            resolved_device = resolve_windows_interface(interface, interface_names)
            diagnostics["resolved_capture_device"] = resolved_device
            scapy_interface: Any = conf.ifaces.dev_from_networkname(resolved_device)
            if scapy_interface is None:
                raise ValueError(
                    f"Scapy did not enumerate Npcap device {resolved_device!r}"
                )
            interface = scapy_interface
            diagnostics["scapy_interface"] = {
                "name": scapy_interface.name,
                "description": scapy_interface.description,
                "network_name": scapy_interface.network_name,
                "index": scapy_interface.index,
            }
            diagnostics["capture_backend"] = getattr(
                conf.L2listen, "__name__", type(conf.L2listen).__name__
            )
            try:
                import scapy

                diagnostics["scapy_version"] = scapy.__version__
            except (ImportError, AttributeError):
                diagnostics["scapy_version"] = "unknown"
        except (ImportError, OSError, ValueError, KeyError, AttributeError) as exc:
            diagnostics["error_category"] = (
                "unsupported_interface" if isinstance(exc, ValueError) else "backend_load_error"
            )
            diagnostics["exception_type"] = type(exc).__name__
            diagnostics["exception_message"] = str(exc)
            raise CaptureBackendError(
                _capture_error_message(diagnostics["error_category"], selected_interface, exc),
                diagnostics,
            ) from exc
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError("Scapy is required for live capture") from exc
    captured: list[PacketEvent] = []
    packet_count = 0
    bpf = packet_filter or f"tcp port {port}"
    deadline = time.monotonic() + duration
    while packet_count < max_packets and time.monotonic() < deadline:
        if stop_event and stop_event.is_set():
            break
        def on_packet(raw_packet: Any) -> None:
            nonlocal packet_count
            packet_count += 1
            event = packet_from_scapy(raw_packet, packet_count, capture_payload)
            if event is None:
                return
            if packet_queue is not None:
                packet_queue.offer(event)
            else:
                captured.append(event)

        def on_started() -> None:
            if ready_event:
                ready_event.set()

        try:
            sniff(
                iface=interface,
                filter=bpf,
                timeout=min(0.25, max(0.01, deadline - time.monotonic())),
                count=max_packets - packet_count,
                store=False,
                prn=on_packet,
                started_callback=on_started,
            )
        except Exception as exc:
            if diagnostics is None:
                raise
            diagnostics = dict(diagnostics)
            category = _classify_capture_error(exc)
            diagnostics["error_category"] = category
            diagnostics["exception_type"] = type(exc).__name__
            diagnostics["exception_message"] = str(exc)
            diagnostics["exception_errno"] = getattr(exc, "errno", None)
            diagnostics["exception_winerror"] = getattr(exc, "winerror", None)
            diagnostics["capture_permissions"] = (
                "denied" if category == "permission_denied" else "not established"
            )
            raise CaptureBackendError(
                _capture_error_message(category, selected_interface, exc),
                diagnostics,
            ) from exc
    return captured


def _is_windows_admin() -> bool | None:
    if not IS_WINDOWS:
        return None
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return None


def _classify_capture_error(error: Exception) -> str:
    message = str(error).casefold()
    winerror = getattr(error, "winerror", None)
    if isinstance(error, PermissionError) or getattr(error, "errno", None) in {5, 13} or winerror == 5:
        return "permission_denied"
    if winerror in {2, 1167} or "no such device" in message or "device not found" in message:
        return "unsupported_interface"
    if winerror in {126, 127} or "dll" in message or "wpcap" in message:
        return "npcap_runtime_load_error"
    if "filter" in message or "bpf" in message:
        return "invalid_capture_filter"
    return "capture_initialization_error"


def _capture_error_message(category: str, interface: str, error: Exception) -> str:
    if category == "unsupported_interface":
        return (
            f"The selected adapter {interface!r} is not available to Scapy/Npcap. "
            "Refresh the interface list and select an enumerated adapter. "
            f"Details: {error}"
        )
    if category == "permission_denied":
        return (
            f"Npcap denied access to {interface!r}. Check the installed Npcap access "
            "policy for this user; NetPath Sentinel will not elevate itself. "
            f"Details: {error}"
        )
    if category == "invalid_capture_filter":
        return f"Npcap rejected the TCP capture filter for {interface!r}: {error}"
    if category == "npcap_runtime_load_error":
        return f"The installed Npcap runtime could not be loaded: {error}"
    return f"Capture initialization failed for {interface!r}: {error}"
