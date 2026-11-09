import struct
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netpath_sentinel.domain.models import PacketEvent


def packet_from_scapy(packet: Any, number: int | None = None) -> PacketEvent | None:
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
        payload_preview_hex=payload[:128].hex(),
        packet_number=number,
    )


def replay_pcap(path: Path) -> Iterator[PacketEvent]:
    with path.open("rb") as stream:
        magic = stream.read(4)
    if magic in {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"}:
        yield from replay_raw_pcap(path)
        return
    try:
        from scapy.utils import PcapReader

        with PcapReader(str(path)) as reader:
            for number, packet in enumerate(reader, start=1):
                normalized = packet_from_scapy(packet, number)
                if normalized:
                    yield normalized
        return
    except (ImportError, PermissionError, OSError):
        yield from replay_raw_pcap(path)


def replay_raw_pcap(path: Path) -> Iterator[PacketEvent]:
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
                frame, datetime.fromtimestamp(seconds + micros / 1_000_000, UTC), number + 1
            )
            if event:
                number += 1
                yield event


def packet_from_ethernet_ipv4_tcp(
    frame: bytes, timestamp: datetime, number: int
) -> PacketEvent | None:
    if len(frame) < 14 + 20 or int.from_bytes(frame[12:14], "big") != 0x0800:
        return None
    ip_start = 14
    version_ihl = frame[ip_start]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if len(frame) < ip_start + ip_header_length + 20 or frame[ip_start + 9] != 6:
        return None
    source = ".".join(str(part) for part in frame[ip_start + 12 : ip_start + 16])
    destination = ".".join(str(part) for part in frame[ip_start + 16 : ip_start + 20])
    tcp_start = ip_start + ip_header_length
    source_port, destination_port, sequence, acknowledgement = struct.unpack(
        ">HHII", frame[tcp_start : tcp_start + 12]
    )
    data_offset = (frame[tcp_start + 12] >> 4) * 4
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
        payload_preview_hex=payload[:128].hex(),
        packet_number=number,
    )


def capture_live(
    interface: str, duration: int, port: int, max_packets: int, packet_filter: str | None = None
) -> Iterable[PacketEvent]:
    try:
        from scapy.all import sniff
    except ImportError as exc:
        raise RuntimeError("Scapy is required for live capture") from exc
    captured: list[Any] = []
    bpf = packet_filter or f"tcp port {port}"
    sniff(iface=interface, filter=bpf, timeout=duration, count=max_packets, store=captured)
    return [
        event
        for number, packet in enumerate(captured, start=1)
        if (event := packet_from_scapy(packet, number)) is not None
    ]
