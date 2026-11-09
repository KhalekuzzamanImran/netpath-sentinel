from collections import defaultdict

from netpath_sentinel.domain.models import PacketEvent, TCPSession


class TCPSessionTracker:
    """Deterministic TCP tracker resilient to midstream captures and tuple reuse."""

    def __init__(
        self,
        server_port: int | None = None,
        stream_limit: int = 1_048_576,
        max_sessions: int = 10_000,
        retained_packets_per_session: int = 10_000,
    ) -> None:
        self.server_port = server_port
        self.sessions: list[TCPSession] = []
        self._seen: dict[str, set[tuple[int | None, str]]] = defaultdict(set)
        self.stream_limit = stream_limit
        self.max_sessions = max_sessions
        self.retained_packets_per_session = retained_packets_per_session
        self._segments: dict[str, dict[str, dict[int, bytes]]] = defaultdict(
            lambda: {"client": {}, "server": {}}
        )
        self._acks: dict[str, int | None] = defaultdict(lambda: None)
        self._stream_anchors: dict[str, dict[str, int]] = defaultdict(dict)

    def ingest(self, packet: PacketEvent) -> TCPSession:
        if (
            self.server_port is not None
            and packet.src_port != self.server_port
            and packet.dst_port != self.server_port
        ):
            raise ValueError("packet does not match configured server port")
        if packet.dst_port == self.server_port or (
            self.server_port is None and packet.dst_port < packet.src_port
        ):
            client_ip, client_port, server_ip, server_port = (
                packet.src_ip,
                packet.src_port,
                packet.dst_ip,
                packet.dst_port,
            )
        else:
            client_ip, client_port, server_ip, server_port = (
                packet.dst_ip,
                packet.dst_port,
                packet.src_ip,
                packet.src_port,
            )
        session = self._find(packet, client_ip, client_port, server_ip, server_port)
        if len(session.packets) < self.retained_packets_per_session:
            session.packets.append(packet)
        session.last_seen = packet.timestamp
        if packet.src_ip == client_ip and packet.src_port == client_port:
            session.payload_bytes_client_to_server += packet.payload_length
        else:
            session.payload_bytes_server_to_client += packet.payload_length
        key = (packet.sequence, packet.flags)
        if packet.payload_length and key in self._seen[session.id]:
            session.retransmissions += 1
        if len(self._seen[session.id]) < self.retained_packets_per_session:
            self._seen[session.id].add(key)
        self._update_handshake(session, packet)
        self._update_stream(session, packet, client_ip, client_port)
        return session

    def _update_stream(
        self, session: TCPSession, packet: PacketEvent, client_ip: str, client_port: int
    ) -> None:
        client_direction = packet.src_ip == client_ip and packet.src_port == client_port
        direction = "client" if client_direction else "server"
        data = packet.payload_data[:self.stream_limit]
        retained_bytes = sum(
            len(segment)
            for direction_segments in self._segments[session.id].values()
            for segment in direction_segments.values()
        )
        data = data[: max(0, self.stream_limit * 2 - retained_bytes)]
        if data and packet.sequence is not None:
            seq = (packet.sequence + (1 if "S" in packet.flags else 0)) & 0xFFFFFFFF
            anchors = self._stream_anchors[session.id]
            anchor = anchors.setdefault(direction, seq)
            # TCP sequence numbers use serial arithmetic; signed offsets preserve wrap order.
            seq = ((seq - anchor + 0x80000000) & 0xFFFFFFFF) - 0x80000000
            segments = self._segments[session.id][direction]
            if seq in segments:
                session.retransmissions += 1
            elif sum(
                len(segment)
                for direction_segments in self._segments[session.id].values()
                for segment in direction_segments.values()
            ) < self.stream_limit * 2:
                if segments and seq < max(segments):
                    session.out_of_order_segments += 1
                segments[seq] = data
                # First-seen bytes win for overlap safety; only append contiguous ranges.
                ordered = sorted(segments.items())
                output = bytearray()
                expected = ordered[0][0]
                for start, chunk in ordered:
                    if start > expected:
                        session.stream_incomplete = True
                        break
                    trim = max(0, expected - start)
                    output.extend(chunk[trim:])
                    expected = max(expected, start + len(chunk))
                if len(output) > self.stream_limit:
                    output = output[:self.stream_limit]
                    session.stream_incomplete = True
                if direction == "client":
                    session.stream_client_to_server = output.hex()
                else:
                    session.stream_server_to_client = output.hex()
        if "A" in packet.flags and packet.acknowledgement is not None:
            previous = self._acks[session.id]
            if previous == packet.acknowledgement:
                session.duplicate_acks += 1
            self._acks[session.id] = packet.acknowledgement

    def _find(
        self,
        packet: PacketEvent,
        client_ip: str,
        client_port: int,
        server_ip: str,
        server_port: int,
    ) -> TCPSession:
        for session in reversed(self.sessions):
            if (session.client_ip, session.client_port, session.server_ip, session.server_port) != (
                client_ip,
                client_port,
                server_ip,
                server_port,
            ):
                continue
            if packet.flags == "S" and not any(
                p.flags == "S" and p.sequence == packet.sequence for p in session.packets
            ):
                continue
            return session
        if len(self.sessions) >= self.max_sessions:
            raise ValueError("TCP session limit reached")
        session = TCPSession(
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            capture_started_midstream=packet.flags not in {"S", "SA"},
        )
        self.sessions.append(session)
        return session

    @staticmethod
    def _update_handshake(session: TCPSession, packet: PacketEvent) -> None:
        flags = {p.flags for p in session.packets}
        if "R" in packet.flags:
            session.observed_state = "reset_observed"
            session.handshake = "reset"
        elif "F" in packet.flags:
            session.observed_state = "close_observed"
        elif packet.flags == "SA":
            session.observed_state = "syn_ack_observed"
        elif "S" in packet.flags:
            session.observed_state = "syn_observed"
        syn = next((p for p in session.packets if p.flags == "S"), None)
        syn_ack = next((p for p in session.packets if p.flags == "SA"), None)
        final_ack = next((p for p in session.packets if p.flags == "A"), None)
        handshake_valid = bool(
            syn
            and syn_ack
            and final_ack
            and syn.sequence is not None
            and syn_ack.acknowledgement is not None
            and syn_ack.sequence is not None
            and final_ack.acknowledgement is not None
            and syn_ack.acknowledgement == ((syn.sequence + 1) & 0xFFFFFFFF)
            and final_ack.acknowledgement == ((syn_ack.sequence + 1) & 0xFFFFFFFF)
        )
        if handshake_valid:
            session.handshake = "complete"
            session.observed_state = "established_observed"
        elif "S" in flags and "SA" in flags:
            session.handshake = "syn_ack_observed"
        elif "S" in flags:
            session.handshake = "syn_observed"
        elif session.capture_started_midstream:
            session.handshake = "not_observed_midstream"
