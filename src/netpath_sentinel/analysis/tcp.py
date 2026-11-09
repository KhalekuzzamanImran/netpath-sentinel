from collections import defaultdict

from netpath_sentinel.domain.models import PacketEvent, TCPSession


class TCPSessionTracker:
    """Deterministic TCP tracker resilient to midstream captures and tuple reuse."""

    def __init__(self, server_port: int | None = None) -> None:
        self.server_port = server_port
        self.sessions: list[TCPSession] = []
        self._seen: dict[str, set[tuple[int | None, str]]] = defaultdict(set)

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
        session.packets.append(packet)
        session.last_seen = packet.timestamp
        if packet.src_ip == client_ip and packet.src_port == client_port:
            session.payload_bytes_client_to_server += packet.payload_length
        else:
            session.payload_bytes_server_to_client += packet.payload_length
        key = (packet.sequence, packet.flags)
        if packet.payload_length and key in self._seen[session.id]:
            session.retransmissions += 1
        self._seen[session.id].add(key)
        self._update_handshake(session, packet)
        return session

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
            if packet.flags == "S" and any(
                p.flags == "S" and not (p.flags == "A") for p in session.packets
            ):
                continue
            return session
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
        if "R" in flags:
            session.handshake = "reset"
        elif (
            "S" in flags
            and "SA" in flags
            and any(p.flags == "A" and p.payload_length == 0 for p in session.packets)
        ):
            session.handshake = "complete"
        elif "S" in flags and "SA" in flags:
            session.handshake = "syn_ack_observed"
        elif "S" in flags:
            session.handshake = "syn_observed"
        elif session.capture_started_midstream:
            session.handshake = "not_observed_midstream"
