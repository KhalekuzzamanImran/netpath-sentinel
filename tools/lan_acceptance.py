"""Explicit two-host LAN acceptance helpers; never changes firewall or routing."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import socket
import struct
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from netpath_sentinel.application.runner import DiagnosticRunner, WorkflowEvent
from netpath_sentinel.domain.enums import DiagnosticMode
from netpath_sentinel.domain.models import DiagnosticConfig
from netpath_sentinel.infrastructure.persistence import Repository


def emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, default=str, sort_keys=True), flush=True)


async def capture(args: argparse.Namespace) -> int:
    data_dir = Path(args.data_dir).expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        data_dir.chmod(0o700)
    os.environ["NETPATH_SENTINEL_DATA_DIR"] = str(data_dir)
    database = data_dir / "lan-acceptance.sqlite3"
    repository = Repository(database)
    session_id = str(uuid4())
    config = DiagnosticConfig(
        name=args.name,
        mode=DiagnosticMode.PASSIVE_CAPTURE,
        interface=args.interface,
        destination_ip=args.destination_ip,
        source_ip=args.source_ip,
        destination_port=args.port,
        duration_seconds=args.duration,
        max_packets=args.max_packets,
        capture_payload=False,
    )
    repository.save_session(session_id, config)
    cancel = asyncio.Event()
    loop = asyncio.get_running_loop()
    previous_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, lambda *_: loop.call_soon_threadsafe(cancel.set))

    async def sink(event: WorkflowEvent) -> None:
        record: dict[str, Any] = {
            "session_id": event.session_id,
            "event": event.event_type,
            "stage": event.stage_id,
            "status": event.status,
            "progress": event.progress,
            "message": event.message,
            "timestamp": event.timestamp.isoformat(),
        }
        if event.packet:
            record["packet"] = {
                "timestamp": event.packet.timestamp.isoformat(),
                "source": f"{event.packet.src_ip}:{event.packet.src_port}",
                "destination": f"{event.packet.dst_ip}:{event.packet.dst_port}",
                "flags": event.packet.flags,
                "sequence": event.packet.sequence,
                "acknowledgement": event.packet.acknowledgement,
                "payload_length": event.packet.payload_length,
                "interface": event.packet.capture_interface,
            }
        if event.tcp_session:
            record["tcp_session"] = {
                "client": f"{event.tcp_session.client_ip}:{event.tcp_session.client_port}",
                "server": f"{event.tcp_session.server_ip}:{event.tcp_session.server_port}",
                "handshake": event.tcp_session.handshake,
                "state": event.tcp_session.observed_state,
                "client_to_server_bytes": event.tcp_session.payload_bytes_client_to_server,
                "server_to_client_bytes": event.tcp_session.payload_bytes_server_to_client,
            }
        if event.evidence:
            record["evidence"] = {
                "id": event.evidence.id,
                "type": event.evidence.evidence_type,
                "status": event.evidence.status,
                "observation": event.evidence.observation,
            }
        if event.finding:
            record["finding"] = {
                "id": event.finding.id,
                "code": event.finding.code,
                "confidence": event.finding.confidence,
                "supporting_evidence_ids": event.finding.supporting_evidence_ids,
                "conclusion": event.finding.conclusion,
            }
        emit(record)

    try:
        result = await DiagnosticRunner(repository).run(
            session_id, config, sink=sink, cancel_event=cancel
        )
    except asyncio.CancelledError:
        emit(
            {
                "event": "acceptance_result",
                "status": "cancelled",
                "session_id": session_id,
                "database": str(database),
            "partial_packet_count": len(repository.session_bundle(session_id)["packets"]),
            }
        )
        return 130
    finally:
        signal.signal(signal.SIGINT, previous_handler)

    emit(
        {
            "event": "acceptance_result",
            "status": "completed",
            "session_id": session_id,
            "database": str(database),
            "html_report": str(result["html_report"]),
            "json_report": str(result["json_report"]),
            "findings": [
                {
                    "code": finding.code,
                    "confidence": finding.confidence,
                    "supporting_evidence_ids": finding.supporting_evidence_ids,
                }
                for finding in result["findings"]
            ],
        }
    )
    return 0


async def listen(args: argparse.Namespace) -> int:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        total = 0
        heartbeats = 0
        termination = "graceful_eof"
        try:
            while chunk := await reader.read(4096):
                total += len(chunk)
                heartbeats += sum(line.startswith(b"PHASE9-HEARTBEAT ") for line in chunk.splitlines())
        except ConnectionResetError:
            termination = "reset"
        finally:
            emit(
                {
                    "event": "peer_connection_closed",
                    "peer": peer,
                    "bytes_received": total,
                    "heartbeat_lines": heartbeats,
                    "termination": termination,
                }
            )
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, args.bind, args.port)
    sockets = [sock.getsockname() for sock in server.sockets or []]
    emit({"event": "peer_listener_ready", "bind": sockets})
    try:
        if args.duration:
            async with server:
                await asyncio.sleep(args.duration)
        else:
            async with server:
                await server.serve_forever()
    except asyncio.CancelledError:
        pass
    finally:
        server.close()
        await server.wait_closed()
    return 0


def send(args: argparse.Namespace) -> int:
    payload = args.payload.encode("utf-8")
    try:
        connection = socket.create_connection((args.host, args.port), timeout=args.timeout)
    except ConnectionRefusedError:
        emit({"event": "socket_observation", "result": "refused", "host": args.host, "port": args.port})
        return 0 if args.expect == "refused" else 1
    except TimeoutError:
        emit({"event": "socket_observation", "result": "timeout", "host": args.host, "port": args.port})
        return 0 if args.expect == "timeout" else 1
    except OSError as exc:
        emit(
            {
                "event": "socket_observation",
                "result": "connect_error",
                "host": args.host,
                "port": args.port,
                "error": str(exc),
            }
        )
        return 1

    if args.mode == "probe":
        connection.close()
        emit({"event": "socket_observation", "result": "connected", "host": args.host, "port": args.port})
        return 0 if args.expect == "connected" else 1
    if args.mode == "reset":
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        connection.close()
        emit({"event": "socket_observation", "result": "reset_sent", "host": args.host, "port": args.port})
        return 0

    with connection:
        connection.sendall(payload)
        heartbeat_count = 0
        if args.heartbeat_interval:
            end = time.monotonic() + args.heartbeat_duration
            while time.monotonic() < end:
                connection.sendall(f"PHASE9-HEARTBEAT {heartbeat_count}\n".encode("ascii"))
                heartbeat_count += 1
                time.sleep(args.heartbeat_interval)
    emit(
        {
            "event": "socket_observation",
            "result": "payload_sent_and_gracefully_closed",
            "host": args.host,
            "port": args.port,
            "payload_bytes": len(payload),
            "heartbeat_count": heartbeat_count,
        }
    )
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    capture_parser = commands.add_parser("capture", help="capture and diagnose traffic on this host")
    capture_parser.add_argument("--interface", required=True, help="explicit local adapter name")
    capture_parser.add_argument("--port", type=int, required=True)
    capture_parser.add_argument("--destination-ip")
    capture_parser.add_argument("--source-ip")
    capture_parser.add_argument("--duration", type=int, default=60)
    capture_parser.add_argument("--max-packets", type=int, default=10000)
    capture_parser.add_argument("--name", default="Phase 9 LAN acceptance")
    capture_parser.add_argument("--data-dir", default="./phase9-lan-evidence")
    capture_parser.set_defaults(func=lambda args: asyncio.run(capture(args)))

    listener = commands.add_parser("listen", help="run a controlled TCP peer on this host")
    listener.add_argument("--bind", required=True, help="explicit local address; avoid 0.0.0.0 unless authorized")
    listener.add_argument("--port", type=int, required=True)
    listener.add_argument("--duration", type=int, default=0, help="seconds; 0 runs until Ctrl+C")
    listener.set_defaults(func=lambda args: asyncio.run(listen(args)))

    client = commands.add_parser("send", help="connect, send a test payload/heartbeat, or reset")
    client.add_argument("--host", required=True, help="explicit authorized peer address")
    client.add_argument("--port", type=int, required=True)
    client.add_argument("--mode", choices=["probe", "send", "reset"], default="send")
    client.add_argument("--payload", default="NetPath Sentinel Phase 9 test payload\n")
    client.add_argument("--timeout", type=float, default=3.0)
    client.add_argument("--expect", choices=["connected", "refused", "timeout"], default="connected")
    client.add_argument("--heartbeat-interval", type=float, default=0.0)
    client.add_argument("--heartbeat-duration", type=float, default=10.0)
    client.set_defaults(func=send)
    return root


def main() -> int:
    args = parser().parse_args()
    if args.command in {"capture", "listen"}:
        if not 1 <= args.port <= 65535:
            raise SystemExit("port must be between 1 and 65535")
        if args.duration < 0:
            raise SystemExit("duration cannot be negative")
    elif args.command == "send":
        if not 1 <= args.port <= 65535:
            raise SystemExit("port must be between 1 and 65535")
        if args.heartbeat_interval < 0 or args.heartbeat_duration < 0:
            raise SystemExit("heartbeat timing values cannot be negative")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
