import asyncio

import pytest

from netpath_sentinel.infrastructure.listener import DiagnosticListener


@pytest.mark.asyncio
async def test_diagnostic_listener_receives_payload() -> None:
    received: list[bytes] = []

    async def callback(_ip: str, _port: int, data: bytes) -> None:
        received.append(data)

    listener = DiagnosticListener("127.0.0.1", 0, callback)
    try:
        await listener.start()
    except OSError as exc:
        pytest.skip(f"socket bind unavailable in sandbox: {exc}")
    assert listener.server is not None
    port = listener.server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"heartbeat\n")
    await writer.drain()
    await asyncio.sleep(0)
    writer.close()
    await writer.wait_closed()
    await asyncio.wait_for(reader.read(), timeout=1)
    await listener.stop()
    assert received == [b"heartbeat\n"]
