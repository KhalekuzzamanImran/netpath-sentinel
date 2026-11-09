import asyncio
from collections.abc import Awaitable, Callable

PayloadCallback = Callable[[str, int, bytes], Awaitable[None] | None]


class DiagnosticListener:
    """Explicitly started generic TCP listener; it never modifies firewall state."""

    def __init__(self, host: str, port: int, callback: PayloadCallback | None = None) -> None:
        self.host = host
        self.port = port
        self.callback = callback
        self.server: asyncio.AbstractServer | None = None
        self.connections = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.connections += 1
        peer = writer.get_extra_info("peername")
        try:
            source_ip, source_port = str(peer[0]), int(peer[1])
            while data := await reader.read(64 * 1024):
                if self.callback:
                    result = self.callback(source_ip, source_port, data)
                    if asyncio.iscoroutine(result):
                        await result
        finally:
            writer.close()
            await writer.wait_closed()
