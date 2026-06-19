from __future__ import annotations

import asyncio
import logging
import traceback
from dataclasses import dataclass
from typing import Any

import websockets
from PySide6.QtCore import QObject, QThread, Signal, Slot


@dataclass
class OutboundFrame:
    kind: str
    payload: str | bytes


STOP_FRAME = OutboundFrame("__stop__", "")


class WebSocketWorker(QObject):
    connected = Signal()
    disconnected = Signal(str)
    received = Signal(str, object)
    sent = Signal(str, object)
    error = Signal(str)

    def __init__(self, url: str) -> None:
        super().__init__()
        self.url = url
        self.loop: asyncio.AbstractEventLoop | None = None
        self.websocket: Any = None
        self.queue: asyncio.Queue[OutboundFrame] | None = None
        self.stop_requested = False

    @Slot()
    def run(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._run())
        finally:
            self.loop.close()

    async def _run(self) -> None:
        self.queue = asyncio.Queue()
        try:
            async with websockets.connect(self.url, ping_interval=None) as websocket:
                self.websocket = websocket
                self.connected.emit()
                reader = asyncio.create_task(self._reader())
                writer = asyncio.create_task(self._writer())
                done, pending = await asyncio.wait(
                    {reader, writer},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                for task in done:
                    task.result()
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            if not self.stop_requested:
                logging.exception("websocket worker failed")
                self.error.emit(f"{exc}\n{traceback.format_exc()}")
        finally:
            self.websocket = None
            self.disconnected.emit("closed")

    async def _reader(self) -> None:
        assert self.websocket is not None
        async for message in self.websocket:
            if isinstance(message, bytes):
                self.received.emit("binary", message)
            else:
                self.received.emit("text", message)

    async def _writer(self) -> None:
        assert self.websocket is not None
        assert self.queue is not None
        while not self.stop_requested:
            frame = await self.queue.get()
            if frame is STOP_FRAME:
                return
            await self.websocket.send(frame.payload)
            self.sent.emit(frame.kind, frame.payload)

    def send(self, kind: str, payload: str | bytes) -> None:
        if self.loop is None or self.queue is None:
            self.error.emit("WebSocket is not connected.")
            return
        asyncio.run_coroutine_threadsafe(self.queue.put(OutboundFrame(kind, payload)), self.loop)

    def close(self) -> None:
        self.stop_requested = True
        if self.loop is None:
            return
        if self.queue is not None and not self.loop.is_closed():
            asyncio.run_coroutine_threadsafe(self.queue.put(STOP_FRAME), self.loop)
        if self.websocket is not None:
            asyncio.run_coroutine_threadsafe(self.websocket.close(), self.loop)


class WebSocketClient(QObject):
    connected = Signal()
    disconnected = Signal(str)
    received = Signal(str, object)
    sent = Signal(str, object)
    error = Signal(str)
    connected_for = Signal(int)
    disconnected_for = Signal(int, str)
    received_for = Signal(int, str, object)
    sent_for = Signal(int, str, object)
    error_for = Signal(int, str)

    def __init__(self) -> None:
        super().__init__()
        self.thread: QThread | None = None
        self.worker: WebSocketWorker | None = None
        self.generation = 0

    def connect_url(self, url: str) -> None:
        self.disconnect()
        self.generation += 1
        generation = self.generation
        self.thread = QThread()
        self.worker = WebSocketWorker(url)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.connected.connect(lambda: self._on_connected(generation))
        self.worker.disconnected.connect(lambda reason: self._on_disconnected(generation, reason))
        self.worker.received.connect(lambda kind, payload: self._on_received(generation, kind, payload))
        self.worker.sent.connect(lambda kind, payload: self._on_sent(generation, kind, payload))
        self.worker.error.connect(lambda message: self._on_error(generation, message))
        self.thread.start()

    def send_text(self, text: str) -> None:
        if self.worker is not None:
            self.worker.send("text", text)

    def send_binary(self, data: bytes) -> None:
        if self.worker is not None:
            self.worker.send("binary", data)

    def disconnect(self) -> None:
        if self.worker is not None:
            self.worker.close()
        if self.thread is not None:
            self.thread.quit()
            self.thread.wait(1500)
        self.worker = None
        self.thread = None

    def _on_connected(self, generation: int) -> None:
        self.connected.emit()
        self.connected_for.emit(generation)

    def _on_disconnected(self, generation: int, reason: str) -> None:
        self.disconnected.emit(reason)
        self.disconnected_for.emit(generation, reason)

    def _on_received(self, generation: int, kind: str, payload: object) -> None:
        self.received.emit(kind, payload)
        self.received_for.emit(generation, kind, payload)

    def _on_sent(self, generation: int, kind: str, payload: object) -> None:
        self.sent.emit(kind, payload)
        self.sent_for.emit(generation, kind, payload)

    def _on_error(self, generation: int, message: str) -> None:
        self.error.emit(message)
        self.error_for.emit(generation, message)
