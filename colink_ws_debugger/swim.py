from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from PySide6.QtCore import QObject, QTimer, Signal, Slot

LAN_PORT = 27_777


def now_millis() -> int:
    return int(time.time() * 1000)


@dataclass
class SwimState:
    device_id: str
    seq: int = 1
    incarnation: int = field(default_factory=now_millis)
    peers: dict[str, str] = field(default_factory=dict)

    def ping(self) -> dict[str, Any]:
        message = self.message("swim.ping")
        self.seq += 1
        return message

    def ack(self, seq: int) -> dict[str, Any]:
        return self.message("swim.ack", seq=seq)

    def message(self, message_type: str, seq: int | None = None) -> dict[str, Any]:
        return {
            "type": message_type,
            "payload": {
                "seq": self.seq if seq is None else seq,
                "from": self.device_id,
                "incarnation": self.incarnation,
                "gossip": [
                    {
                        "deviceId": self.device_id,
                        "state": "alive",
                        "incarnation": self.incarnation,
                    },
                ],
            },
        }

    def ingest(self, message: dict[str, Any]) -> None:
        payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
        from_device = payload.get("from")
        if isinstance(from_device, str) and from_device:
            self.peers[from_device] = str(message.get("type") or "")


class SwimRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        if self.path != "/peer/swim/v1":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length") or "0")
        if length > 16 * 1024:
            self.send_error(413)
            return
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self.send_error(400)
            return
        server: "SwimHttpServer" = self.server  # type: ignore[assignment]
        if isinstance(data, dict):
            server.state.ingest(data)
        payload = data.get("payload") if isinstance(data, dict) and isinstance(data.get("payload"), dict) else {}
        seq = int(payload.get("seq") or server.state.seq)
        response = json.dumps(server.state.ack(seq), separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args: Any) -> None:
        return


class SwimHttpServer(ThreadingHTTPServer):
    state: SwimState


class SwimManager(QObject):
    status_changed = Signal(str)

    def __init__(self, device_id: str) -> None:
        super().__init__()
        self.state = SwimState(device_id=device_id)
        self.server: SwimHttpServer | None = None
        self.thread: threading.Thread | None = None
        self.target_url = ""
        self.running = False
        self.timer = QTimer(self)
        self.timer.setInterval(5_000)
        self.timer.timeout.connect(self.bootstrap_ping)

    def replace_identity(self, device_id: str) -> None:
        self.stop()
        self.state = SwimState(device_id=device_id)

    def start(self, websocket_url: str) -> None:
        self.target_url = websocket_url
        self.running = True
        logging.info("swim starting target=%s", websocket_url)
        self.ensure_server()
        self.bootstrap_ping()
        if not self.timer.isActive():
            self.timer.start()

    def stop(self) -> None:
        self.running = False
        self.timer.stop()
        logging.info("swim stopping")
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=1.5)
        self.server = None
        self.thread = None

    def ensure_server(self) -> None:
        if self.server is not None:
            return
        try:
            server = SwimHttpServer(("0.0.0.0", LAN_PORT), SwimRequestHandler)
        except OSError as exc:
            logging.warning("swim listen failed: %s", exc)
            self.status_changed.emit(f"SWIM listen failed: {exc}")
            return
        server.state = self.state
        self.server = server
        self.thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.thread.start()
        logging.info("swim listening port=%s", LAN_PORT)
        self.status_changed.emit(f"SWIM listening on {LAN_PORT}")

    @Slot()
    def bootstrap_ping(self) -> None:
        if not self.running:
            return
        parsed = urlparse(self.target_url)
        if not parsed.hostname:
            return
        port = parsed.port or LAN_PORT
        url = f"http://{parsed.hostname}:{port}/peer/swim/v1"
        logging.debug("swim bootstrap ping url=%s", url)
        body = json.dumps(self.state.ping(), separators=(",", ":")).encode("utf-8")
        request = Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        threading.Thread(target=self._post_ping, args=(request,), daemon=True).start()

    def _post_ping(self, request: Request) -> None:
        try:
            with urlopen(request, timeout=1.0) as response:
                data = json.loads(response.read().decode("utf-8"))
            if isinstance(data, dict):
                self.state.ingest(data)
            logging.info("swim ping succeeded")
            self.status_changed.emit("SWIM alive")
        except Exception as exc:
            logging.warning("swim ping failed: %s", exc)
            self.status_changed.emit(f"SWIM failed: {exc}")
