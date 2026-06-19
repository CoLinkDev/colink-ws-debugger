from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from PySide6.QtCore import QSignalBlocker, Qt, QTimer, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from colink_ws_debugger.protocol import (
    DeviceIdentity,
    LanProtocolSession,
    TEMPLATE_GROUPS,
    pretty_json,
)
from colink_ws_debugger.identity_store import load_or_create_identity, regenerate_identity
from colink_ws_debugger.logging_config import configure_logging
from colink_ws_debugger.swim import SwimManager
from colink_ws_debugger.trust_store import (
    load_trust_store,
    trusted_peer_from_session,
    upsert_trusted_peer,
)
from colink_ws_debugger.ws_client import WebSocketClient


@dataclass
class MessageRecord:
    at: str
    direction: str
    kind: str
    summary: str
    raw: str
    parsed: str
    decrypted: str = ""


def parse_frame(kind: str, payload: Any, *, format_json_raw: bool = False) -> tuple[str, str, str]:
    if kind == "binary" or isinstance(payload, bytes):
        data = payload if isinstance(payload, bytes) else bytes(payload)
        raw = data.hex(" ")
        return f"binary {len(data)} bytes", raw, raw
    text = str(payload)
    try:
        parsed = json.loads(text)
        message_type = parsed.get("type") if isinstance(parsed, dict) else None
        summary = str(message_type or "json")
        formatted = pretty_json(parsed)
        return summary, formatted if format_json_raw else text, formatted
    except json.JSONDecodeError:
        return "text", text, text


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.identity = load_or_create_identity()
        self.session = LanProtocolSession(self.identity)
        self.client = WebSocketClient()
        self.swim = SwimManager(self.identity.device_id)
        self.trusted_peers = load_trust_store()
        self.connection_generation = 0
        self.records: list[MessageRecord] = []
        self.ws_connected = False
        self.ping_timer = QTimer(self)
        self.ping_timer.setInterval(15_000)
        self.ping_timer.timeout.connect(self.send_heartbeat_ping)
        self.updating_peer_controls = False
        self.active_flow: str | None = None
        self.hello_sent = False
        self.hello_ack_sent = False
        self.hello_ack_received = False
        self.auth_challenge_sent = False
        self.auth_response_sent = False
        self.auth_verified_sent = False
        self.auth_verified_received = False
        self.pairing_request_sent = False
        self.pairing_exchange_sent = False
        self.pairing_confirm_sent = False
        self.pairing_complete_sent = False
        self.business_version_sent = False
        self.business_version_ack_sent = False
        self.business_version_ack_received = False
        self.key_exchange_sent = False
        self.key_exchange_received = False
        self.negotiate_sent = False
        self.negotiate_received = False
        self.setWindowTitle("CoLink WebSocket Debugger")
        self.resize(1280, 820)

        self.client.connected_for.connect(self.on_connected)
        self.client.disconnected_for.connect(self.on_disconnected)
        self.client.received_for.connect(self.on_received)
        self.client.sent_for.connect(self.on_sent)
        self.client.error_for.connect(self.on_error)
        self.swim.status_changed.connect(self.on_swim_status)
        logging.info("identity device_id=%s", self.identity.device_id)

        self.build_ui()
        self.refresh_identity()
        self.refresh_state()
        self.load_template()

    def build_ui(self) -> None:
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)
        layout.addLayout(self.build_connection_bar())

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self.build_left_panel())
        splitter.addWidget(self.build_right_panel())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)
        self.setCentralWidget(root)

    def build_connection_bar(self) -> QHBoxLayout:
        layout = QHBoxLayout()
        self.url_edit = QLineEdit("ws://127.0.0.1:27777/peer")
        self.connect_button = QPushButton("Connect")
        self.disconnect_button = QPushButton("Disconnect")
        self.disconnect_button.setEnabled(False)
        self.status_label = QLabel("Disconnected")
        self.auto_ping_check = QCheckBox("Auto Ping/Pong")
        self.auto_ping_check.setChecked(True)
        self.auto_ping_check.toggled.connect(self.toggle_auto_ping)
        self.connect_button.clicked.connect(self.connect_ws)
        self.disconnect_button.clicked.connect(self.disconnect_ws)
        layout.addWidget(QLabel("URL"))
        layout.addWidget(self.url_edit, 1)
        layout.addWidget(self.connect_button)
        layout.addWidget(self.disconnect_button)
        layout.addWidget(self.auto_ping_check)
        layout.addWidget(self.status_label)
        return layout

    def build_left_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.addWidget(self.build_identity_box())
        layout.addWidget(self.build_state_box())
        layout.addWidget(self.build_template_box(), 1)
        panel.setMinimumWidth(390)
        return panel

    def build_identity_box(self) -> QGroupBox:
        box = QGroupBox("Local Identity")
        form = QFormLayout(box)
        self.device_id_label = QLabel()
        self.device_name_label = QLabel()
        self.device_type_label = QLabel()
        self.public_key_edit = QPlainTextEdit()
        self.public_key_edit.setReadOnly(True)
        self.public_key_edit.setFixedHeight(72)
        self.regenerate_identity_button = QPushButton("New Identity")
        self.regenerate_identity_button.clicked.connect(self.regenerate_local_identity)
        form.addRow("Device ID", self.device_id_label)
        form.addRow("Name", self.device_name_label)
        form.addRow("Type", self.device_type_label)
        form.addRow("Public Key", self.public_key_edit)
        form.addRow("", self.regenerate_identity_button)
        return box

    def build_state_box(self) -> QGroupBox:
        box = QGroupBox("Protocol State")
        form = QFormLayout(box)
        self.peer_id_edit = QLineEdit()
        self.peer_key_edit = QPlainTextEdit()
        self.peer_key_edit.setFixedHeight(64)
        self.pairing_code_label = QLabel("-")
        self.phase_label = QLabel("idle")
        self.trust_label = QLabel("-")
        self.save_trust_button = QPushButton("Trust Peer")
        self.save_trust_button.clicked.connect(self.save_current_peer_trust)
        self.peer_id_edit.editingFinished.connect(self.update_peer_from_controls)
        self.peer_key_edit.textChanged.connect(self.update_peer_from_controls)
        form.addRow("Peer ID", self.peer_id_edit)
        form.addRow("Peer Public Key", self.peer_key_edit)
        form.addRow("Pairing Code", self.pairing_code_label)
        form.addRow("Trust", self.trust_label)
        form.addRow("", self.save_trust_button)
        form.addRow("Phase", self.phase_label)
        return box

    def build_template_box(self) -> QGroupBox:
        box = QGroupBox("Send")
        layout = QVBoxLayout(box)
        flow_buttons = QHBoxLayout()
        self.hello_flow_button = QPushButton("One-click Hello")
        self.auth_flow_button = QPushButton("One-click Auth")
        self.pairing_flow_button = QPushButton("One-click Pairing")
        self.hello_flow_button.clicked.connect(self.start_hello_flow)
        self.auth_flow_button.clicked.connect(self.send_auth_flow)
        self.pairing_flow_button.clicked.connect(self.send_pairing_flow)
        flow_buttons.addWidget(self.hello_flow_button)
        flow_buttons.addWidget(self.auth_flow_button)
        flow_buttons.addWidget(self.pairing_flow_button)
        layout.addLayout(flow_buttons)

        row = QHBoxLayout()
        self.template_combo = QComboBox()
        for group, names in TEMPLATE_GROUPS.items():
            self.template_combo.addItem(f"-- {group} --", None)
            for name in names:
                self.template_combo.addItem(name, name)
        self.template_combo.currentIndexChanged.connect(self.load_template)
        self.frame_type_combo = QComboBox()
        self.frame_type_combo.addItems(["Text/JSON", "Binary hex"])
        row.addWidget(self.template_combo, 1)
        row.addWidget(self.frame_type_combo)
        layout.addLayout(row)

        self.editor = QPlainTextEdit()
        self.editor.setPlaceholderText("Write a custom WebSocket frame or edit a protocol template.")
        layout.addWidget(self.editor, 1)

        buttons = QHBoxLayout()
        self.reload_template_button = QPushButton("Reload Template")
        self.format_button = QPushButton("Format JSON")
        self.send_button = QPushButton("Send")
        self.reload_template_button.clicked.connect(self.load_template)
        self.format_button.clicked.connect(self.format_editor)
        self.send_button.clicked.connect(self.send_current)
        buttons.addWidget(self.reload_template_button)
        buttons.addWidget(self.format_button)
        buttons.addWidget(self.send_button)
        layout.addLayout(buttons)
        return box

    def build_right_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        toolbar = QHBoxLayout()
        toolbar.addWidget(QLabel("Messages"))
        toolbar.addStretch(1)
        clear_top_button = QPushButton("Clear Log")
        clear_top_button.clicked.connect(self.clear_messages)
        toolbar.addWidget(clear_top_button)
        layout.addLayout(toolbar)

        self.message_table = QTableWidget(0, 4)
        self.message_table.setHorizontalHeaderLabels(["Time", "Dir", "Kind", "Summary"])
        self.message_table.itemSelectionChanged.connect(self.show_selected_message)
        self.message_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.message_table, 2)

        detail_splitter = QSplitter(Qt.Orientation.Horizontal)
        raw_box = QGroupBox("Raw")
        raw_layout = QVBoxLayout(raw_box)
        self.raw_view = QPlainTextEdit()
        self.raw_view.setReadOnly(True)
        raw_layout.addWidget(self.raw_view)
        decrypted_box = QGroupBox("Decrypted / Parsed")
        decrypted_layout = QVBoxLayout(decrypted_box)
        self.parsed_view = QPlainTextEdit()
        self.parsed_view.setReadOnly(True)
        decrypted_layout.addWidget(self.parsed_view)
        detail_splitter.addWidget(raw_box)
        detail_splitter.addWidget(decrypted_box)
        detail_splitter.setStretchFactor(0, 1)
        detail_splitter.setStretchFactor(1, 1)
        layout.addWidget(detail_splitter, 1)

        bottom = QHBoxLayout()
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear_messages)
        bottom.addStretch(1)
        bottom.addWidget(clear_button)
        layout.addLayout(bottom)
        return panel

    def refresh_identity(self) -> None:
        self.device_id_label.setText(self.identity.device_id)
        self.device_name_label.setText(self.identity.name)
        self.device_type_label.setText(self.identity.device_type)
        self.public_key_edit.setPlainText(self.identity.public_key)

    @Slot()
    def regenerate_local_identity(self) -> None:
        if self.ws_connected:
            QMessageBox.warning(self, "Connected", "Disconnect before creating a new local identity.")
            return
        self.identity = regenerate_identity()
        self.session = LanProtocolSession(self.identity)
        self.swim.replace_identity(self.identity.device_id)
        self.trusted_peers = load_trust_store()
        self.reset_protocol_state()
        self.refresh_identity()
        self.refresh_state()
        self.load_template()

    def refresh_state(self) -> None:
        peer = self.session.peer
        self.updating_peer_controls = True
        try:
            if not self.peer_id_edit.hasFocus():
                with QSignalBlocker(self.peer_id_edit):
                    self.peer_id_edit.setText(peer.device_id)
            if not self.peer_key_edit.hasFocus():
                with QSignalBlocker(self.peer_key_edit):
                    self.peer_key_edit.setPlainText(peer.public_key)
        finally:
            self.updating_peer_controls = False
        self.pairing_code_label.setText(self.session.pairing_code() or "-")
        trusted = self.trusted_peers.get(peer.device_id)
        self.trust_label.setText("trusted" if trusted and trusted.public_key == peer.public_key else "-")
        self.refresh_phase_label()

    @Slot()
    def update_peer_from_controls(self) -> None:
        if self.updating_peer_controls:
            return
        self.session.peer.device_id = self.peer_id_edit.text().strip()
        self.session.peer.public_key = self.peer_key_edit.toPlainText().strip()
        self.apply_trusted_peer_if_available()
        self.refresh_phase_label()

    def apply_trusted_peer_if_available(self) -> None:
        peer = self.trusted_peers.get(self.session.peer.device_id)
        if peer is None:
            return
        if not self.session.peer.public_key:
            self.session.peer.public_key = peer.public_key
        if not self.session.peer.name:
            self.session.peer.name = peer.name

    def refresh_phase_label(self) -> None:
        peer = self.session.peer
        phase = "idle"
        if peer.hello_received or peer.hello_ack_received or self.hello_sent or self.hello_ack_sent:
            phase = "hello"
        if peer.peer_nonce or peer.local_nonce or self.auth_challenge_sent or self.auth_response_sent:
            phase = "auth"
        if (
            peer.pairing_request_nonce
            or peer.pairing_exchange_nonce
            or self.pairing_request_sent
            or self.pairing_exchange_sent
            or self.pairing_confirm_sent
            or self.pairing_complete_sent
        ):
            phase = "pairing"
        if (
            peer.business_version
            or peer.ephemeral_public_key
            or self.session.local_ephemeral_public
            or self.business_version_sent
        ):
            phase = "business"
        self.phase_label.setText(phase)

    @Slot()
    def connect_ws(self) -> None:
        url = self.url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "Missing URL", "WebSocket URL is empty.")
            return
        self.session.reset_connection_state()
        self.reset_protocol_state()
        self.swim.start(url)
        self.client.connect_url(url)
        logging.info("connecting websocket url=%s generation=%s", url, self.client.generation)
        self.connection_generation = self.client.generation
        self.status_label.setText("Connecting...")
        self.connect_button.setEnabled(False)

    @Slot()
    def disconnect_ws(self) -> None:
        self.swim.stop()
        self.client.disconnect()
        logging.info("disconnect requested")

    @Slot()
    def on_connected(self, generation: int) -> None:
        if generation != self.connection_generation:
            return
        self.ws_connected = True
        logging.info("websocket connected generation=%s", generation)
        self.status_label.setText("Connected")
        self.connect_button.setEnabled(False)
        self.disconnect_button.setEnabled(True)
        if self.auto_ping_check.isChecked():
            self.ping_timer.start()

    @Slot(str)
    def on_disconnected(self, generation: int, reason: str) -> None:
        if generation != self.connection_generation:
            return
        self.ws_connected = False
        logging.info("websocket disconnected generation=%s reason=%s", generation, reason)
        self.ping_timer.stop()
        self.status_label.setText("Disconnected")
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self.session.reset_connection_state()
        self.reset_protocol_state()
        self.refresh_state()

    @Slot(str)
    def on_error(self, generation: int, message: str) -> None:
        if generation != self.connection_generation:
            return
        self.add_record("error", "text", message)
        self.status_label.setText("Error")
        logging.error("websocket error generation=%s message=%s", generation, message)

    @Slot(str)
    def on_swim_status(self, message: str) -> None:
        self.status_label.setText(message)
        logging.info("swim status: %s", message)

    @Slot(str, object)
    def on_received(self, generation: int, kind: str, payload: object) -> None:
        if generation != self.connection_generation:
            return
        message = None
        if isinstance(payload, str):
            try:
                message = json.loads(payload)
                self.session.ingest(message)
                self.apply_trusted_peer_if_available()
            except json.JSONDecodeError:
                pass
        self.add_record("in", kind, payload)
        if isinstance(message, dict):
            self.advance_state_machine(message)
        self.refresh_state()

    @Slot(str, object)
    def on_sent(self, generation: int, kind: str, payload: object) -> None:
        if generation != self.connection_generation:
            return
        if isinstance(payload, str):
            try:
                self.note_outbound_message(json.loads(payload))
            except json.JSONDecodeError:
                pass
        self.add_record("out", kind, payload)

    @Slot()
    def load_template(self) -> None:
        name = self.template_combo.currentData()
        if not name:
            return
        self.update_peer_from_controls()
        try:
            message = self.session.template(str(name))
        except Exception as exc:
            QMessageBox.warning(self, "Template failed", str(exc))
            return
        self.editor.setPlainText(pretty_json(message))
        self.frame_type_combo.setCurrentIndex(0)
        self.refresh_state()

    @Slot()
    def format_editor(self) -> None:
        try:
            self.editor.setPlainText(pretty_json(json.loads(self.editor.toPlainText())))
        except json.JSONDecodeError as exc:
            QMessageBox.warning(self, "Invalid JSON", str(exc))

    @Slot()
    def send_current(self) -> None:
        text = self.editor.toPlainText()
        if self.frame_type_combo.currentText() == "Binary hex":
            cleaned = "".join(ch for ch in text if ch not in " \r\n\t")
            try:
                self.client.send_binary(bytes.fromhex(cleaned))
            except ValueError as exc:
                QMessageBox.warning(self, "Invalid hex", str(exc))
            return
        self.client.send_text(text)

    @Slot()
    def start_hello_flow(self) -> None:
        self.update_peer_from_controls()
        self.active_flow = "hello"
        self.continue_hello_flow()

    @Slot()
    def send_auth_flow(self) -> None:
        self.update_peer_from_controls()
        self.active_flow = "auth"
        self.continue_auth_flow()

    @Slot()
    def send_pairing_flow(self) -> None:
        self.update_peer_from_controls()
        self.active_flow = "pairing"
        self.continue_pairing_flow()

    def reset_protocol_state(self) -> None:
        self.active_flow = None
        self.hello_sent = False
        self.hello_ack_sent = False
        self.hello_ack_received = False
        self.auth_challenge_sent = False
        self.auth_response_sent = False
        self.auth_verified_sent = False
        self.auth_verified_received = False
        self.pairing_request_sent = False
        self.pairing_exchange_sent = False
        self.pairing_confirm_sent = False
        self.pairing_complete_sent = False
        self.business_version_sent = False
        self.business_version_ack_sent = False
        self.business_version_ack_received = False
        self.key_exchange_sent = False
        self.key_exchange_received = False
        self.negotiate_sent = False
        self.negotiate_received = False

    def send_protocol_message(self, message: dict[str, Any]) -> None:
        self.note_outbound_message(message)
        logging.debug("sending protocol message type=%s", message.get("type"))
        self.client.send_text(json.dumps(message, ensure_ascii=False, separators=(",", ":")))
        self.refresh_state()

    def note_outbound_message(self, message: dict[str, Any]) -> None:
        message_type = str(message.get("type") or "")
        if message_type == "protocol.hello":
            self.hello_sent = True
        elif message_type == "protocol.hello-ack":
            self.hello_ack_sent = True
        elif message_type == "auth.v1.challenge":
            self.auth_challenge_sent = True
        elif message_type == "auth.v1.response":
            self.auth_response_sent = True
        elif message_type == "auth.v1.verified":
            self.auth_verified_sent = True
        elif message_type == "pairing.v1.request":
            self.pairing_request_sent = True
        elif message_type == "pairing.v1.exchange":
            self.pairing_exchange_sent = True
        elif message_type == "pairing.v1.confirm":
            self.pairing_confirm_sent = True
        elif message_type == "pairing.v1.complete":
            self.pairing_complete_sent = True
        elif message_type == "business.v1.version":
            self.business_version_sent = True
        elif message_type == "business.v1.version-ack":
            self.business_version_ack_sent = True
        elif message_type == "business.v1.key-exchange":
            self.key_exchange_sent = True
        elif message_type == "business.v1.negotiate":
            self.negotiate_sent = True

    def advance_state_machine(self, message: dict[str, Any]) -> None:
        message_type = str(message.get("type") or "")
        if message_type == "business.v1.message":
            self.try_decrypt_business_message(message)
        if message_type == "heartbeat.v1.ping" and self.auto_ping_check.isChecked():
            self.send_protocol_message(self.session.heartbeat_pong())
            return
        if message_type == "protocol.hello-ack":
            self.hello_ack_received = bool((message.get("payload") or {}).get("compatible"))
        elif message_type == "auth.v1.verified":
            self.auth_verified_received = True
        elif message_type == "business.v1.version-ack":
            self.business_version_ack_received = bool((message.get("payload") or {}).get("compatible"))
        elif message_type == "business.v1.key-exchange":
            self.key_exchange_received = True
        elif message_type == "business.v1.negotiate":
            self.negotiate_received = True
            self.session.choose_suite(local_is_initiator=True)

        if self.active_flow == "hello":
            self.continue_hello_flow()
            return
        if self.active_flow == "auth":
            self.advance_auth_flow(message, message_type)
            return
        if self.active_flow == "pairing":
            self.advance_pairing_flow(message, message_type)
            return

    def continue_hello_flow(self) -> None:
        if not self.hello_sent:
            self.send_protocol_message(self.session.protocol_hello())
        if self.session.peer.hello_received and not self.hello_ack_sent:
            self.send_protocol_message(self.session.protocol_hello_ack())
        if self.hello_sent and self.hello_ack_sent and self.hello_ack_received:
            self.finish_flow("Hello completed.")

    def continue_auth_flow(self) -> None:
        if self.session.peer.peer_nonce and not self.auth_response_sent:
            self.send_protocol_message(self.session.auth_response())
        if not self.auth_challenge_sent:
            self.send_protocol_message(self.session.auth_challenge())
            return
        if self.auth_verified_sent and self.auth_verified_received:
            self.maybe_start_business_flow()

    def advance_auth_flow(self, message: dict[str, Any], message_type: str) -> None:
        if message_type == "auth.v1.challenge":
            self.continue_auth_flow()
            return
        if message_type == "auth.v1.response":
            if self.session.verify_auth_response(message):
                self.send_protocol_message(self.session.auth_verified())
            else:
                self.send_protocol_message(self.session.auth_reject())
                self.finish_flow("Auth failed: peer signature invalid.")
            return
        if message_type == "auth.v1.verified":
            if not self.auth_verified_sent:
                self.send_protocol_message(self.session.auth_verified())
            self.maybe_start_business_flow()
            return
        if message_type == "auth.v1.reject":
            self.finish_flow("Auth rejected by peer.")
            return
        self.advance_business_flow(message, message_type)

    def continue_pairing_flow(self) -> None:
        if self.session.peer.pairing_request_nonce and not self.pairing_exchange_sent:
            self.send_protocol_message(self.session.pairing_exchange())
            return
        if self.session.peer.pairing_exchange_nonce and not self.pairing_confirm_sent:
            self.send_protocol_message(self.session.pairing_confirm())
            return
        if not self.pairing_request_sent and not self.session.peer.pairing_request_nonce:
            self.send_protocol_message(self.session.pairing_request())

    def advance_pairing_flow(self, message: dict[str, Any], message_type: str) -> None:
        if message_type == "pairing.v1.request":
            self.continue_pairing_flow()
            return
        if message_type == "pairing.v1.exchange":
            self.continue_pairing_flow()
            return
        if message_type == "pairing.v1.confirm":
            self.send_protocol_message(self.session.pairing_complete())
            self.save_peer_trust_from_session()
            self.maybe_start_business_flow()
            return
        if message_type == "pairing.v1.complete":
            self.save_peer_trust_from_session()
            self.maybe_start_business_flow()
            return
        if message_type == "pairing.v1.reject":
            self.finish_flow("Pairing rejected by peer.")
            return
        self.advance_business_flow(message, message_type)

    def maybe_start_business_flow(self) -> None:
        if not self.business_version_sent:
            self.send_protocol_message(self.session.business_version())
        self.continue_business_flow()

    def continue_business_flow(self) -> None:
        if (
            self.business_version_sent
            and self.business_version_ack_sent
            and self.business_version_ack_received
            and not self.key_exchange_sent
        ):
            self.send_protocol_message(self.session.business_key_exchange())
            return
        if self.key_exchange_sent and self.key_exchange_received and not self.negotiate_sent:
            self.send_protocol_message(self.session.business_negotiate())

    def advance_business_flow(self, message: dict[str, Any], message_type: str) -> None:
        if message_type == "business.v1.version":
            if not self.business_version_sent:
                self.send_protocol_message(self.session.business_version())
            if not self.business_version_ack_sent:
                self.send_protocol_message(self.session.business_version_ack())
            self.continue_business_flow()
            return
        if message_type == "business.v1.version-ack":
            compatible = bool((message.get("payload") or {}).get("compatible"))
            self.business_version_ack_received = compatible
            if compatible:
                self.continue_business_flow()
            return
        if message_type == "business.v1.key-exchange":
            if self.session.verify_key_exchange(message):
                self.key_exchange_received = True
                if not self.key_exchange_sent:
                    self.send_protocol_message(self.session.business_key_exchange())
                self.continue_business_flow()
            else:
                self.send_protocol_message(self.session.business_key_exchange_reject())
                self.finish_flow("Business key exchange failed: peer signature invalid.")
            return
        if message_type == "business.v1.key-exchange-reject":
            self.finish_flow("Business key exchange rejected by peer.")
            return
        if message_type == "business.v1.negotiate":
            self.negotiate_received = True
            if not self.negotiate_sent:
                self.send_protocol_message(self.session.business_negotiate())
                self.negotiate_sent = True
            self.finish_flow("Protocol flow completed.")

    @Slot(bool)
    def toggle_auto_ping(self, enabled: bool) -> None:
        if enabled and self.ws_connected:
            self.ping_timer.start()
        else:
            self.ping_timer.stop()

    @Slot()
    def send_heartbeat_ping(self) -> None:
        self.send_protocol_message(self.session.heartbeat_ping())

    def try_decrypt_business_message(self, message: dict[str, Any]) -> str:
        payload = message.get("payload")
        if not isinstance(payload, dict):
            return ""
        try:
            return pretty_json(self.session.decrypt_business_payload(payload))
        except Exception as exc:
            return f"Decrypt failed: {exc}"

    def finish_flow(self, message: str) -> None:
        self.status_label.setText(message)
        self.active_flow = None

    @Slot()
    def save_current_peer_trust(self) -> None:
        if self.save_peer_trust_from_session():
            self.status_label.setText("Peer trusted.")
        else:
            QMessageBox.warning(self, "Missing peer", "Peer device ID or public key is missing.")

    def save_peer_trust_from_session(self) -> bool:
        peer = trusted_peer_from_session(
            self.session.peer.device_id,
            self.session.peer.name,
            self.session.peer.public_key,
        )
        if peer is None:
            return False
        self.trusted_peers = upsert_trusted_peer(peer)
        self.refresh_state()
        return True

    def add_record(self, direction: str, kind: str, payload: Any) -> None:
        selected_rows = {index.row() for index in self.message_table.selectedIndexes()}
        summary, raw, parsed = parse_frame(kind, payload, format_json_raw=direction == "in")
        decrypted = ""
        if isinstance(payload, str):
            try:
                message = json.loads(payload)
                if isinstance(message, dict) and message.get("type") == "business.v1.message":
                    decrypted = self.try_decrypt_business_message(message)
            except json.JSONDecodeError:
                pass
        record = MessageRecord(
            at=datetime.now().strftime("%H:%M:%S.%f")[:-3],
            direction=direction,
            kind=kind,
            summary=summary,
            raw=raw,
            parsed=parsed,
            decrypted=decrypted,
        )
        self.records.append(record)
        row = self.message_table.rowCount()
        self.message_table.insertRow(row)
        foreground = QColor("#b00020") if direction == "error" else None
        for column, value in enumerate([record.at, record.direction, record.kind, record.summary]):
            item = QTableWidgetItem(value)
            if foreground is not None:
                item.setForeground(foreground)
            self.message_table.setItem(row, column, item)
        if not selected_rows:
            self.message_table.selectRow(row)

    @Slot()
    def show_selected_message(self) -> None:
        rows = {index.row() for index in self.message_table.selectedIndexes()}
        if not rows:
            return
        row = min(rows)
        if row >= len(self.records):
            return
        record = self.records[row]
        self.parsed_view.setPlainText(record.decrypted or record.parsed)
        self.raw_view.setPlainText(record.raw)

    @Slot()
    def clear_messages(self) -> None:
        self.records.clear()
        self.message_table.setRowCount(0)
        self.parsed_view.clear()
        self.raw_view.clear()

    def closeEvent(self, event: Any) -> None:
        self.swim.stop()
        self.client.disconnect()
        super().closeEvent(event)


def main() -> None:
    configure_logging()
    qt_app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    raise SystemExit(qt_app.exec())
