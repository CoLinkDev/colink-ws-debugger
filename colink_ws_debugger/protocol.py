from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

PROTOCOL_VERSION = "1.1.0"
BUSINESS_VERSION = "1.1.0"
AES_256_GCM_SUITE = "x25519-aes-256-gcm"
CHACHA20_POLY1305_SUITE = "x25519-chacha20-poly1305"
SUPPORTED_SUITES = [AES_256_GCM_SUITE, CHACHA20_POLY1305_SUITE]


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def now_millis() -> int:
    return int(time.time() * 1000)


def random_nonce(length: int = 32) -> str:
    return base64.urlsafe_b64encode(os.urandom(length)).decode("ascii").rstrip("=")


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False)


@dataclass
class DeviceIdentity:
    user_id: str | None
    device_id: str
    name: str
    device_type: str
    public_key: str
    private_key: str
    cloud_key_sync_pending: bool = True
    _private: Ed25519PrivateKey = field(repr=False, compare=False, default=None)

    @classmethod
    def generate(cls) -> "DeviceIdentity":
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        private_raw = private.private_bytes(
            Encoding.Raw,
            PrivateFormat.Raw,
            NoEncryption(),
        )
        public_raw = public.public_bytes(Encoding.Raw, PublicFormat.Raw)
        hostname = socket.gethostname().strip() or "Windows"
        return cls(
            user_id=None,
            device_id=str(uuid.uuid4()),
            name=f"CoLink WS Debugger ({hostname})",
            device_type="windows",
            public_key=b64(public_raw),
            private_key=b64(private_raw),
            cloud_key_sync_pending=True,
            _private=private,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DeviceIdentity":
        private_key = str(data["privateKey"]).strip()
        private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_key))
        public_key = str(data.get("publicKey") or "").strip()
        if not public_key:
            public_key = b64(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        return cls(
            user_id=data.get("userId"),
            device_id=str(data["deviceId"]).strip(),
            name=str(data.get("name") or "CoLink WS Debugger").strip(),
            device_type=str(data.get("deviceType") or "windows").strip(),
            public_key=public_key,
            private_key=private_key,
            cloud_key_sync_pending=bool(data.get("cloudKeySyncPending", True)),
            _private=private,
        )

    def public(self) -> Ed25519PublicKey:
        return self._private.public_key()

    def summary(self) -> dict[str, Any]:
        return {
            "userId": self.user_id,
            "deviceId": self.device_id,
            "name": self.name,
            "deviceType": self.device_type,
            "publicKey": self.public_key,
            "cloudKeySyncPending": self.cloud_key_sync_pending,
        }

    def to_dict(self) -> dict[str, Any]:
        data = self.summary()
        data["privateKey"] = self.private_key
        return data

    def sign(self, payload: bytes) -> str:
        return b64(self._private.sign(payload))


def verify_ed25519(public_key: str, payload: bytes, signature: str) -> bool:
    try:
        verifier = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key))
        verifier.verify(base64.b64decode(signature), payload)
        return True
    except Exception:
        return False


@dataclass
class PeerState:
    device_id: str = ""
    name: str = ""
    device_type: str = ""
    public_key: str = ""
    protocol_version: str = ""
    business_version: str = ""
    hello_received: bool = False
    hello_ack_received: bool = False
    local_nonce: str = ""
    peer_nonce: str = ""
    pairing_request_nonce: str = ""
    pairing_exchange_nonce: str = ""
    ephemeral_public_key: str = ""
    supported_suites: list[str] = field(default_factory=list)
    preferred_suite: str = ""


@dataclass
class LanProtocolSession:
    identity: DeviceIdentity
    peer: PeerState = field(default_factory=PeerState)
    seq: int = 1
    last_sent_id: str | None = None
    last_received_id: str | None = None
    local_ephemeral_private: X25519PrivateKey | None = field(default=None, repr=False)
    local_ephemeral_public: str = ""
    negotiated_suite: str = ""
    outbound_role: int = 0
    encryption_counter: int = 0
    session_key: bytes | None = field(default=None, repr=False)

    def reset_connection_state(self) -> None:
        self.peer = PeerState()
        self.seq = 1
        self.last_sent_id = None
        self.last_received_id = None
        self.local_ephemeral_private = None
        self.local_ephemeral_public = ""
        self.negotiated_suite = ""
        self.outbound_role = 0
        self.encryption_counter = 0
        self.session_key = None

    def ingest(self, message: Any) -> None:
        if not isinstance(message, dict):
            return
        message_type = message.get("type")
        payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
        if isinstance(message.get("id"), str):
            self.last_received_id = message["id"]
        if message_type == "protocol.hello":
            self.peer.device_id = str(payload.get("deviceId") or "")
            self.peer.protocol_version = str(payload.get("protocolVersion") or "")
            self.peer.hello_received = True
            return
        if message_type == "protocol.hello-ack":
            self.peer.hello_ack_received = bool(payload.get("compatible"))
            return
        from_device = message.get("from")
        if isinstance(from_device, str) and from_device:
            self.peer.device_id = from_device
        if message_type == "auth.v1.challenge":
            self.peer.peer_nonce = str(payload.get("nonce") or "")
            return
        if message_type == "pairing.v1.request":
            self.peer.public_key = str(payload.get("publicKey") or self.peer.public_key)
            self.peer.name = str(payload.get("name") or self.peer.name)
            self.peer.pairing_request_nonce = str(payload.get("nonce") or "")
            return
        if message_type == "pairing.v1.exchange":
            self.peer.public_key = str(payload.get("publicKey") or self.peer.public_key)
            self.peer.name = str(payload.get("name") or self.peer.name)
            self.peer.pairing_exchange_nonce = str(payload.get("nonce") or "")
            return
        if message_type == "business.v1.version":
            self.peer.business_version = str(payload.get("businessVersion") or "")
            return
        if message_type == "business.v1.key-exchange":
            self.peer.ephemeral_public_key = str(payload.get("ephemeralPublicKey") or "")
            return
        if message_type == "business.v1.negotiate":
            supported = payload.get("supported")
            self.peer.supported_suites = [str(item) for item in supported] if isinstance(supported, list) else []
            self.peer.preferred_suite = str(payload.get("preferred") or "")

    def verify_auth_response(self, message: dict[str, Any]) -> bool:
        if not self.peer.public_key:
            return False
        payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
        signature = str(payload.get("signature") or "")
        sender = str(message.get("from") or "")
        timestamp = message.get("timestamp")
        if not signature or not sender or timestamp is None or not self.peer.local_nonce:
            return False
        canonical = f"from={sender}\ntimestamp={timestamp}\nnonce={self.peer.local_nonce}".encode()
        return verify_ed25519(self.peer.public_key, canonical, signature)

    def verify_key_exchange(self, message: dict[str, Any]) -> bool:
        if not self.peer.public_key:
            return False
        payload = message.get("payload") if isinstance(message.get("payload"), dict) else {}
        ephemeral_public_key = str(payload.get("ephemeralPublicKey") or "")
        signature = str(payload.get("signature") or "")
        sender = str(message.get("from") or "")
        receiver = str(message.get("to") or "")
        timestamp = message.get("timestamp")
        if not ephemeral_public_key or not signature or not sender or not receiver or timestamp is None:
            return False
        canonical = (
            "domain=colink-lan-key-exchange\n"
            f"from={sender}\n"
            f"to={receiver}\n"
            f"ephemeralPublicKey={ephemeral_public_key}\n"
            f"timestamp={timestamp}"
        ).encode()
        return verify_ed25519(self.peer.public_key, canonical, signature)

    def bare(self, message_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        return {"type": message_type, "payload": payload}

    def envelope(
        self,
        message_type: str,
        payload: dict[str, Any] | None = None,
        correlation_id: str | None = None,
    ) -> dict[str, Any]:
        message_id = str(uuid.uuid4())
        envelope = {
            "id": message_id,
            "type": message_type,
            "from": self.identity.device_id,
            "to": self.peer.device_id or "peer-device-id",
            "seq": self.seq,
            "timestamp": now_millis(),
            "correlationId": correlation_id,
            "payload": payload or {},
        }
        self.seq += 1
        self.last_sent_id = message_id
        return envelope

    def protocol_hello(self) -> dict[str, Any]:
        return self.bare(
            "protocol.hello",
            {
                "deviceId": self.identity.device_id,
                "protocolVersion": PROTOCOL_VERSION,
                "extensions": {
                    "name": self.identity.name,
                    "deviceType": self.identity.device_type,
                },
            },
        )

    def protocol_hello_ack(self, compatible: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {"compatible": compatible}
        if not compatible:
            payload.update(
                {
                    "reason": "colink:protocol.generic.v1",
                    "message": "Rejected by debugger operator",
                },
            )
        return self.bare("protocol.hello-ack", payload)

    def auth_challenge(self) -> dict[str, Any]:
        self.peer.local_nonce = random_nonce()
        return self.envelope("auth.v1.challenge", {"nonce": self.peer.local_nonce})

    def auth_response(self) -> dict[str, Any]:
        nonce = self.peer.peer_nonce or "peer_nonce_missing"
        timestamp = now_millis()
        payload = f"from={self.identity.device_id}\ntimestamp={timestamp}\nnonce={nonce}".encode()
        envelope = self.envelope("auth.v1.response", {"signature": self.identity.sign(payload)})
        envelope["timestamp"] = timestamp
        return envelope

    def auth_verified(self) -> dict[str, Any]:
        return self.envelope("auth.v1.verified", {})

    def auth_reject(self) -> dict[str, Any]:
        return self.envelope(
            "auth.v1.reject",
            {
                "reason": "colink:auth.unknown_device.v1",
                "message": "No persisted trust record in temporary debugger session",
            },
        )

    def pairing_request(self) -> dict[str, Any]:
        self.peer.pairing_request_nonce = random_nonce()
        return self.envelope(
            "pairing.v1.request",
            {
                "publicKey": self.identity.public_key,
                "name": self.identity.name,
                "type": self.identity.device_type,
                "nonce": self.peer.pairing_request_nonce,
            },
        )

    def pairing_exchange(self) -> dict[str, Any]:
        self.peer.pairing_exchange_nonce = random_nonce()
        return self.envelope(
            "pairing.v1.exchange",
            {
                "publicKey": self.identity.public_key,
                "name": self.identity.name,
                "type": self.identity.device_type,
                "nonce": self.peer.pairing_exchange_nonce,
            },
        )

    def pairing_confirm(self) -> dict[str, Any]:
        return self.envelope("pairing.v1.confirm", {})

    def pairing_complete(self) -> dict[str, Any]:
        return self.envelope("pairing.v1.complete", {})

    def pairing_reject(self) -> dict[str, Any]:
        return self.envelope(
            "pairing.v1.reject",
            {
                "reason": "colink:pairing.user_rejected.v1",
                "message": "Rejected by debugger operator",
            },
        )

    def pairing_code(self) -> str:
        peer_key = self.peer.public_key
        nonce_a = self.peer.pairing_request_nonce
        nonce_b = self.peer.pairing_exchange_nonce
        if not peer_key or not nonce_a or not nonce_b:
            return ""
        keys = sorted([self.identity.public_key, peer_key])
        canonical = (
            "domain=colink-lan-pairing-code\n"
            f"publicKeyA={keys[0]}\n"
            f"publicKeyB={keys[1]}\n"
            f"nonceA={nonce_a}\n"
            f"nonceB={nonce_b}"
        )
        digest = hashlib.sha256(canonical.encode()).digest()
        value = int.from_bytes(digest[:8], "big") % 1_000_000
        return f"{value:06d}"

    def business_version(self) -> dict[str, Any]:
        return self.envelope(
            "business.v1.version",
            {"businessVersion": BUSINESS_VERSION},
        )

    def business_version_ack(self, compatible: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {"compatible": compatible}
        if not compatible:
            payload.update(
                {
                    "reason": "colink:business.generic.v1",
                    "message": "Rejected by debugger operator",
                },
            )
        return self.envelope("business.v1.version-ack", payload)

    def business_key_exchange(self) -> dict[str, Any]:
        self.local_ephemeral_private = X25519PrivateKey.generate()
        public = self.local_ephemeral_private.public_key().public_bytes(
            Encoding.Raw,
            PublicFormat.Raw,
        )
        self.local_ephemeral_public = b64(public)
        timestamp = now_millis()
        peer_id = self.peer.device_id or "peer-device-id"
        canonical = (
            "domain=colink-lan-key-exchange\n"
            f"from={self.identity.device_id}\n"
            f"to={peer_id}\n"
            f"ephemeralPublicKey={self.local_ephemeral_public}\n"
            f"timestamp={timestamp}"
        )
        envelope = self.envelope(
            "business.v1.key-exchange",
            {
                "ephemeralPublicKey": self.local_ephemeral_public,
                "signature": self.identity.sign(canonical.encode()),
            },
        )
        envelope["timestamp"] = timestamp
        return envelope

    def business_key_exchange_reject(self) -> dict[str, Any]:
        return self.envelope(
            "business.v1.key-exchange-reject",
            {
                "reason": "colink:key_exchange.generic.v1",
                "message": "Rejected by debugger operator",
            },
        )

    def business_negotiate(self) -> dict[str, Any]:
        return self.envelope(
            "business.v1.negotiate",
            {
                "supported": SUPPORTED_SUITES,
                "preferred": AES_256_GCM_SUITE,
            },
        )

    def choose_suite(self, local_is_initiator: bool) -> str:
        peer_supported = self.peer.supported_suites or SUPPORTED_SUITES
        ordered = SUPPORTED_SUITES if local_is_initiator else peer_supported
        other = peer_supported if local_is_initiator else SUPPORTED_SUITES
        for suite in ordered:
            if suite in other:
                self.negotiated_suite = suite
                self.outbound_role = 0 if local_is_initiator else 1
                return suite
        raise ValueError("No compatible business cipher suite.")

    def ensure_session_key(self) -> bytes:
        if self.session_key is not None:
            return self.session_key
        if self.local_ephemeral_private is None:
            raise ValueError("Local ephemeral key is missing. Run business.v1.key-exchange first.")
        if not self.peer.ephemeral_public_key:
            raise ValueError("Peer ephemeral key is missing. Wait for business.v1.key-exchange.")
        suite = self.negotiated_suite or self.choose_suite(local_is_initiator=True)
        peer_public = base64.b64decode(self.peer.ephemeral_public_key)
        shared = self.local_ephemeral_private.exchange(X25519PublicKey.from_public_bytes(peer_public))
        local_first = self.identity.device_id <= self.peer.device_id
        if local_first:
            from_id = self.identity.device_id
            to_id = self.peer.device_id
            ephemeral_a = self.local_ephemeral_public
            ephemeral_b = self.peer.ephemeral_public_key
        else:
            from_id = self.peer.device_id
            to_id = self.identity.device_id
            ephemeral_a = self.peer.ephemeral_public_key
            ephemeral_b = self.local_ephemeral_public
        info = (
            "domain=colink-lan-session-key\n"
            f"from={from_id}\n"
            f"to={to_id}\n"
            f"ephemeralA={ephemeral_a}\n"
            f"ephemeralB={ephemeral_b}\n"
            f"protocolVersion={PROTOCOL_VERSION}\n"
            f"suite={suite}"
        ).encode()
        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"colink-lan-v2",
            info=info,
        ).derive(shared)
        return self.session_key

    def next_nonce(self) -> bytes:
        nonce = bytearray(12)
        nonce[0] = self.outbound_role
        nonce[4:] = self.encryption_counter.to_bytes(8, "big")
        self.encryption_counter = (self.encryption_counter + 1) & 0xFFFFFFFFFFFFFFFF
        return bytes(nonce)

    def encrypt_business_payload(self, inner: dict[str, Any]) -> dict[str, str]:
        key = self.ensure_session_key()
        nonce = self.next_nonce()
        plaintext = json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode()
        suite = self.negotiated_suite or AES_256_GCM_SUITE
        if suite == CHACHA20_POLY1305_SUITE:
            ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
        else:
            ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        return {"ciphertext": b64(ciphertext), "nonce": b64(nonce)}

    def decrypt_business_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        key = self.ensure_session_key()
        nonce = base64.b64decode(str(payload.get("nonce") or ""))
        ciphertext = base64.b64decode(str(payload.get("ciphertext") or ""))
        suite = self.negotiated_suite or AES_256_GCM_SUITE
        if suite == CHACHA20_POLY1305_SUITE:
            plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
        else:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
        value = json.loads(plaintext.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Decrypted business message is not an object.")
        return value

    def business_message(self, inner: dict[str, Any]) -> dict[str, Any]:
        return self.envelope("business.v1.message", self.encrypt_business_payload(inner))

    def business_text_message(self) -> dict[str, Any]:
        return self.business_message(
            {
                "type": "message.v1.text",
                "payload": {
                    "messageId": str(uuid.uuid4()),
                    "text": "Hello from CoLink WebSocket Debugger",
                },
            },
        )

    def business_clipboard_sync(self) -> dict[str, Any]:
        return self.business_message(
            {
                "type": "clipboard.v1.sync",
                "payload": {
                    "contentType": "text/plain",
                    "content": "Clipboard text from CoLink WebSocket Debugger",
                    "data": None,
                },
            },
        )

    def business_sysinfo_alive(self) -> dict[str, Any]:
        return self.business_message({"type": "sysinfo.v1.alive", "payload": {}})

    def business_sysinfo_stats(self) -> dict[str, Any]:
        return self.business_message(
            {
                "type": "sysinfo.v1.stats",
                "payload": {
                    "cpu": 12.5,
                    "mem": 45.0,
                    "gpu": None,
                },
            },
        )

    def business_music_track(self) -> dict[str, Any]:
        return self.business_message(
            {
                "type": "music.v1.track",
                "payload": {
                    "trackId": "debug-track-001",
                    "title": "Debugger Signal",
                    "artists": ["CoLink Debugger"],
                    "album": "Protocol Session",
                    "source": "ncm",
                    "coverUrl": None,
                    "coverData": None,
                    "duration": 180000,
                },
            },
        )

    def business_music_lyric(self) -> dict[str, Any]:
        return self.business_message(
            {
                "type": "music.v1.lyric",
                "payload": {
                    "trackId": "debug-track-001",
                    "lines": [
                        {"time": 0, "text": "Debugger session started"},
                        {"time": 15000, "text": "Encrypted frames are flowing"},
                        {"time": 30000, "text": "CoLink LAN protocol is alive"},
                    ],
                    "translatedLines": [
                        {"time": 0, "text": "调试会话已开始"},
                        {"time": 15000, "text": "加密帧正在流动"},
                        {"time": 30000, "text": "CoLink LAN 协议已连通"},
                    ],
                },
            },
        )

    def business_music_progress(self) -> dict[str, Any]:
        return self.business_message(
            {
                "type": "music.v1.progress",
                "payload": {
                    "trackId": "debug-track-001",
                    "progress": 30000,
                    "paused": False,
                },
            },
        )

    def business_music_alive(self) -> dict[str, Any]:
        return self.business_message({"type": "music.v1.alive", "payload": {}})

    def business_music_request(self) -> dict[str, Any]:
        return self.business_message({"type": "music.v1.request", "payload": {}})

    def heartbeat_ping(self) -> dict[str, Any]:
        return self.envelope("heartbeat.v1.ping", {})

    def heartbeat_pong(self) -> dict[str, Any]:
        return self.envelope("heartbeat.v1.pong", {}, self.last_received_id)

    def template(self, name: str) -> dict[str, Any]:
        templates = {
            "protocol.hello": self.protocol_hello,
            "protocol.hello-ack": self.protocol_hello_ack,
            "auth.v1.challenge": self.auth_challenge,
            "auth.v1.response": self.auth_response,
            "auth.v1.verified": self.auth_verified,
            "auth.v1.reject": self.auth_reject,
            "pairing.v1.request": self.pairing_request,
            "pairing.v1.exchange": self.pairing_exchange,
            "pairing.v1.confirm": self.pairing_confirm,
            "pairing.v1.complete": self.pairing_complete,
            "pairing.v1.reject": self.pairing_reject,
            "business.v1.version": self.business_version,
            "business.v1.version-ack": self.business_version_ack,
            "business.v1.key-exchange": self.business_key_exchange,
            "business.v1.key-exchange-reject": self.business_key_exchange_reject,
            "business.v1.negotiate": self.business_negotiate,
            "business.message.text": self.business_text_message,
            "business.clipboard.sync": self.business_clipboard_sync,
            "business.sysinfo.alive": self.business_sysinfo_alive,
            "business.sysinfo.stats": self.business_sysinfo_stats,
            "business.music.track": self.business_music_track,
            "business.music.lyric": self.business_music_lyric,
            "business.music.progress": self.business_music_progress,
            "business.music.alive": self.business_music_alive,
            "business.music.request": self.business_music_request,
            "heartbeat.v1.ping": self.heartbeat_ping,
            "heartbeat.v1.pong": self.heartbeat_pong,
        }
        return templates[name]()


TEMPLATE_GROUPS = {
    "Version Negotiation": ["protocol.hello", "protocol.hello-ack"],
    "Authentication": [
        "auth.v1.challenge",
        "auth.v1.response",
        "auth.v1.verified",
        "auth.v1.reject",
    ],
    "Pairing": [
        "pairing.v1.request",
        "pairing.v1.exchange",
        "pairing.v1.confirm",
        "pairing.v1.complete",
        "pairing.v1.reject",
    ],
    "Business": [
        "business.v1.version",
        "business.v1.version-ack",
        "business.v1.key-exchange",
        "business.v1.key-exchange-reject",
        "business.v1.negotiate",
        "business.message.text",
        "business.clipboard.sync",
        "business.sysinfo.alive",
        "business.sysinfo.stats",
        "business.music.track",
        "business.music.lyric",
        "business.music.progress",
        "business.music.alive",
        "business.music.request",
    ],
    "Keepalive": ["heartbeat.v1.ping", "heartbeat.v1.pong"],
}
