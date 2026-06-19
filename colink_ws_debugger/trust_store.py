from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from colink_ws_debugger.identity_store import data_dir


@dataclass
class TrustedPeer:
    device_id: str
    name: str
    public_key: str
    trusted_by_lan: bool = True


def trust_path() -> Path:
    return data_dir() / "trusted_peers.json"


def load_trust_store() -> dict[str, TrustedPeer]:
    path = trust_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, list):
        return {}
    peers: dict[str, TrustedPeer] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        device_id = str(item.get("deviceId") or item.get("device_id") or "").strip()
        public_key = str(item.get("publicKey") or item.get("public_key") or "").strip()
        if not device_id or not public_key:
            continue
        peers[device_id] = TrustedPeer(
            device_id=device_id,
            name=str(item.get("name") or device_id).strip(),
            public_key=public_key,
            trusted_by_lan=bool(item.get("trustedByLan", item.get("trusted_by_lan", True))),
        )
    return peers


def save_trust_store(peers: dict[str, TrustedPeer]) -> None:
    path = trust_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = [
        {
            "deviceId": peer.device_id,
            "name": peer.name,
            "publicKey": peer.public_key,
            "trustedByLan": peer.trusted_by_lan,
        }
        for peer in sorted(peers.values(), key=lambda item: (item.name.lower(), item.device_id))
    ]
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def upsert_trusted_peer(peer: TrustedPeer) -> dict[str, TrustedPeer]:
    peers = load_trust_store()
    peers[peer.device_id] = peer
    save_trust_store(peers)
    return peers


def trusted_peer_from_session(device_id: str, name: str, public_key: str) -> TrustedPeer | None:
    device_id = device_id.strip()
    public_key = public_key.strip()
    if not device_id or not public_key:
        return None
    return TrustedPeer(device_id=device_id, name=name.strip() or device_id, public_key=public_key)
