from __future__ import annotations

import json
from pathlib import Path

from colink_ws_debugger.protocol import DeviceIdentity


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def data_dir() -> Path:
    return project_root() / "data"


def identity_path() -> Path:
    return data_dir() / "identity.json"


def load_or_create_identity() -> DeviceIdentity:
    path = identity_path()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return DeviceIdentity.from_dict(data)
        except Exception:
            pass
    identity = DeviceIdentity.generate()
    save_identity(identity)
    return identity


def save_identity(identity: DeviceIdentity) -> None:
    path = identity_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(identity.to_dict(), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def regenerate_identity() -> DeviceIdentity:
    identity = DeviceIdentity.generate()
    save_identity(identity)
    return identity
