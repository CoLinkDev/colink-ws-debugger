import json

from colink_ws_debugger import identity_store


def test_load_or_create_identity_persists(monkeypatch, tmp_path):
    monkeypatch.setattr(identity_store, "data_dir", lambda: tmp_path)

    first = identity_store.load_or_create_identity()
    second = identity_store.load_or_create_identity()

    assert first.device_id == second.device_id
    assert first.public_key == second.public_key
    assert json.loads((tmp_path / "identity.json").read_text(encoding="utf-8"))["privateKey"]


def test_regenerate_identity_replaces_saved_identity(monkeypatch, tmp_path):
    monkeypatch.setattr(identity_store, "data_dir", lambda: tmp_path)

    first = identity_store.load_or_create_identity()
    second = identity_store.regenerate_identity()
    loaded = identity_store.load_or_create_identity()

    assert first.device_id != second.device_id
    assert loaded.device_id == second.device_id
