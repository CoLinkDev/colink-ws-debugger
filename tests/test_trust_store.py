from colink_ws_debugger import trust_store
from colink_ws_debugger.trust_store import TrustedPeer


def test_trust_store_persists_peer(monkeypatch, tmp_path):
    monkeypatch.setattr(trust_store, "data_dir", lambda: tmp_path)

    trust_store.upsert_trusted_peer(
        TrustedPeer(device_id="peer-1", name="Peer", public_key="key"),
    )
    peers = trust_store.load_trust_store()

    assert peers["peer-1"].name == "Peer"
    assert peers["peer-1"].public_key == "key"


def test_trusted_peer_from_session_requires_id_and_key():
    assert trust_store.trusted_peer_from_session("", "Peer", "key") is None
    assert trust_store.trusted_peer_from_session("peer", "Peer", "") is None
    peer = trust_store.trusted_peer_from_session("peer", "", "key")

    assert peer is not None
    assert peer.name == "peer"
