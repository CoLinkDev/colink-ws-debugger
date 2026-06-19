import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from colink_ws_debugger.protocol import DeviceIdentity, LanProtocolSession


def test_identity_contains_colink_device_fields():
    identity = DeviceIdentity.generate()
    summary = identity.summary()

    assert summary["deviceId"]
    assert summary["name"]
    assert summary["deviceType"] == "windows"
    assert summary["publicKey"]
    assert "privateKey" not in summary


def test_auth_response_signature_verifies():
    identity = DeviceIdentity.generate()
    session = LanProtocolSession(identity)
    session.peer.device_id = "peer"
    session.peer.peer_nonce = "nonce"

    message = session.auth_response()
    payload = (
        f"from={identity.device_id}\n"
        f"timestamp={message['timestamp']}\n"
        "nonce=nonce"
    ).encode()
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(identity.public_key))
    public_key.verify(base64.b64decode(message["payload"]["signature"]), payload)


def test_pairing_code_is_stable():
    first = LanProtocolSession(DeviceIdentity.generate())
    second = LanProtocolSession(DeviceIdentity.generate())
    first.peer.public_key = second.identity.public_key
    second.peer.public_key = first.identity.public_key
    first.peer.pairing_request_nonce = "nonce-a"
    first.peer.pairing_exchange_nonce = "nonce-b"
    second.peer.pairing_request_nonce = "nonce-a"
    second.peer.pairing_exchange_nonce = "nonce-b"

    assert first.pairing_code() == second.pairing_code()
    assert len(first.pairing_code()) == 6


def test_key_exchange_signature_verifies():
    identity = DeviceIdentity.generate()
    session = LanProtocolSession(identity)
    session.peer.device_id = "peer"

    message = session.business_key_exchange()
    payload = (
        "domain=colink-lan-key-exchange\n"
        f"from={identity.device_id}\n"
        "to=peer\n"
        f"ephemeralPublicKey={message['payload']['ephemeralPublicKey']}\n"
        f"timestamp={message['timestamp']}"
    ).encode()
    public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(identity.public_key))
    public_key.verify(base64.b64decode(message["payload"]["signature"]), payload)


def test_auth_template_does_not_create_hello():
    session = LanProtocolSession(DeviceIdentity.generate())
    session.peer.device_id = "peer"

    message = session.auth_challenge()

    assert message["type"] == "auth.v1.challenge"
    assert session.peer.hello_received is False


def test_pairing_template_does_not_create_hello():
    session = LanProtocolSession(DeviceIdentity.generate())
    session.peer.device_id = "peer"

    message = session.pairing_request()

    assert message["type"] == "pairing.v1.request"
    assert session.peer.hello_received is False


def test_business_message_encrypts_inner_payload():
    first = LanProtocolSession(DeviceIdentity.generate())
    second = LanProtocolSession(DeviceIdentity.generate())
    first.peer.device_id = second.identity.device_id
    first.peer.public_key = second.identity.public_key
    second.peer.device_id = first.identity.device_id
    second.peer.public_key = first.identity.public_key

    first_key_exchange = first.business_key_exchange()
    second_key_exchange = second.business_key_exchange()
    first.ingest(second_key_exchange)
    second.ingest(first_key_exchange)
    first.peer.supported_suites = ["x25519-aes-256-gcm", "x25519-chacha20-poly1305"]
    second.peer.supported_suites = ["x25519-aes-256-gcm", "x25519-chacha20-poly1305"]
    first.choose_suite(local_is_initiator=True)
    second.choose_suite(local_is_initiator=False)

    encrypted = first.business_text_message()
    payload = encrypted["payload"]

    assert encrypted["type"] == "business.v1.message"
    assert "base64(AEAD" not in payload["ciphertext"]
    assert second.decrypt_business_payload(payload)["type"] == "message.v1.text"


def test_music_template_encrypts_inner_payload():
    first = LanProtocolSession(DeviceIdentity.generate())
    second = LanProtocolSession(DeviceIdentity.generate())
    first.peer.device_id = second.identity.device_id
    first.peer.public_key = second.identity.public_key
    second.peer.device_id = first.identity.device_id
    second.peer.public_key = first.identity.public_key

    first_key_exchange = first.business_key_exchange()
    second_key_exchange = second.business_key_exchange()
    first.ingest(second_key_exchange)
    second.ingest(first_key_exchange)
    first.peer.supported_suites = ["x25519-aes-256-gcm", "x25519-chacha20-poly1305"]
    second.peer.supported_suites = ["x25519-aes-256-gcm", "x25519-chacha20-poly1305"]
    first.choose_suite(local_is_initiator=True)
    second.choose_suite(local_is_initiator=False)

    encrypted = first.business_music_track()

    assert encrypted["type"] == "business.v1.message"
    assert second.decrypt_business_payload(encrypted["payload"])["type"] == "music.v1.track"


def test_new_key_exchange_clears_previous_session_key():
    first = LanProtocolSession(DeviceIdentity.generate())
    second = LanProtocolSession(DeviceIdentity.generate())
    first.peer.device_id = second.identity.device_id
    first.peer.public_key = second.identity.public_key
    second.peer.device_id = first.identity.device_id
    second.peer.public_key = first.identity.public_key

    first_key_exchange = first.business_key_exchange()
    second_key_exchange = second.business_key_exchange()
    first.ingest(second_key_exchange)
    second.ingest(first_key_exchange)
    first.peer.supported_suites = ["x25519-aes-256-gcm"]
    second.peer.supported_suites = ["x25519-aes-256-gcm"]
    first.choose_suite(local_is_initiator=True)
    second.choose_suite(local_is_initiator=False)
    first.ensure_session_key()
    assert first.session_key is not None

    first.business_key_exchange()

    assert first.session_key is None
    assert first.encryption_counter == 0
