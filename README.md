# CoLink WebSocket Debugger

Standalone PySide6 WebSocket debugger for CoLink LAN protocol work.

**Tech stack:** Python 3.11+ · PySide6 · websockets · cryptography (Ed25519)

## Run

```powershell
uv sync
uv run colink-ws-debugger
```

Each process creates a temporary local device identity in memory. The identity includes device ID, name, device type, Ed25519 key pair and protocol metadata. Nothing is persisted.

## Features

- Connect to arbitrary `ws://` or `wss://` endpoints.
- Send custom text, JSON and binary frames.
- Inspect inbound and outbound frames with raw and parsed views.
- Generate CoLink LAN envelopes with monotonically increasing sequence numbers.
- Send predefined protocol templates for hello, auth, pairing, business negotiation and heartbeat.
- Sign `auth.v1.response` and `business.v1.key-exchange` with the temporary local identity.
- Calculate pairing codes from real public keys and nonces.
- Inspect and simulate SWIM membership protocol messages.

## Tests

```powershell
uv run pytest
```
