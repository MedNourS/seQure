# seQure

Single client + relay server with **post‑quantum key exchange**.

## What is included?

- CLI client (encrypted chat + file transfer)
- Relay server for peer discovery
- PQC handshake (Kyber512 KEM) + ChaCha20‑Poly1305 session encryption

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ./client
pip install -e ./server
```

## Run relay

```bash
python server/app.py
```

## Run client (two terminals)

```bash
python client/app.py --relay-host 127.0.0.1 --relay-port 9999
```

Or install the CLI and run:

```bash
sequre --relay-host 127.0.0.1 --relay-port 9999
```

## How does it work?

1. The clients connect to a relay, which is only used to store a UUID hash and a network socket
2. The client attempts to connect to a peer, and waits for the peer to connect back to the client
3. On a mutual connection, an intro packet is sent with the client's public key and a random nonce
4. The receiving client performs a PQC key exchange using Kyber512, and sends back an intro response with its own public key and nonce
5. Both clients compute the shared secret and derive a symmetric session key, which is used to encrypt all subsequent payloads with ChaCha20‑Poly1305
6. Clients can exchange encrypted chat messages and files until one client sends a BYE packet or disconnects


> NOTE: The relay server is not involved in the key exchange or encrypted communication, and cannot read the contents of the messages or files. The relay only facilitates peer discovery and connection setup. All communication remains peer to peer and end‑to‑end encrypted.