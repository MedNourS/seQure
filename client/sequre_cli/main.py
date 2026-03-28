import argparse
import hashlib
import json
import socket
import time

from .client import Client


def uuid_hash(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def relay_request(relay_host: str, relay_port: int, payload: dict, timeout: float = 5.0) -> dict:
    with socket.create_connection((relay_host, relay_port), timeout=timeout) as sock:
        file = sock.makefile("rwb")
        file.write((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
        file.flush()
        line = file.readline()
        if not line:
            raise RuntimeError("Relay closed connection")
        return json.loads(line.decode("utf-8"))


def relay_unregister(relay_host: str, relay_port: int, my_hash: str) -> None:
    try:
        relay_request(relay_host, relay_port, {"action": "unregister", "uuid_hash": my_hash})
    except Exception:
        pass


def print_relay_records(list_response: dict, my_hash: str | None = None) -> None:
    if not list_response.get("ok"):
        print(f"Relay list failed: {list_response}")
        return

    all_records = list_response.get("records", [])
    records = [rec for rec in all_records if rec.get("uuid_hash") != my_hash]
    print(f"Active relay records: {len(records)}")
    if not records:
        print("- No peers registered yet")
        return

    for rec in records:
        print(f"- {rec['uuid_hash']} @ {rec['ip']}:{rec['port']} (age {rec.get('age', 0)}s)")


def run() -> None:
    parser = argparse.ArgumentParser(description="seQure PQC CLI")
    parser.add_argument("--bind-ip", default="127.0.0.1", help="local bind IP")
    parser.add_argument("--relay-host", default="127.0.0.1", help="trusted relay host")
    parser.add_argument("--relay-port", type=int, default=9999, help="trusted relay port")
    args = parser.parse_args()

    me = Client(args.bind_ip)
    print(f"UUID: {me.UUID}")
    my_hash = uuid_hash(me.UUID)
    print(f"UUID hash: {my_hash}")
    my_port = me.listening_socket.getsockname()[1]
    print(f"Port: {my_port}")

    register_response = relay_request(
        args.relay_host,
        args.relay_port,
        {"action": "register", "uuid_hash": my_hash, "port": my_port},
    )
    if not register_response.get("ok"):
        raise RuntimeError(f"Relay register failed: {register_response}")

    print(f"Registered on relay as: {my_hash}")

    list_choice = input("Show active relay records now? [y/N]\n> ").strip().lower()
    if list_choice in {"y", "yes"}:
        list_response = relay_request(args.relay_host, args.relay_port, {"action": "list"})
        print_relay_records(list_response, my_hash=my_hash)

    target_ip = None
    target_port = None
    peer_hash = None
    while True:
        peer_identifier = input("Enter peer UUID/hash (or /list):\n> ").strip()
        if not peer_identifier:
            continue
        if peer_identifier.lower() == "/list":
            list_response = relay_request(args.relay_host, args.relay_port, {"action": "list"})
            print_relay_records(list_response, my_hash=my_hash)
            continue

        peer_hash = peer_identifier.lower() if len(peer_identifier.strip()) == 64 else uuid_hash(peer_identifier)
        if peer_hash == my_hash:
            print("Cannot target your own UUID/hash.")
            continue

        resolve_response = relay_request(
            args.relay_host,
            args.relay_port,
            {"action": "resolve", "uuid_hash": peer_hash},
        )
        if not resolve_response.get("ok"):
            if resolve_response.get("error") == "not_found":
                print("Peer not found on relay yet. Retry in 1s.")
                time.sleep(1)
                continue
            raise RuntimeError(f"Relay resolve failed: {resolve_response}")

        target_ip = resolve_response["ip"]
        target_port = int(resolve_response["port"])
        break

    if my_hash < peer_hash:
        print("Role: initiator (connecting)")
        conn = None
        while conn is None:
            try:
                conn, _ = me.connect(target_ip, target_port)
            except OSError:
                print("Peer not ready, retrying...")
                time.sleep(1)
    else:
        print("Role: listener (waiting for incoming connection)")
        conn, _ = me.listen()

    relay_unregister(args.relay_host, args.relay_port, my_hash)

    try:
        me.start_session(conn)
    finally:
        relay_unregister(args.relay_host, args.relay_port, my_hash)
