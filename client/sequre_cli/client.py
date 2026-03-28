import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from pqcrypto.kem import ml_kem_512 as _pqc_kem
except ImportError:
    from pqcrypto.kem import kyber512 as _pqc_kem

from .peer import Peer
from .utils import PacketType


class Client:
    def __init__(self, ip: str = "127.0.0.1", port: int = 0):
        self.UUID = str(uuid.uuid4())
        self.ADDRESS = ip
        self.PORT = port
        self.MAGIC_NUMBER = 0xDEAD
        self.TIMEOUT = 30

        self.listening_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listening_socket.bind((self.ADDRESS, self.PORT))

        self.file_chunk_size = 16 * 1024
        self.incoming_files = {}

        self.pqc_public_key, self.pqc_private_key = _pqc_kem.generate_keypair()
        self.peer = None
        self.session_key = None

        self.send_lock = threading.Lock()
        self.crypto_lock = threading.Lock()
        self.hb_lock = threading.Lock()
        self.heartbeat_interval = 10
        self.awaiting_pong = False
        self.last_ping_sent_at = 0.0
        self.last_ping_id = None

    def connect(self, peer_ip: str, peer_port: int):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((peer_ip, peer_port))
        return conn, peer_ip

    def listen(self):
        self.listening_socket.listen()
        return self.listening_socket.accept()

    def start_session(self, conn: socket.socket):
        try:
            self.peer = self.handshake(conn)
        except Exception as e:
            print(f"Handshake failed: {e}")
            self.safe_close(conn)
            return

        stop_event = threading.Event()
        recv_thread = threading.Thread(target=self.receive_loop, args=(conn, stop_event), daemon=True)
        send_thread = threading.Thread(target=self.send_loop, args=(conn, stop_event), daemon=True)
        hb_thread = threading.Thread(target=self.heartbeat_loop, args=(conn, stop_event), daemon=True)

        recv_thread.start()
        send_thread.start()
        hb_thread.start()

        recv_thread.join()
        send_thread.join()
        hb_thread.join()

    def handshake(self, conn: socket.socket):
        intro = {
            "UUID": self.UUID,
            "PQC_PUBKEY": base64.b64encode(self.pqc_public_key).decode(),
            "TIMEOUT": self.TIMEOUT,
        }
        self.send(conn, self.make_packet(PacketType.HELLO, json.dumps(intro, sort_keys=True)))

        packet_type, payload = self.read_packet(conn, expect_hello=True)
        if packet_type != PacketType.HELLO.value:
            raise ValueError("Expected HELLO packet")

        their_intro = json.loads(payload["content"])
        if their_intro.get("UUID") == self.UUID:
            raise ValueError("Refusing self-connection")

        peer_pqc_pubkey = base64.b64decode(their_intro["PQC_PUBKEY"].encode())
        self._exchange_pqc_kem(conn, peer_pqc_pubkey)

        conn.settimeout(int(their_intro.get("TIMEOUT", self.TIMEOUT)))
        print(f"Peer UUID:   {their_intro['UUID']}")
        print("PQC secure session established.")

        return Peer(their_intro["UUID"], their_intro["PQC_PUBKEY"], int(their_intro.get("TIMEOUT", self.TIMEOUT)))

    def receive_loop(self, conn: socket.socket, stop_event: threading.Event):
        try:
            while not stop_event.is_set():
                try:
                    packet_type, payload = self.read_packet(conn)
                except ConnectionError:
                    print("Peer disconnected")
                    break
                except ValueError as e:
                    print(f"Bad packet: {e}")
                    continue

                if packet_type == PacketType.BYE.value:
                    print("Peer disconnected")
                    break

                try:
                    if packet_type == PacketType.PING.value:
                        cleartext = self.decrypt_content(payload["content"])
                        ping_payload = json.loads(cleartext)
                        pong_payload = {"id": ping_payload.get("id")}
                        self.send(conn, self.make_secure_packet(PacketType.PONG, json.dumps(pong_payload, sort_keys=True)))
                        continue

                    if packet_type == PacketType.PONG.value:
                        cleartext = self.decrypt_content(payload["content"])
                        pong_payload = json.loads(cleartext)
                        with self.hb_lock:
                            if self.last_ping_id and pong_payload.get("id") == self.last_ping_id:
                                self.awaiting_pong = False
                                self.last_ping_id = None
                        continue

                    if packet_type == PacketType.DATA.value:
                        msg = self.decrypt_content(payload["content"])
                        print(f"\nPeer: {msg}")
                        print("> ", end="", flush=True)
                        continue

                    if packet_type == PacketType.FILE_META.value:
                        self.handle_file_meta(payload["content"])
                        print("> ", end="", flush=True)
                        continue

                    if packet_type == PacketType.FILE_CHUNK.value:
                        self.handle_file_chunk(payload["content"])
                        continue

                    if packet_type == PacketType.FILE_END.value:
                        self.handle_file_end(payload["content"])
                        print("> ", end="", flush=True)
                        continue
                except Exception as e:
                    print(f"Failed to parse packet: {e}")
                    continue
        except socket.timeout:
            print("Peer timed out")
        except (OSError, ConnectionError):
            pass
        finally:
            for file_state in self.incoming_files.values():
                try:
                    file_state["handle"].close()
                except OSError:
                    pass
            self.incoming_files.clear()
            stop_event.set()
            self.safe_close(conn)

    def send_loop(self, conn: socket.socket, stop_event: threading.Event):
        try:
            while not stop_event.is_set():
                msg = input("> ")
                if msg.lower() == "/quit":
                    self.send(conn, self.make_secure_packet(PacketType.BYE, ""))
                    break
                if msg.startswith("/send "):
                    self.send_file(conn, msg[len("/send "):].strip())
                    continue
                self.send(conn, self.make_secure_packet(PacketType.DATA, msg))
        except (KeyboardInterrupt, OSError):
            pass
        finally:
            stop_event.set()
            self.safe_close(conn)

    def heartbeat_loop(self, conn: socket.socket, stop_event: threading.Event):
        try:
            while not stop_event.is_set():
                now = time.time()
                with self.hb_lock:
                    if self.awaiting_pong and now - self.last_ping_sent_at >= self.TIMEOUT:
                        print("Peer timed out (no heartbeat response)")
                        stop_event.set()
                        self.safe_close(conn)
                        break

                    if not self.awaiting_pong and now - self.last_ping_sent_at >= self.heartbeat_interval:
                        ping_id = str(uuid.uuid4())
                        payload = {"id": ping_id, "ts": int(now)}
                        self.send(conn, self.make_secure_packet(PacketType.PING, json.dumps(payload, sort_keys=True)))
                        self.last_ping_id = ping_id
                        self.last_ping_sent_at = now
                        self.awaiting_pong = True
                time.sleep(1)
        except OSError:
            stop_event.set()

    def send_file(self, conn_out: socket.socket, file_path: str):
        path = os.path.expanduser(file_path)
        if not os.path.isfile(path):
            print(f"File not found: {path}")
            return

        file_id = str(uuid.uuid4())
        file_name = os.path.basename(path)
        file_size = os.path.getsize(path)

        meta = {"file_id": file_id, "name": file_name, "size": file_size}
        self.send(conn_out, self.make_secure_packet(PacketType.FILE_META, json.dumps(meta, sort_keys=True)))

        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(self.file_chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
                chunk_payload = {
                    "file_id": file_id,
                    "data": base64.b64encode(chunk).decode(),
                }
                self.send(conn_out, self.make_secure_packet(PacketType.FILE_CHUNK, json.dumps(chunk_payload, sort_keys=True)))

        end_payload = {"file_id": file_id, "sha256": hasher.hexdigest()}
        self.send(conn_out, self.make_secure_packet(PacketType.FILE_END, json.dumps(end_payload, sort_keys=True)))
        print(f"Sent file '{file_name}' ({file_size} bytes)")

    def handle_file_meta(self, encrypted_content: str):
        cleartext = self.decrypt_content(encrypted_content)
        meta = json.loads(cleartext)

        file_id = meta["file_id"]
        file_name = os.path.basename(meta["name"])
        expected_size = int(meta["size"])

        download_dir = os.path.join(os.getcwd(), "downloads")
        os.makedirs(download_dir, exist_ok=True)

        base, ext = os.path.splitext(file_name)
        target_path = os.path.join(download_dir, file_name)
        i = 1
        while os.path.exists(target_path):
            target_path = os.path.join(download_dir, f"{base}_{i}{ext}")
            i += 1

        self.incoming_files[file_id] = {
            "path": target_path,
            "size": expected_size,
            "received": 0,
            "hasher": hashlib.sha256(),
            "handle": open(target_path, "wb"),
        }
        print(f"\nReceiving file '{file_name}' ({expected_size} bytes)...")

    def handle_file_chunk(self, encrypted_content: str):
        cleartext = self.decrypt_content(encrypted_content)
        chunk_payload = json.loads(cleartext)
        file_id = chunk_payload["file_id"]
        file_state = self.incoming_files.get(file_id)
        if not file_state:
            return

        raw_chunk = base64.b64decode(chunk_payload["data"].encode())
        file_state["handle"].write(raw_chunk)
        file_state["hasher"].update(raw_chunk)
        file_state["received"] += len(raw_chunk)

    def handle_file_end(self, encrypted_content: str):
        cleartext = self.decrypt_content(encrypted_content)
        payload = json.loads(cleartext)
        file_id = payload["file_id"]
        expected_hash = payload["sha256"]

        file_state = self.incoming_files.pop(file_id, None)
        if not file_state:
            return

        file_state["handle"].close()
        actual_hash = file_state["hasher"].hexdigest()
        if actual_hash != expected_hash:
            print(f"\nFile transfer failed integrity check: {file_state['path']}")
            try:
                os.remove(file_state["path"])
            except OSError:
                pass
        else:
            print(f"\nFile saved to {file_state['path']}")

    def make_secure_packet(self, packet_type: PacketType, content: str):
        if packet_type in {PacketType.HELLO, PacketType.KEM}:
            return self.make_packet(packet_type, content)
        encrypted_content = self.encrypt_content(content)
        return self.make_packet(packet_type, encrypted_content)

    def make_header(self, packet_type: PacketType, payload_length: int):
        if packet_type in {PacketType.HELLO, PacketType.KEM}:
            return struct.pack(">HBI", self.MAGIC_NUMBER, packet_type.value, payload_length)
        return struct.pack(">BI", packet_type.value, payload_length)

    def make_packet(self, packet_type: PacketType, content: str):
        payload = {
            "time": int(time.time()),
            "type": packet_type.name,
            "content": content,
        }

        clean_payload_bytes = json.dumps(payload, sort_keys=True).encode()
        payload["checksum"] = "0" * 64
        final_size = len(json.dumps(payload, sort_keys=True).encode())
        header = self.make_header(packet_type, final_size)

        payload["checksum"] = hashlib.sha256(header + clean_payload_bytes).hexdigest()
        final_payload = json.dumps(payload, sort_keys=True).encode()
        return header + final_payload

    def verify_packet(self, header: bytes, body: bytes):
        payload = json.loads(body.decode())
        checksum = payload.pop("checksum", None)
        if not checksum:
            return False

        clean_payload = json.dumps(payload, sort_keys=True).encode()
        expected_checksum = hashlib.sha256(header + clean_payload).hexdigest()
        return checksum == expected_checksum

    def send(self, conn_out: socket.socket, packet: bytes):
        with self.send_lock:
            conn_out.sendall(packet)

    def read_packet(self, conn: socket.socket, expect_hello: bool = False):
        if expect_hello:
            header = self.recv_exact(conn, 7)
            if not header:
                raise ConnectionError("Peer closed during HELLO")

            magic, packet_type, length = struct.unpack(">HBI", header)
            if magic != self.MAGIC_NUMBER:
                raise ValueError("Invalid HELLO magic")
        else:
            header = self.recv_exact(conn, 5)
            if not header:
                raise ConnectionError("Peer closed")

            packet_type, length = struct.unpack(">BI", header)

        body = self.recv_exact(conn, length)
        if not body:
            raise ConnectionError("Peer closed during packet body")
        if not self.verify_packet(header, body):
            raise ValueError("Checksum verification failed")

        payload = json.loads(body.decode())
        return packet_type, payload

    def safe_close(self, conn: socket.socket):
        try:
            conn.close()
        except OSError:
            pass

    def encrypt_content(self, content: str):
        with self.crypto_lock:
            key = self.session_key
        if not key:
            raise RuntimeError("Session key not established")

        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(12)
        ciphertext = aead.encrypt(nonce, content.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt_content(self, content: str):
        with self.crypto_lock:
            key = self.session_key
        if not key:
            raise RuntimeError("Session key not established")

        encrypted = base64.b64decode(content.encode())
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        cleartext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, None)
        return cleartext.decode()

    def _exchange_pqc_kem(self, conn: socket.socket, peer_pqc_pubkey: bytes) -> None:
        if hasattr(_pqc_kem, "encapsulate"):
            ct_out, ss_out = _pqc_kem.encapsulate(peer_pqc_pubkey)
        else:
            ct_out, ss_out = _pqc_kem.encrypt(peer_pqc_pubkey)
        self.send(conn, self.make_packet(PacketType.KEM, base64.b64encode(ct_out).decode()))

        packet_type, payload = self.read_packet(conn, expect_hello=True)
        if packet_type != PacketType.KEM.value:
            raise ValueError("Expected KEM packet")

        ct_in = base64.b64decode(payload["content"].encode())
        if hasattr(_pqc_kem, "decapsulate"):
            ss_in = _pqc_kem.decapsulate(ct_in, self.pqc_private_key)
        else:
            ss_in = _pqc_kem.decrypt(self.pqc_private_key, ct_in)

        # deterministic combine: order by public key bytes
        if self.pqc_public_key < peer_pqc_pubkey:
            key_material = ss_out + ss_in
        else:
            key_material = ss_in + ss_out

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"sequre-pqc-session",
        )
        with self.crypto_lock:
            self.session_key = hkdf.derive(key_material)

    def recv_exact(self, conn: socket.socket, size: int):
        chunks = []
        bytes_read = 0
        while bytes_read < size:
            chunk = conn.recv(size - bytes_read)
            if not chunk:
                return b""
            chunks.append(chunk)
            bytes_read += len(chunk)
        return b"".join(chunks)
