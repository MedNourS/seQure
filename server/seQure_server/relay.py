import json
import socket
import threading
import time


class RelayServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 9999, ttl_seconds: int = 600):
        self.host = host
        self.port = port
        self.ttl_seconds = ttl_seconds
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen()

        self._records = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

    def serve_forever(self) -> None:
        cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        cleanup_thread.start()

        print(f"Relay listening on {self.host}:{self.port}")
        try:
            while not self._stop_event.is_set():
                conn, addr = self._sock.accept()
                handler = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                handler.start()
        finally:
            self._stop_event.set()
            self._sock.close()

    def _cleanup_loop(self) -> None:
        while not self._stop_event.is_set():
            now = time.time()
            with self._lock:
                expired = [
                    key
                    for key, record in self._records.items()
                    if now - record["updated_at"] > self.ttl_seconds
                ]
                for key in expired:
                    self._records.pop(key, None)
            time.sleep(5)

    def _handle_client(self, conn: socket.socket, addr: tuple[str, int]) -> None:
        file = conn.makefile("rwb")
        try:
            while True:
                line = file.readline()
                if not line:
                    break

                try:
                    req = json.loads(line.decode("utf-8"))
                except json.JSONDecodeError:
                    self._send(file, {"ok": False, "error": "bad_json"})
                    continue

                action = str(req.get("action", "")).lower()
                if action == "register":
                    self._handle_register(file, req, addr)
                elif action == "unregister":
                    self._handle_unregister(file, req)
                elif action == "resolve":
                    self._handle_resolve(file, req)
                elif action == "list":
                    self._handle_list(file)
                elif action == "ping":
                    self._send(file, {"ok": True, "action": "pong", "time": int(time.time())})
                else:
                    self._send(file, {"ok": False, "error": "unknown_action"})
        finally:
            try:
                file.close()
            finally:
                conn.close()

    def _handle_register(self, file, req: dict, addr: tuple[str, int]) -> None:
        uuid_hash = str(req.get("uuid_hash", "")).strip().lower()
        listen_port = req.get("port")

        if not uuid_hash or len(uuid_hash) != 64:
            self._send(file, {"ok": False, "error": "invalid_uuid_hash"})
            return
        if not isinstance(listen_port, int) or not (1 <= listen_port <= 65535):
            self._send(file, {"ok": False, "error": "invalid_port"})
            return

        now = time.time()
        with self._lock:
            self._records[uuid_hash] = {
                "uuid_hash": uuid_hash,
                "ip": addr[0],
                "port": listen_port,
                "updated_at": now,
            }

        self._send(
            file,
            {
                "ok": True,
                "action": "register",
                "uuid_hash": uuid_hash,
                "ip": addr[0],
                "port": listen_port,
                "ttl": self.ttl_seconds,
            },
        )

    def _handle_unregister(self, file, req: dict) -> None:
        uuid_hash = str(req.get("uuid_hash", "")).strip().lower()
        if not uuid_hash or len(uuid_hash) != 64:
            self._send(file, {"ok": False, "error": "invalid_uuid_hash"})
            return

        removed = False
        with self._lock:
            if uuid_hash in self._records:
                self._records.pop(uuid_hash, None)
                removed = True

        self._send(file, {"ok": True, "action": "unregister", "uuid_hash": uuid_hash, "removed": removed})

    def _handle_resolve(self, file, req: dict) -> None:
        uuid_hash = str(req.get("uuid_hash", "")).strip().lower()
        if not uuid_hash or len(uuid_hash) != 64:
            self._send(file, {"ok": False, "error": "invalid_uuid_hash"})
            return

        with self._lock:
            record = self._records.get(uuid_hash)

        if not record:
            self._send(file, {"ok": False, "error": "not_found"})
            return

        self._send(
            file,
            {
                "ok": True,
                "action": "resolve",
                "uuid_hash": uuid_hash,
                "ip": record["ip"],
                "port": record["port"],
                "age": int(time.time() - record["updated_at"]),
            },
        )

    def _handle_list(self, file) -> None:
        now = time.time()
        with self._lock:
            records = [
                {
                    "uuid_hash": rec["uuid_hash"],
                    "ip": rec["ip"],
                    "port": rec["port"],
                    "age": int(now - rec["updated_at"]),
                }
                for rec in self._records.values()
            ]

        self._send(file, {"ok": True, "action": "list", "count": len(records), "records": records})

    @staticmethod
    def _send(file, obj: dict) -> None:
        file.write((json.dumps(obj, sort_keys=True) + "\n").encode("utf-8"))
        file.flush()
