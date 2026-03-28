class Peer:
    def __init__(self, peer_uuid: str, public_key: str, timeout: int):
        self.UUID = peer_uuid
        self.PUBLIC_KEY = public_key
        self.TIMEOUT = timeout
