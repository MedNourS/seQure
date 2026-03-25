import uuid

class Client:
    def __init__(self, ip: str, port: int):
        self.UUID = str(uuid.uuid4())
        self.ADDRESS = ip
        self.PORT = port

        