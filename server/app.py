from seQure_server import RelayServer


if __name__ == "__main__":
    RelayServer(host="0.0.0.0", port=9999, ttl_seconds=600).serve_forever()
