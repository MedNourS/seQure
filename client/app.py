from seQure_client.client import Client

if __name__ == "__main__":
    client = Client("127.0.0.1", int(input("Which port would you like to listen on?\n> ")))
    print(f"Client UUID: {client.UUID}")
    print(f"Client Address: {client.ADDRESS}")
    print(f"Client Port: {client.PORT}")