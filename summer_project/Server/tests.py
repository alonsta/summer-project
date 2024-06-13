import socket
import json


def test_signup():
    server_address = ('localhost', 11000)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)

    def send(data):
        data_str = json.dumps(data)
        data_length = len(data_str)
        header_length = len(str(data_length))

        client_socket.send(str(header_length).encode())
        client_socket.send(str(data_length).encode())
        client_socket.send(data_str.encode())

    def get():
        header_length = int(client_socket.recv(1).decode())
        data_length = int(client_socket.recv(header_length).decode())
        data = client_socket.recv(data_length).decode()
        data = json.loads(data)
        return data

    try:
        request = {
            "reason": "upload_message",
            "username": "testuser",
            "auth": "TWXN2OLP3Z0W",
            "chat_name": "the boys",
            "message": "whats up boyyss"
        }
        send(request)
        data = json.loads(get())
        print(data)

    except Exception as e:
        print(f"Error: {e}")

    finally:
        client_socket.close()


if __name__ == '__main__':
    test_signup()