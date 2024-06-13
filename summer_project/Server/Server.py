import threading
import DBactions
import socket
import json


def main():
    port = 11000
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', port))
    print("Server running")
    while True:
        try:
            server_socket.listen()
            client_socket, client_address = server_socket.accept()
            print(client_address[0] + " connected")
            th1 = threading.Thread(target=serve_client, args=(client_socket, client_address))
            th1.start()
        except Exception as e:
            print(e)


def serve_client(client_socket, client_address):
    actions_dict = {
        "signup": sign_up,
        "login": login,
        "create_chat": create_chat
    }

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
        data = get()
        action = data["reason"]
        if action in actions_dict:
            response = actions_dict[action](data)
            send(response)
    except Exception as e:
        print(f"Error serving client: {e}")


def login(data):
    username = data["username"]
    password = data["password"]
    if DBactions.login(username, password):
        response = '{"reason": "login", "status": "true", "auth":' + '"' + DBactions.get_auth(username) + '"' + '}'
    else:
        response = '{"reason": "login", "status": "false"}'
    return response


def sign_up(data):
    username = data["username"]
    password = data["password"]
    if DBactions.user_exists(username):
        response = '{"reason": "signup", "status": "false"}'
    else:
        DBactions.add_user(username, password)
        response = '{"reason": "signup", "status": "true"}'
    return response


def create_chat(data):
    try:
        if DBactions.get_auth(username=data["username"]) == data["auth"]:
            auth = data["auth"]
            DBactions.create_chat(data["chat_name"], auth)
            response = '{"reason": "create_chat", "status": "true"}'
    except Exception as e:
        response = '{"reason": "create_chat", "status": "false"}'
        print(e)
    return response





#   def upload_message


#   add_user





#   update(use this on login to get chats history and friends)

if __name__ == "__main__":
    main()
