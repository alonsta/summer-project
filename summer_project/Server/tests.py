import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QHBoxLayout, \
    QMessageBox, QMainWindow, QTextEdit, QAction, QInputDialog
from PyQt5.QtGui import QFont
import socket
import json
import threading
import time
from PyQt5.QtCore import Qt, QTimer
AUTH = ""
SERVER_IP = ""
USERNAME = ""
CHATS = []


class display_chats(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Chat Application')
        self.setGeometry(100, 100, 500, 400)

        main_layout = QVBoxLayout()

        title = QLabel("Chat Application")
        title.setFont(QFont('Arial', 20))
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        self.chat_buttons_layout = QVBoxLayout()
        self.loadChats()

        main_layout.addLayout(self.chat_buttons_layout)

        create_chat_button = QPushButton("Create Chat")
        create_chat_button.setFont(QFont('Arial', 14))
        create_chat_button.clicked.connect(self.createChat)
        main_layout.addWidget(create_chat_button)

        self.setLayout(main_layout)

    def loadChats(self):
        print(CHATS)
        for chat in json.loads(CHATS.replace("'", '"')):
            chat_name = chat['name']
            users = ', '.join(chat['users'])
            last_message = chat['messages'][-1]['message'] if chat['messages'] else 'No messages'
            button_text = f"Chat: {chat_name}\nUsers: {users}\nLast message: {last_message}"

            button = QPushButton(button_text)
            button.setFont(QFont('Arial', 12))
            button.setStyleSheet("QPushButton { margin: 5px; padding: 10px; }")
            button.clicked.connect(lambda checked, c=chat: self.showChatDetails(c))
            self.chat_buttons_layout.addWidget(button)

    def showChatDetails(self, chat):
        chat = json.loads(chat)
        chat_name = chat['name']
        users = ', '.join(chat['users'])
        messages = '\n'.join([f"{msg['username']}: {msg['message']}" for msg in chat['messages']])

        details = f"Chat: {chat_name}\nUsers: {users}\nMessages:\n{messages}"
        QMessageBox.information(self, "Chat Details", details)

    def createChat(self):
        chat_name, ok = QInputDialog.getText(self, 'Create Chat', 'Enter chat name:')
        if ok and chat_name:
            send_request(reason="create_chat")
            self.refreshChats()

    def refreshChats(self):
        for i in reversed(range(self.chat_buttons_layout.count())):
            widget = self.chat_buttons_layout.itemAt(i).widget()
            if widget is not None:
                widget.setParent(None)

        self.loadChats()


class LoginSignupApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Chat app')
        self.setGeometry(100, 100, 400, 200)

        layout = QVBoxLayout()

        self.username_label = QLabel('Username:')
        self.username_label.setFont(QFont('Arial', 12))
        self.username_input = QLineEdit()
        self.username_input.setFont(QFont('Arial', 12))

        self.password_label = QLabel('Password:')
        self.password_label.setFont(QFont('Arial', 12))
        self.password_input = QLineEdit()
        self.password_input.setFont(QFont('Arial', 12))
        self.password_input.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton('Login')
        self.login_button.setFont(QFont('Arial', 12))
        self.signup_button = QPushButton('Signup')
        self.signup_button.setFont(QFont('Arial', 12))

        self.login_button.clicked.connect(self.login)
        self.signup_button.clicked.connect(self.signup)

        layout.addWidget(self.username_label)
        layout.addWidget(self.username_input)
        layout.addWidget(self.password_label)
        layout.addWidget(self.password_input)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.login_button)
        button_layout.addWidget(self.signup_button)

        layout.addLayout(button_layout)

        self.setLayout(layout)

        self.setStyleSheet("""
            QWidget {
                background-color: #f0f0f0;
            }
            QLabel {
                margin-bottom: 5px;
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 5px;
                margin-bottom: 15px;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
        """)

    def login(self):
        global AUTH, USERNAME, CHATS
        username = self.username_input.text()
        password = self.password_input.text()
        response = json.loads(send_request('login', username=username, password=password))
        if response and response["status"] == "true":
            AUTH = response["auth"]
            USERNAME = username
            QMessageBox.warning(self, 'Login Status', 'Login successful.')
            CHATS = json.loads(send_request(action='update', username=USERNAME, auth=AUTH))["chats"]
            update_thread = threading.Thread(target=updateChats)
            update_thread.daemon = True
            update_thread.start()
            self.show_chats()
        else:
            QMessageBox.warning(self, 'Login Status', 'Login failed.')

    def signup(self):
        username = self.username_input.text()
        password = self.password_input.text()
        response = json.loads(send_request('signup', username=username, password=password))
        if response and response["status"] == "true":
            QMessageBox.information(self, 'Signup', 'Signup successful!')
        else:
            QMessageBox.warning(self, 'Signup', 'Signup failed.')

    def show_chats(self):
        self.chats_window = display_chats()
        self.chats_window.show()



def send_request(action, username="", password="", auth="", chat_name="", new_user=""):
    global AUTH
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((SERVER_IP, 11000))
            request = json.dumps({
                    "reason": action,
                    "username": username,
                    "password": password,
                    "auth": AUTH,
                    "chat_name": chat_name,
                    "new_user": new_user
                })
            request_length = len(request)
            header_length = len(str(request_length))

            client_socket.send(str(header_length).encode())
            client_socket.send(str(request_length).encode())
            client_socket.send(request.encode())

            header_length = int(client_socket.recv(1).decode())
            data_length = int(client_socket.recv(header_length).decode())
            response = json.loads(client_socket.recv(data_length).decode())

            return response
    except Exception as e:
        print(f"Error connecting to server: {e}")
        return None


def updateChats():
    global CHATS
    # Simulate a request to update the CHATS variable
    response = send_request(action='update', username=USERNAME, auth=AUTH)
    chats = json.loads(response)["chats"]
    CHATS = json.loads(chats.replace("'", '"'))


def discover_server():
    port = 50000
    broadcast_ip = '255.255.255.255'
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    message = 'DISCOVER_SERVER'
    client_socket.sendto(message.encode(), (broadcast_ip, port))

    client_socket.settimeout(5)
    try:
        response, server_address = client_socket.recvfrom(1024)
        server_ip = response.decode().split(':')[1]
        return server_ip
    except socket.timeout:
        print("No response from server.")
        return None


if __name__ == '__main__':
    SERVER_IP = discover_server()
    if not SERVER_IP:
        print("Failed to discover server.")
        sys.exit()
    print(SERVER_IP)
    app = QApplication(sys.argv)
    window = LoginSignupApp()
    window.show()
    sys.exit(app.exec_())
