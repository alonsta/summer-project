from pymongo import MongoClient
import random
import string
import json
connection_string = "***************"
client = MongoClient(connection_string)
db = client.summerproject
users = db.users
chats = db.chats


def user_exists(username):
    return users.find_one({"username": username}) is not None


def add_user(username, password):
    auth = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(12))
    user_info = {"username": username, "password": password, "auth": auth, "chats": list()}
    users.insert_one(user_info)


def login(username, password):
    return password == users.find_one({"username": username})["password"]


def authorize_user(username, auth):
    return auth == users.find_one({"username": username})["auth"]


def authorize_chat(chat_name, auth):
    return auth == chats.find_one({"name": chat_name})["auth"]


def create_chat(chat_name, auth):
    chat = {"name": chat_name, "auth": auth, "messages": [], "users": [users.find_one({"auth": auth})["username"]]}
    chats.insert_one(chat)
    users.update_one({"auth": auth}, {"$addToSet": {"chats": chat_name}})


def chat_exists(chat_name):
    answer = chats.find_one({"name": chat_name})
    if answer:
        return True
    return False


def upload_message(message, chat_name, username):
    if not chat_exists(chat_name):
        create_chat(chat_name, users.find_one({"username": username})["auth"])
    if username in chats.find_one({"name": chat_name})["users"]:
        message = json.loads('{"username":"' + username + '",' + '"message":"' + message + '"}')
        chats.update_one({"name": chat_name}, {"$addToSet": {"messages": message}})
    else:
        raise PermissionError("User not authorized to send messages in this chat")


def add_user_to_chat(chat_name, new_user, username):
    if not chat_exists(chat_name):
        raise ValueError("Chat does not exist")

    user = users.find_one({"username": username})

    if not authorize_chat(chat_name, user["auth"]):
        raise PermissionError("User not authorized to add members to this chat")

    new_user_doc = users.find_one({"username": new_user})
    if not new_user_doc:
        raise ValueError("New user does not exist")

    chats.update_one({"name": chat_name}, {"$addToSet": {"users": new_user}})

    users.update_one({"username": new_user}, {"$addToSet": {"chats": chat_name}})


def get_chat(chat_name, username):
    if username and username in chats.find_one({"name": chat_name})["users"]:
        chat = chats.find_one({"name": chat_name})
        return "name:" + chat["name"] + "-" + "messages:" + str(chat["messages"]) + "-" + "users:" + str(chat["users"])
    raise PermissionError("User not authorized to view this chat")


def get_auth(username):
    return users.find_one({"username": username})["auth"]
