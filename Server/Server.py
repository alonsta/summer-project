import threading
from scapy.layers.inet import UDP, IP
from scapy.all import sniff, send, Raw
import DBactions  # Assuming DBactions is already implemented


def main():
    print("Server running")
    while True:
        try:
            packets = sniff(filter="udp and port 9000", count=1)
            th1 = threading.Thread(target=serve_client, args=(packets[0],))
            th1.start()
        except Exception as e:
            print(e)


def serve_client(packet):
    actions_dict = {
        "signup": sign_up,
        "connection": login,
    }

    try:
        action = packet[Raw].load.decode().split("-")[0].split(":")[1]
        if action in actions_dict:
            actions_dict[action](packet)
    except Exception as e:
        print(f"Error serving client: {e}")


def login(packet):
    username = packet[Raw].load.decode().split("-")[1].split(":")[1]
    password = packet[Raw].load.decode().split("-")[2].split(":")[1]
    if DBactions.authorize_user(username, password):
        response = IP(dst=packet[IP].src) / UDP(dport=9001) / Raw(
            f"reason:connect-auth:{DBactions.get_auth(username)}-status:true".encode())
    else:
        response = IP(dst=packet[IP].src) / UDP(dport=9001) / Raw("reason:connect-status:false".encode())
    send(response)


def sign_up(packet):
    username = packet[Raw].load.decode().split("-")[1].split(":")[1]
    password = packet[Raw].load.decode().split("-")[2].split(":")[1]
    if DBactions.user_exists(username):
        response = IP(dst=packet[IP].src) / UDP(dport=9001) / Raw("reason:signup-status:false".encode())
    else:
        DBactions.add_user(username, password)
        response = IP(dst=packet[IP].src) / UDP(dport=9001) / Raw("reason:signup-status:true".encode())
    send(response)


if __name__ == "__main__":
    main()

#   def upload_message


#   create_chat(gets an add req and makes sure to connect between the two)(update the friends in DB)(req/ack)


#   update(use this on login to get chats history and friends)


if __name__ == "__main__":
    main()
