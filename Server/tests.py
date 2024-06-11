from scapy.layers.inet import UDP, IP
from scapy.all import sr1, Raw
from scapy.sendrecv import send

packet = IP(dst="127.0.0.1") / UDP(dport=9000) / Raw(load="reason:signup-username:alon-password:12345678".encode())
send(packet)