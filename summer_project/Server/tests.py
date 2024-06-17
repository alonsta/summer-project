from scapy.layers.inet import IP, TCP
from scapy.all import sr1
import threading


def main():
    ip = input("enter ip to scan: ")
    amount = input("amount of ports to scan 1 - : ")
    ports = scanner(ip, int(amount))
    if ports:
        print("Open ports:")
        for port_num in ports:
            print("Port:", port_num)
    else:
        print("No open ports found.")


def scanner(ip, amount) -> list:
    open_ports = []
    threads = list()

    def scan_port(port_num):
        check = IP(dst=ip)/TCP(dport=port_num, flags='S')
        answer = sr1(check, timeout=2, verbose=0)
        if answer and answer.haslayer(TCP) and answer[TCP].flags == 'SA':
            open_ports.append(port_num)

    for port in range(1, amount):
        print("checking: " + str(port))
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()

    return open_ports


if __name__ == "__main__":
    main()