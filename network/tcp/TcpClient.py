import socket
import time
import argparse
from datetime import datetime

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="TCP Client",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-n", "--client-name", help="Client's name like h1", required=True)
    parser.add_argument("-ip", "--server-ip", help="Server IP. E.g: 10.0.1.101", required=True)
    parser.add_argument("-t", "--send-duration", help="Send duration in seconds", required=True)
    parser.add_argument("-d", "--data", help="Data character to send, like A", required=False)
    parser.add_argument("-np", "--num-packets", help="Number of packets", required=False)
    config = vars(parser.parse_args())

    client_name = config['client_name']
    data = config['data']
    if data is None or data == '':
        data = 'A'
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Define the server's host and port to connect
    server_host = config['server_ip']  # Change this to the server's IP address
    server_port = 80
    print(f"connecting to {server_host}:{server_port}")
    # Connect to the server
    client_socket.connect((server_host, server_port))

    # Number of packets to send
    num_packets = 100000
    if (config['num_packets'] is not None) and (not config['num_packets'] == ''):
        num_packets = int(config['num_packets'])
    packet_size = 512
    # Time duration (in seconds) for sending all packets
    send_duration = int(config['send_duration'])  # Adjust this as needed
    # Calculate the delay between sending packets
    packet_delay = send_duration / num_packets
    print(f"(TcpClient) --> Init client ({client_name}):\n"
          f"  - port ({client_socket.getsockname()[1]})\n"
          f"  - to call server ({server_host}:{server_port})\n"
          f"  - rate ({num_packets} pkts / {send_duration} s)\n"
          f"  - rate/s ({num_packets/send_duration} pkts/s) \n"
          f"  - pkt size ({packet_size} B) \n"
          f"  - data ({data}) \n"
          f"  - packet delay ({packet_delay} s)")
    message = data * packet_size
    start = time.time()
    print(f"(TcpClient) Started at: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
    sent_packets = 0
    for i in range(num_packets):
        # Send data to the server
        try:
            client_socket.send(message.encode('utf-8'))
        except Exception as error:
            print("Unable to send packet:", error)
        end = time.time()
        # Pause for the calculated delay
        # time.sleep(packet_delay)
        target_time = end + packet_delay
        while time.time() < target_time:
            pass
        if i % 1000 == 0:
            print(f'(TcpClient) ----> {i} packets sent')
        sent_packets = sent_packets + 1
        if end - start > send_duration:
            print(f'(TcpClient) --> Stopping client ({client_name}) due to timeout')
            break
    # Close the client socket
    print(f'(TcpClient) --> Client ({client_name}) sent ({sent_packets}) pkts = ({(sent_packets * packet_size)} bytes)')
    try:
        client_socket.close()
    except Exception as error:
        print("Socket already closed:", error)