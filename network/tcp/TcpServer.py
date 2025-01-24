import socket

import argparse
import datetime
import threading
import logging
import time
import subprocess
import re
import signal

WITH_LOGGING = False

is_still_running = True
server = None

def handler_stop_signals(signum, frame):
    global is_still_running
    global server
    is_still_running = False
    if server:
        server.shutdown()
        print("> Server is shutdown gracefully")

def receive_from_new_client(client_socket, client_address, verbose = False):
    print(f"(TcpSever) --> Accepted connection from {client_address}")
    packet_count = 0
    while True and is_still_running:
        # Receive data from the client
        data = None
        try:
            packet_count += 1
            data = client_socket.recv(1024)
            data = data.decode('utf-8')
        except Exception as error:
            if verbose:
                print("An exception occurred:", error)
            if WITH_LOGGING:
                logging.error("An exception occurred: " + str(error))
        if verbose:
            print(f"(TcpSever) --> {datetime.datetime.now()}: Received data from client: {data}")
        if not data:
            break  # Exit loop if no more data
        # Close the client socket
    try:
        client_socket.close()
    except Exception as error:
        print("Socket already closed:", error)
        if WITH_LOGGING:
            logging.error("Socket already closed: " + str(error))
    print(f"(TcpSever) <-- Closed connection from {client_address} after receiving {packet_count}")

def main():
    global server
    parser = argparse.ArgumentParser(description="TCP Client",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-n", "--server-name", help="Server's name like hs", required=True)
    parser.add_argument("-ip", "--server-ip", help="Server IP. E.g: 10.0.1.101", required=True)
    parser.add_argument("-v", "--verbose", action="store_true", help="Whether to log received messages information")
    config = vars(parser.parse_args())

    server_name = config['server_name']
    verbose = config['verbose']
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Define the host and port to bind the server
    host = config['server_ip']  # You can change this to your server's IP address
    port = 80
    # Bind the socket to the host and port
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server = server_socket
    # Listen for incoming connections (maximum of 6 clients in the queue)
    server_socket.listen(6)
    print(f"(TcpSever) --> Init sever ({server_name}) at {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}:\n"
          f"  - exposed at ({host}:{port})\n")

    while True and is_still_running:
        # Accept a connection from a client
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=receive_from_new_client, args=(client_socket, client_address, verbose,), daemon=True)
        client_thread.start()

def get_pid_by_port(port):
    try:
        result = subprocess.run(f"ss -lptn 'sport = :{port}'", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True, shell=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None

def kill_process_using_port():
    try:
        pattern = re.compile(r'pid=(\d+)')
        match = pattern.search(get_pid_by_port(80))
        if match:
            # Getting {process-id} value
            pid_value = match.group(1)
            subprocess.run(['kill', str(pid_value)], check=True)
            print(f">>> Process with PID {pid_value} killed successfully.")
        else:
            print(f">>> No process using port 80.")
    except subprocess.CalledProcessError:
        print(f">>> Unable to kill process using port 80.")

if __name__ == '__main__':
    signal.signal(signal.SIGINT, handler_stop_signals)
    signal.signal(signal.SIGTERM, handler_stop_signals)
    print("> TcpServer.__main__")
    retrys = 0
    max_retrys = 3
    already_up = False
    while (not already_up) and retrys < max_retrys and is_still_running:
        print(">> Try starting server")
        if retrys > 0:
            print(">>> Retry No. ", retrys)
        retrys += 1
        try:
            kill_process_using_port()
            if WITH_LOGGING:
                logging.basicConfig(filename='TcpServer.py.log', filemode='w', level=logging.DEBUG)
            main()
            already_up = True
        except Exception as error:
            try:
                with open(f"error - {time.time_ns()}", 'w') as file:
                    content_to_write = "Hello, this is the content to write to the file."
                    file.write(content_to_write)
                print("Content successfully written to the file.")
            except Exception as e:
                print(f"An error occurred: {e}")
            print("Error from server side:", error)
            if WITH_LOGGING:
                logging.error("Error from server side: " + str(error))
            time.sleep(0.5)
    if (not already_up) and retrys >= max_retrys:
        input("Failed to start server, press any key to continue...")

