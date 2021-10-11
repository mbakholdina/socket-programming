import socket
import sys
import argparse

MSG_FROM_CLIENT = "Hello UDP server!"
HOST = 'localhost'
SEND_BUF_SIZE = 2048


def echo_client(port): 
    """ A simple echo client """

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Send message to server using created UDP socket
    print (f"1. Sending message to server")
    sent = sock.sendto(MSG_FROM_CLIENT.encode('utf-8'), (HOST, port))

    print (f"Sent {sent} bytes to {HOST}, port {port}")
    print (f"Data: {MSG_FROM_CLIENT}")

    # Receive response from server
    print("2. Waiting response from server")
    data, addr = sock.recvfrom(SEND_BUF_SIZE)
    print (f"Received {len(data)} bytes from {addr}")
    print (f"Data: {data}")


if __name__ == '__main__': 
    parser = argparse.ArgumentParser(description='UDP Echo Client') 
    parser.add_argument('--port', action="store", dest="port", type=int, required=True)
    given_args = parser.parse_args()
    port = given_args.port
    echo_client(port)
