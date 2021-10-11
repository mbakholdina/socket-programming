import socket
import sys
import argparse

MSG_FROM_SERVER = "Hello UDP Client!"
HOST = 'localhost'
RECV_BUF_SIZE = 2048

def echo_server(port): 
    """ A simple echo server """

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to address and port
    sock.bind((HOST, port))

    print(f"UDP server up and listening on {HOST} port {port}")

    # Listen for incoming datagrams
    while True:
        print ("1. Waiting to receive a message from client")
        data, addr = sock.recvfrom(RECV_BUF_SIZE)

        print (f"Received {len(data)} bytes from {addr}")
        print (f"Data: {data}")

        print("2. Sending reply to client")
        sent = sock.sendto(MSG_FROM_SERVER.encode('utf-8'), addr)
        print (f"Sent {sent} bytes to {addr}")
        print(f"Data: {MSG_FROM_SERVER}")

        break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Socket Server Example')
    parser.add_argument('--port', action="store", dest="port", type=int, required=True)
    given_args = parser.parse_args()
    port = given_args.port
    echo_server(port)
