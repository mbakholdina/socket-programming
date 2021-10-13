import socket
import sys
import argparse

HOST = 'localhost'
RECV_BUF_SIZE = 1500  # Corresponds to MTU


def srt_server(port): 
    """ A simple SRT server """

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind the socket to address and port
    sock.bind((HOST, port))

    print(f"SRT server up and listening on {HOST} port {port}")

    # Listen for incoming datagrams
    while True:
        data, addr = sock.recvfrom(RECV_BUF_SIZE)

        print (f"Received {len(data)} bytes from {addr}")
        print (f"Data: {data}")

        # Detect incoming handshake
        if data.startswith(b'\x80\x00'):
            print(f'This is an SRT handshake. Timestamp: {data[8:12]} ~ {int.from_bytes(data[8:12], "big")} \n')
            # break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Socket Server Example')
    parser.add_argument('--port', action="store", dest="port", type=int, required=True)
    given_args = parser.parse_args()
    port = given_args.port
    srt_server(port)
