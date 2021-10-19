import argparse
from enum import Enum
import socket

import attr


HOST = 'localhost'
RECV_BUF_SIZE = 1500  # Corresponds to Ethernet MTU


class HandshakeType(Enum):
    INDUCTION = b'\x00\x00\x00\x01'


@attr.s
class SrtHandshake(object):
    """ SRT Handshake Packet """
    # TODO: Validator for the first two bytes
    header: bytes = attr.ib()
    payload: bytes = attr.ib()

    timestamp: bytes = attr.ib()
    @timestamp.default
    def _extract_timestamp(self):
        return int.from_bytes(self.header[8:12], "big")

    version: int = attr.ib()
    @version.default
    def _extract_version(self):
        return int.from_bytes(self.payload[:4], "big")

    # ??? long int
    initial_seqno: int = attr.ib()
    @initial_seqno.default
    def _extract_initial_seqno(self):
        return int.from_bytes(self.payload[8:12], "big")

    type: HandshakeType = attr.ib()
    @type.default
    def _extract_type(self):
        return HandshakeType(self.payload[20:24])

    srt_socket_id: bytes = attr.ib()
    @srt_socket_id.default
    def _extract_srt_socket_id(self):
        return self.payload[24:28]


def srt_server(port): 
    """ A simple SRT server """

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, port))

        print(f"SRT server up and listening on {HOST} port {port}")

        # Listen for incoming datagrams
        while True:
            data, addr = sock.recvfrom(RECV_BUF_SIZE)

            if not data: # recvfrom() returns b''
                # TODO: Doesn't work, hanging on recvfrom() if there is no incoming data
                break

            print (f"Received {len(data)} bytes from {addr}")
            print (f"Data: {data}")

            # Detect incoming handshake
            if data.startswith(b'\x80\x00'):
                # print(f'This is an SRT handshake. Timestamp: {data[8:12]} ~ {int.from_bytes(data[8:12], "big")} \n')

                hs = SrtHandshake(data[:16], data[16:])
                print(hs)

                if hs.type == HandshakeType.INDUCTION:
                    print("Induction handshake, break")
                    
                    # TODO: reply to handshake


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Socket Server Example')
    parser.add_argument('--port', action="store", dest="port", type=int, required=True)
    given_args = parser.parse_args()
    port = given_args.port
    srt_server(port)
