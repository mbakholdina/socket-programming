import argparse
from enum import Enum
import socket

import attr


HOST = 'localhost'
RECV_BUF_SIZE = 1500  # Corresponds to Ethernet MTU
SRT_PACKET_HEADER_SIZE_BYTES = 16
HANDSHAKE_PAYLOAD_SIZE_BYTES = 48


class ControlType(Enum):
    Handshake = b'\x80\x00'


class HandshakeType(Enum):
    Induction = b'\x00\x00\x00\x01'


def bytes2int(x: bytes) -> int:
    return int.from_bytes(x, "big")

def bytes2hex(x: bytes) -> str:
    return x.hex()


@attr.s
class Handshake(object):
    # TODO: Validators for length in bytes

    control_type: ControlType = attr.ib()  # first bit is set to 1 plus 15 bits control type = 2 bytes, default
    @control_type.validator
    def _check_control_type(self, attribute, value):
        if value != ControlType.Handshake:
            raise ValueError("SRT packet doesn't correspond to a handshake packet")

    subtype:            int = attr.ib()  # 2 bytes, default
    type_specific_info: int = attr.ib()  # 4 bytes, not used
    timestamp:          int = attr.ib()  # 4 bytes
    dst_sockid:         str = attr.ib()  # 4 bytes

    # The handshake payload starts here
    version:        int           = attr.ib()  # 4 bytes
    encr_field:     int           = attr.ib()  # 2 bytes, default
    ext_field:      bytes         = attr.ib()  # 2 bytes - ???
    initial_seqno:  int           = attr.ib()  # 4 bytes
    mtu:            int           = attr.ib()  # 4 bytes
    flow_window:    int           = attr.ib()  # 4 bytes
    handshake_type: HandshakeType = attr.ib()  # 4 bytes
    srt_sockid:     str           = attr.ib()  # 4 bytes
    syn_cookie:     str           = attr.ib()  # 4 bytes
    peer_ip:        bytes         = attr.ib()  # 16 bytes

    # ??? length

    @classmethod
    def from_udp_payload(cls, data):
        """ From UDP packet payload. """

        return cls(
            ControlType(data[:2]),       # control_type
            bytes2int(data[2:4]),        # subtype
            bytes2int(data[4:8]),        # type_specific_information
            bytes2int(data[8:12]),       # timestamp
            bytes2hex(data[12:16]),      # dst_sockid
            bytes2int(data[16:20]),      # version
            bytes2int(data[20:22]),      # encr_field
            data[22:24],                 # ext_field
            bytes2int(data[24:28]),      # initial_seqno
            bytes2int(data[28:32]),      # mtu
            bytes2int(data[32:36]),      # flight_window
            HandshakeType(data[36:40]),  # handshake_type
            bytes2hex(data[40:44]),      # srt_sockid
            bytes2hex(data[44:48]),      # syn_cookie
            data[48:64],                 # peer_ip
        )

    def to_udp_payload(self):
        pass


@attr.s
class SrtHandshake(object):
    """ SRT Handshake Packet """

    header: bytearray = attr.ib(converter=bytearray)
    @header.validator
    def _check_header(self, attribute, value):
        if not value.startswith(b'\x80\x00'):
            raise ValueError("SRT packet doesn't correspond to a handshake packet")

        if len(value) != SRT_PACKET_HEADER_SIZE_BYTES:
            raise ValueError(f"Header size must be {SRT_PACKET_HEADER_SIZE_BYTES} bytes")

    payload: bytearray = attr.ib(converter=bytearray)

    @classmethod
    def from_udp_payload(cls, data):
        """ From UDP packet payload. """
        return cls(data[:SRT_PACKET_HEADER_SIZE_BYTES], data[SRT_PACKET_HEADER_SIZE_BYTES:])

    timestamp: int = attr.ib()
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

    srt_socket_id: bytearray = attr.ib(converter=bytearray)
    @srt_socket_id.default
    def _extract_srt_socket_id(self):
        return self.payload[24:28]

    def update_version(self, value: int):
        self.version = value
        self.payload[:4] = value.to_bytes(4, byteorder="big")

    def get_udp_payload(self):
        return self.header + self.payload



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
            if data.startswith(ControlType.Handshake.value):
                print("Incoming_handshake")
                hs_in = Handshake.from_udp_payload(data)
                print(hs_in)

                if (hs_in.dst_sockid == '00000000') & (hs_in.version == 4) & (hs_in.handshake_type == HandshakeType.Induction):
                    print("Sending reply back")
                    # TODO: reply to handshake
                    # Extension Field = 0x4A17
                    # Version = 5
                    # hs.type == HandshakeType.INDUCTION
                    # SRT Socket ID: Socket ID of the Listener
                    # SYN Cookie: a cookie that is crafted based on host, port and
                    # current time with 1 minute accuracy to avoid SYN flooding attack

                    hs_reply = Handshake(
                        ControlType.Handshake,
                        0,
                        0,
                        0, # no connection on induction, no timestamp
                        hs_in.srt_sockid,
                        5,
                        0,
                        '0x4A17', # magic code
                        hs_in.initial_seqno,
                        hs_in.mtu,
                        hs_in.flow_window,
                        HandshakeType.Induction,
                        0, # no socket is yet created
                        0, # ??? cookie
                        0  # ??? peer_ip
                    )

                    print(hs_reply)
                    break


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Socket Server Example')
    parser.add_argument('--port', action="store", dest="port", type=int, required=True)
    given_args = parser.parse_args()
    port = given_args.port
    srt_server(port)
