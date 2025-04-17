from __future__ import annotations

import socket
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256

PORT = 12345


class HandSide(Enum):
    LEFT = b'Left'
    RIGHT = b'Right'


class AuthenticationStatus(Enum):
    RECEIVED_OK = b'OK'
    RECEIVED_FAILED = b'FAILED'
    RECEIVED_PASSED = b'PASSED'


class ClientRole(Enum):
    ADMIN = b'A'
    TARGET = b'T'


@dataclass
class Packet:
    data_length: int
    checksum: int
    data: bytes

    @classmethod
    def build_packet(cls, data: bytes):
        data_length = len(data)
        checksum = cls.calculate_checksum(data)
        return cls(data_length=data_length, checksum=checksum, data=data)

    @staticmethod
    def data_length_field_size() -> int:
        return 4

    @staticmethod
    def checksum_field_size() -> int:
        return 32

    @staticmethod
    def calculate_checksum(data: bytes) -> int:
        return int(sha256(data).hexdigest(), 16)

    def to_bytes(self) -> bytes:
        return (self.data_length.to_bytes(self.data_length_field_size()) +
                self.checksum.to_bytes(self.checksum_field_size()) +
                self.data)

    def validate(self) -> bool:
        return self.calculate_checksum(self.data) == self.checksum


class BaseVOSSSocket:
    tcp_socket: socket.socket

    def __init__(self) -> None:
        self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def close(self) -> None:
        self.tcp_socket.close()

    def __send(self, data: bytes) -> None:
        self.tcp_socket.send(data)

    def __recv(self, size: int = 1024) -> bytes:
        return self.tcp_socket.recv(size)

    def send_data(self, data: bytes):
        packet = Packet.build_packet(data)
        self.__send(packet.to_bytes())

    def recv_data(self) -> bytes:
        data_length = int.from_bytes(self.__recv(Packet.data_length_field_size()))
        checksum = int.from_bytes(self.__recv(Packet.checksum_field_size()))
        data = self.__recv(data_length)
        packet = Packet(data_length, checksum, data)
        if not packet.validate():
            raise Exception("error - invalid checksum")
        return data


class VOSSSocketServer(BaseVOSSSocket):
    def accept(self) -> tuple[VOSSSocketConnection, tuple[str, int]]:
        conn, address = self.tcp_socket.accept()
        role = ClientRole(conn.recv(1))
        if role == ClientRole.ADMIN:
            voss_conn = VOSSSocketConnectionAdmin(conn)
        elif role == ClientRole.TARGET:
            voss_conn = VOSSSocketConnectionTarget(conn)
        return voss_conn, address

    def bind_and_listen(self, host: str) -> None:
        self.tcp_socket.bind((host, PORT))
        self.tcp_socket.listen(5)


class VOSSSocketClient(BaseVOSSSocket):
    def connect(self, host: str) -> None:
        self.tcp_socket.connect((host, PORT))


class VOSSSocketClientTarget(VOSSSocketClient):
    def recv_take_screenshot_request(self) -> None:
        if self.recv_data() != b'Take screenshot':
            raise Exception('Request should be "Take screenshot"')

    def send_take_screenshot_response(self, screenshot_filename: str) -> None:
        # TODO send screenshot file uploaded to the FTP server
        ...


class VOSSSocketClientAdmin(VOSSSocketClient):
    def send_hand_side_auth_request(self, hand_side: HandSide):
        self.send_data(hand_side.value)

    def recv_hand_side_auth_response(self) -> AuthenticationStatus:
        return AuthenticationStatus(self.recv_data())

    def send_screenshot_from_target_request(self, target_ip: str) -> None:
        self.send_data(target_ip.encode())

    def recv_screenshot_from_target_response(self) -> str:
        # TODO return the name of the screenshot file in the FTP server
        ...


class VOSSSocketConnection(BaseVOSSSocket):
    def __init__(self, conn_socket: socket.socket):
        super().__init__()
        self.tcp_socket = conn_socket


class VOSSSocketConnectionTarget(VOSSSocketConnection):
    def send_take_screenshot_request(self):
        ...

    def recv_take_screenshot_response(self) -> str:
        # TODO return the name of the screenshot file from the FTP server
        ...


class VOSSSocketConnectionAdmin(VOSSSocketConnection):
    def recv_hand_side_auth_request(self) -> 'HandSide':
        received_hand_side = self.recv_data()
        return HandSide(received_hand_side)

    def send_hand_side_auth_response(self, authentication_status: AuthenticationStatus) -> None:
        self.send_data(authentication_status.value)

    def recv_screenshot_from_target_request(self) -> str:
        # TODO return the target ip address
        ...

    def send_screenshot_from_target_response(self, screenshot_filename: str) -> None:
        ...
