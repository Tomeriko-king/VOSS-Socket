from __future__ import annotations

import socket
from enum import Enum

PORT = 12345


class HandSide(Enum):
    LEFT = 'Left'
    RIGHT = 'Right'


class AuthenticationStatus(Enum):
    RECEIVED_OK = b'OK'
    RECEIVED_FAILED = b'FAILED'
    RECEIVED_PASSED = b'PASSED'


class ClientRole(Enum):
    ADMIN = b'A'
    TARGET = b'T'


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
        ...

    def send_take_screenshot_response(self, screenshot_filename: str) -> None:
        # TODO send screenshot file uploaded to the FTP server
        ...


class VOSSSocketClientAdmin(VOSSSocketClient):
    def send_hand_side_auth_request(self, hand_side):
        ...

    def recv_hand_side_auth_response(self):
        ...

    def send_screenshot_from_target_request(self, target_ip: str) -> None:
        ...

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
        ...

    def send_hand_side_auth_response(self, authentication_status: AuthenticationStatus) -> None:
        ...

    def recv_screenshot_from_target_request(self) -> str:
        # TODO return the target ip address
        ...

    def send_screenshot_from_target_response(self, screenshot_filename: str) -> None:
        ...
