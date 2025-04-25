from __future__ import annotations

import random
import string
import socket
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
from pathlib import Path
from urllib.request import FTPHandler
import os

from ftplib import FTP

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

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
    ftp_server: FTPServer

    def accept(self) -> tuple[VOSSSocketConnection, tuple[str, int]]:
        conn, address = self.tcp_socket.accept()
        role = ClientRole(conn.recv(1))
        if role == ClientRole.ADMIN:
            voss_conn = VOSSSocketConnectionAdmin(conn)
        elif role == ClientRole.TARGET:
            voss_conn = VOSSSocketConnectionTarget(conn)
        else:
            raise Exception("Unknown Client Role")
        return voss_conn, address

    def init_socket(self, host: str = '0.0.0.0'):
        self.bind_and_listen(host)
        self.run_ftp_server(host)

    def bind_and_listen(self, host: str) -> None:
        self.tcp_socket.bind((host, PORT))
        self.tcp_socket.listen(5)

    def run_ftp_server(self, host: str):
        # Instantiate an authorizer object to manage authentication
        authorizer = DummyAuthorizer()

        # Add user permission
        # Arguments: user, password, directory, permission
        # 'elradfmw' gives full permissions (read/write) on the given directory
        authorizer.add_user("user", "password", "C:\Ftp", perm="elradfmw")

        # Create an FTP handler instance to handle FTP requests
        handler = FTPHandler
        handler.authorizer = authorizer

        # Create the FTP server
        self.ftp_server = FTPServer((host, 21), handler)  # Listen on all interfaces on port 21

        # Start the server
        self.ftp_server.serve_forever(blocking=False)


class VOSSSocketClient(BaseVOSSSocket):
    ftp_client: FTP

    def connect(self, host: str) -> None:
        self.tcp_socket.connect((host, PORT))

        ftp = FTP()
        ftp.connect(host, 21)
        ftp.login('user', 'password')


class VOSSSocketClientTarget(VOSSSocketClient):
    def upload_file(self, file_path: Path, filename_in_server: str):
        with open(file_path, 'rb') as f:
            self.ftp_client.storbinary(f"STOR {filename_in_server}", f)

    def recv_take_screenshot_request(self) -> None:
        if self.recv_data() != b'Take screenshot':
            raise Exception('Request should be "Take screenshot"')

    def send_take_screenshot_response(self, screenshot_path: Path) -> None:
        screenshot_extension = screenshot_path.suffix
        random_filename = ''.join(random.choices(string.ascii_letters + string.digits, k=16)) + screenshot_extension

        self.upload_file(screenshot_path, random_filename)
        self.send_data(random_filename.encode())


class VOSSSocketClientAdmin(VOSSSocketClient):
    def download_file(self, filename: str, output_path: Path) -> None:
        with open(output_path, 'wb') as f:
            self.ftp_client.retrbinary(f'RETR {filename}', f.write)

    def send_hand_side_auth_request(self, hand_side: HandSide):
        self.send_data(hand_side.value)

    def recv_hand_side_auth_response(self) -> AuthenticationStatus:
        return AuthenticationStatus(self.recv_data())

    def send_screenshot_from_target_request(self, target_ip: str) -> None:
        self.send_data(target_ip.encode())

    def recv_screenshot_from_target_response(self, output_path: Path) -> None:
        screenshot_filename = self.recv_data().decode()
        self.download_file(screenshot_filename, output_path)


class VOSSSocketConnection(BaseVOSSSocket):
    def __init__(self, conn_socket: socket.socket):
        super().__init__()
        self.tcp_socket = conn_socket


class VOSSSocketConnectionTarget(VOSSSocketConnection):
    def send_take_screenshot_request(self):
        self.send_data(b'Take screenshot')

    def recv_take_screenshot_response(self) -> str:
        filename_in_ftp_server = self.recv_data().decode()

        files = [f for f in os.listdir('your_directory_path') if f.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp'))]

        if filename_in_ftp_server in files:
            print("file upload approved! exists in server.")
        else:
            raise Exception('file is not located in the ftp server."')

        return filename_in_ftp_server


class VOSSSocketConnectionAdmin(VOSSSocketConnection):
    def recv_hand_side_auth_request(self) -> 'HandSide':
        received_hand_side = self.recv_data()
        return HandSide(received_hand_side)

    def send_hand_side_auth_response(self, authentication_status: AuthenticationStatus) -> None:
        self.send_data(authentication_status.value)

    def recv_screenshot_from_target_request(self) -> str:
        target_ip = self.recv_data().decode()
        return target_ip

    def send_screenshot_from_target_response(self, screenshot_filename: str) -> None:
        self.send_data(screenshot_filename.encode())

# 1. send_screenshot_from_target_request    admin -> server
#
# 2. recv_screenshot_from_target_request    server
#
# 3. send_take_screenshot_request           server -> target
#
# 4. recv_take_screenshot_request           target
#
# 5. send_take_screenshot_response          target -> server
#
# 6. recv_take_screenshot_response          server
#
# 7. send_screenshot_from_target_response   server -> admin
#
# 8. recv_screenshot_from_target_response   admin

# Screenshot between 4 & 5
# 5. FTP Upload
# 8. FTP Download

# filename = target_conn.recv_take_screenshot_response()
# admin_conn.send_screenshot_from_target_response(filename)
