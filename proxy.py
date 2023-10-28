# python 3.11
import json
import logging
from enum import Enum
import socket
import re
from logging import basicConfig, debug


class Method(Enum):
    GET = b"GET"
    POST = b"POST"
    PUT = b"PUT"
    DELETE = b"DELETE"
    HEAD = b"HEAD"
    CONNECT = b"CONNECT"
    OPTIONS = b"OPTIONS"
    TRACE = b"TRACE"
    PATCH = b"PATCH"


class Type_(Enum):
    REQUEST = b"REQUEST"
    RESPONSE = b"RESPONSE"


class Packet:
    def __init__(self, type_, ip, port, version, header, body):
        self.type_: bytes = type_
        self.ip: bytes = ip
        self.port: int = port
        self.header: dict[str, str] = header
        self.body: bytes = body
        self.version: bytes = version

    def text(self):
        return self.body.decode("unicode_escape")

    def json(self):
        return json.loads(self.body.decode())

    def raw_packet(self):
        raise NotImplementedError()

    def __str__(self):
        return self.raw_packet().decode("unicode_escape")

    def __dict__(self):
        return self.header

    def replace_value(self, pattern: bytes, new_content: bytes):
        self.body = re.sub(pattern, new_content, self.body)

    def updadte_header(self):
        if "Content-Length" in self.header:
            self.header["Content-Length"] = str(len(self.body))

    def is_compressed(self):
        return "Content-Encoding" in self.header

    def is_chunked(self):
        return "Transfer-Encoding" in self.header and self.header["Transfer-Encoding"] == "chunked"

    def is_editable_body(self):
        return not self.is_compressed() and not self.is_chunked()


class Request(Packet):
    def __init__(self, method: bytes, sub_url, version, headers, body, host, port):
        self.method: bytes = method
        self.sub_url: bytes = sub_url
        self.url = headers["Host"].strip() + sub_url.decode()
        super().__init__(Type_.REQUEST, host, port, version, headers, body)

    def raw_packet(self):
        self.updadte_header()
        return self.method + b" " + self.sub_url + b" " + self.version + b"\r\n" + b"\r\n".join(
            k.encode() + b": " + v.encode() for k, v in self.header.items()) + b"\r\n\r\n" + self.body


class Response(Packet):
    def __init__(self, version, status, reason, headers, body, host, port, request: Request = None):
        self.status: int = status
        self.reason: bytes = reason
        self.request: Request = request
        super().__init__(Type_.RESPONSE, host, port, version, headers, body)

    def raw_packet(self):
        self.updadte_header()
        return self.version + b" " + str(self.status).encode() + b" " + self.reason + b"\r\n" + b"\r\n".join(
            k.encode() + b": " + v.encode() for k, v in self.header.items()) + b"\r\n\r\n" + self.body


class Filter:
    def __init__(self, type_: list[Type_] = False, methode: list[Method] = False, in_url: list[bytes] = False,
                 in_body: list[bytes] = False, in_header: list[bytes] = False, ip: list[bytes] = False,
                 port: list[int] = False, status: list[int] = False, inverse=False):
        type_ = type_ or []
        self.type_: list[bytes] = [e.value for e in type_] if type_ else []
        self.methode: list[bytes] = [e.value for e in methode] if methode else []
        self.in_url: list[str] = in_url or []
        self.in_body: list[bytes] = in_body or []
        self.in_header: list[bytes] = in_header or []
        self.ip: list[bytes] = ip or []
        self.port: list[int] = port or []
        self.status: list[int] = status or []
        self.inverse: bool = inverse


class Proxy:

    def __init__(self, host='localhost', port=8945):
        self.host = host
        self.port = port
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.last_request: Request

    def connect(self):
        self.client.connect((self.host, self.port))

    class Scan:
        def __init__(self, proxy, filter_: Filter = False):
            self.filter_ = filter_
            self.proxy = proxy
            self.current_packet = None

        def __enter__(self):
            while not (current_packet := self.proxy.wait(self.filter_)):
                pass
            self.current_packet = current_packet
            return self.current_packet

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.proxy.send(self.current_packet)

    def scan(self, filter_: Filter = False):
        return self.Scan(self, filter_)

    def wait(self, filter_: Filter = False):
        if not self.client:
            raise RuntimeError('Client is not connected. Call connect() first.')

        header_size = 0
        body_size = 0
        is_header = True
        content = b''
        debug("Waiting for packet")
        while True:
            chunk = self.client.recv(1024)
            if chunk:
                content += chunk
                if is_header:
                    if body_size == -1 and b"Content-Length:" in content and b"\r\n" in content[content.find(
                            b"Content-Length:"):]:
                        body_size = int(content.split(b"Content-Length:")[1].split(b"\r\n")[0].strip())
                    if b"\r\n\r\n" in content:
                        is_header = False
                        header_size = content.find(b"\r\n\r\n") + 4
            if len(chunk) < 1024 and b"\r\n" in content:
                break
        debug("Packet received")
        version_proxy, type_, ip, port, first_line = content.split(b"\r\n", 1)[0].split(b",", 4)
        brut_header = content[content.find(b"\r\n") + 2:header_size]
        body = content[header_size:]
        first_line = first_line.split(b" ", 2)

        header = {}
        for line in brut_header.split(b"\r\n"):
            if not line:
                continue
            if b":" in line:
                key, value = line.split(b":", 1)
                header[key.decode().strip()] = value.decode().strip()
            else:
                header[line.decode().strip()] = ""
        status = None
        reason = None
        res = None
        if type_ == b"REQUEST":
            sub_url = first_line[1]
            method = first_line[0]
            version_http = first_line[2]
            header["Accept-Encoding"] = "identity"  # TODO: add Encoding support
            self.last_request = Request(method, sub_url, version_http, header, body, ip, port)
            res = self.last_request
        else:
            status = int(first_line[1])
            reason = first_line[2]
            version_http = first_line[0]
            res = Response(version_http, status, reason, header, body, ip, port, self.last_request)
        debug(content)
        debug(res.header)
        if filter_:
            if (type_ not in filter_.type_ and
                ip not in filter_.ip and
                port not in filter_.port and
                all(not e in brut_header for e in filter_.in_header) and
                all(not e in body for e in filter_.in_body) and
                all(not e in self.last_request.url for e in filter_.in_url) and
                    (type_ != b"RESPONSE" or
                    all(e != status for e in filter_.status))
            ) == filter_.inverse:
                debug(res.raw_packet())
                debug("Packet filtered")
                self.send(res)
                return False
            # for debug
            """if type_ not in filter_.type_:
                pass
            if ip not in filter_.ip:
                pass
            if port not in filter_.port:
                pass
            if not all(not e in brut_header for e in filter_.in_header):
                pass
            if not all(not e in body for e in filter_.in_body):
                pass
            if not all(not e in self.last_request.url for e in filter_.in_url):
                pass
            if type_ == b"RESPONSE" and not all(e != status for e in filter_.status):
                pass"""

        return res

    def send(self, packet: Packet):
        if not self.client:
            raise RuntimeError('Client is not connected. Call connect() first.')
        self.client.sendall(packet.raw_packet())

    def close_connection(self):
        debug("Closing connection")
        self.client.close()

    def __del__(self):
        debug("Deleting proxy")
        self.close_connection()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        debug("Exiting proxy")
        self.close_connection()


if __name__ == '__main__':
    basicConfig(level=logging.INFO)
    with Proxy() as proxy:
        while True:
            # les filtres de sont pas encore totalement au point
            with proxy.scan(Filter()) as packet:
                print(packet.header)
                print(packet.body)
                if type(packet) == Response:
                    packet.header["MyProxy"] = "HELLO WORLD"
                if not packet.is_chunked():
                    packet.replace_value(b"<title>.*?</title>", b"<title>INTERACTIF PROXY</title>")
                    # update automatically Content-Length
                    print(packet.body)
                print("-"*50)
                print("\n")
                # reconstruction et envoi du packet modifié automatiquement
