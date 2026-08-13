# Author: Rayan Hamour (22103817)
"""
Real-socket DoIP gateway: unlike doip.gateway (in-process DoIPMessage
objects only), this opens an actual TCP listening socket and exchanges
wire-format DoIP frames (doip.protocol) with real client sockets - the
attacker/tester is a genuine separate socket-level actor connecting over
TCP/IP, not a Python object handed directly to a method call. This is the
project's most protocol-accurate DoIP model; doip.gateway remains the one
used by the main evaluation harness for speed and simplicity.

Authorization is tracked per TCP connection rather than by a persistent
source-address set (unlike doip.gateway): disconnecting and reconnecting
drops routing activation, matching how a real DoIP session actually works
- a small but real accuracy improvement over the in-process model.
"""

from __future__ import annotations

import socket
import threading
import time

import can

from carnet.config import DOIP_GATEWAY_LOGICAL_ADDRESS, DOIP_ROUTE_TARGET_CAN_ID
from carnet.doip.protocol import (
    HEADER_LEN,
    PAYLOAD_TYPE_DIAGNOSTIC_MESSAGE,
    PAYLOAD_TYPE_DIAGNOSTIC_MESSAGE_POS_ACK,
    PAYLOAD_TYPE_ROUTING_ACTIVATION_REQUEST,
    PAYLOAD_TYPE_ROUTING_ACTIVATION_RESPONSE,
    ROUTING_ACTIVATION_SUCCESS,
    DoIPProtocolError,
    decode_diagnostic_message,
    decode_header,
    decode_routing_activation_request,
    decode_routing_activation_response,
    encode_diagnostic_ack,
    encode_diagnostic_message,
    encode_routing_activation_request,
    encode_routing_activation_response,
)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("connection closed before expected bytes arrived")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class SocketDoIPGateway:
    def __init__(
        self,
        bus: can.Bus,
        host: str = "127.0.0.1",
        port: int = 0,
        require_routing_activation: bool = True,
        start_time: float | None = None,
    ):
        self.bus = bus
        self.require_routing_activation = require_routing_activation
        self.start_time = start_time if start_time is not None else time.monotonic()

        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((host, port))
        self._server.listen(8)
        self._server.settimeout(0.2)  # lets the accept loop notice stop()

        self._lock = threading.Lock()
        self.events: list[dict] = []
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._accept_loop, name="doip-accept", daemon=True)

    @property
    def port(self) -> int:
        return self._server.getsockname()[1]

    def start(self) -> None:
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._server.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2.0)
        for t in self._threads:
            t.join(timeout=1.0)

    def _log(self, kind: str, **fields) -> None:
        with self._lock:
            self.events.append({"timestamp": time.monotonic() - self.start_time, "kind": kind, **fields})

    def _accept_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                conn, _addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_connection, args=(conn,), daemon=True)
            t.start()
            self._threads.append(t)

    def _handle_connection(self, conn: socket.socket) -> None:
        conn.settimeout(2.0)
        activated = not self.require_routing_activation
        try:
            while not self._stop_event.is_set():
                try:
                    header_bytes = _recv_exact(conn, HEADER_LEN)
                except (ConnectionError, socket.timeout, OSError):
                    break
                try:
                    payload_type, length = decode_header(header_bytes)
                    payload = _recv_exact(conn, length) if length else b""
                except (DoIPProtocolError, ConnectionError):
                    self._log("malformed_frame")
                    break

                if payload_type == PAYLOAD_TYPE_ROUTING_ACTIVATION_REQUEST:
                    source_address, _activation_type = decode_routing_activation_request(payload)
                    activated = True
                    self._log("routing_activation", source=source_address)
                    response = encode_routing_activation_response(
                        source_address, DOIP_GATEWAY_LOGICAL_ADDRESS, ROUTING_ACTIVATION_SUCCESS
                    )
                    conn.sendall(response)
                    continue

                if payload_type == PAYLOAD_TYPE_DIAGNOSTIC_MESSAGE:
                    source_address, _target_address, uds_data = decode_diagnostic_message(payload)
                    if not activated:
                        self._log("unauthorized_diagnostic_attempt", source=source_address)
                        conn.sendall(
                            encode_diagnostic_ack(DOIP_GATEWAY_LOGICAL_ADDRESS, source_address, positive=False)
                        )
                        continue
                    can_data = uds_data[:8].ljust(8, b"\x00")
                    can_msg = can.Message(arbitration_id=DOIP_ROUTE_TARGET_CAN_ID, data=can_data, is_extended_id=False)
                    try:
                        self.bus.send(can_msg)
                        self._log("forwarded_to_can", source=source_address, can_id=DOIP_ROUTE_TARGET_CAN_ID)
                        conn.sendall(
                            encode_diagnostic_ack(DOIP_GATEWAY_LOGICAL_ADDRESS, source_address, positive=True)
                        )
                    except can.CanError:
                        self._log("forward_failed", source=source_address)
                    continue

                self._log("unhandled_payload_type", payload_type=payload_type)
        finally:
            conn.close()


class DoIPSocketClient:
    """A tester/attacker's real TCP session against a SocketDoIPGateway."""

    def __init__(self, host: str, port: int, source_address: int, timeout: float = 2.0):
        self.source_address = source_address
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._sock.settimeout(timeout)

    def routing_activation(self) -> bool:
        self._sock.sendall(encode_routing_activation_request(self.source_address))
        payload_type, payload = self._read_frame()
        if payload_type != PAYLOAD_TYPE_ROUTING_ACTIVATION_RESPONSE:
            return False
        _, _, response_code = decode_routing_activation_response(payload)
        return response_code == ROUTING_ACTIVATION_SUCCESS

    def send_diagnostic(self, target_address: int, uds_data: bytes) -> bool:
        self._sock.sendall(encode_diagnostic_message(self.source_address, target_address, uds_data))
        payload_type, _payload = self._read_frame()
        return payload_type == PAYLOAD_TYPE_DIAGNOSTIC_MESSAGE_POS_ACK

    def _read_frame(self) -> tuple[int, bytes]:
        header_bytes = _recv_exact(self._sock, HEADER_LEN)
        payload_type, length = decode_header(header_bytes)
        payload = _recv_exact(self._sock, length) if length else b""
        return payload_type, payload

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass
