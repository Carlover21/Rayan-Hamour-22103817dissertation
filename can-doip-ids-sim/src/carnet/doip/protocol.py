# Author: Rayan Hamour (22103817)
"""
Wire-format encode/decode for the real-socket DoIP gateway (doip.socket_gateway).

This is a subset of the ISO 13400-2 generic DoIP header and two payload
types - enough to carry an actual routing-activation handshake and
diagnostic message over a real TCP socket, which the rest of this project's
DoIP model (doip.gateway) deliberately does not do (in-process objects
only). Still not spec-complete: no UDP vehicle-identification/discovery,
no TLS, no multi-ECU logical addressing beyond a single gateway address,
and only the two payload types this project's attack surface needs.

Generic header (8 bytes): protocol version, inverse protocol version
(bitwise complement - a real DoIP receiver rejects a frame where these
don't match, modelled here too), payload type (2 bytes), payload length
(4 bytes) - followed by the payload itself.
"""

from __future__ import annotations

import struct

PROTOCOL_VERSION = 0x02  # ISO 13400-2:2012
HEADER_LEN = 8
MAX_PAYLOAD_LEN = 1 << 20  # sanity bound against a malformed/hostile length field

PAYLOAD_TYPE_ROUTING_ACTIVATION_REQUEST = 0x0005
PAYLOAD_TYPE_ROUTING_ACTIVATION_RESPONSE = 0x0006
PAYLOAD_TYPE_DIAGNOSTIC_MESSAGE = 0x8001
PAYLOAD_TYPE_DIAGNOSTIC_MESSAGE_POS_ACK = 0x8002
PAYLOAD_TYPE_DIAGNOSTIC_MESSAGE_NEG_ACK = 0x8003

ROUTING_ACTIVATION_SUCCESS = 0x10
ROUTING_ACTIVATION_DENIED = 0x00


class DoIPProtocolError(Exception):
    pass


def encode_frame(payload_type: int, payload: bytes) -> bytes:
    header = struct.pack(">BBHI", PROTOCOL_VERSION, 0xFF ^ PROTOCOL_VERSION, payload_type, len(payload))
    return header + payload


def decode_header(header_bytes: bytes) -> tuple[int, int]:
    """Returns (payload_type, payload_length). Raises on a malformed header,
    same as a real DoIP entity would reject/close the connection."""
    if len(header_bytes) != HEADER_LEN:
        raise DoIPProtocolError("short header")
    version, inv_version, payload_type, length = struct.unpack(">BBHI", header_bytes)
    if version != PROTOCOL_VERSION or inv_version != (0xFF ^ PROTOCOL_VERSION):
        raise DoIPProtocolError(f"bad protocol version bytes: {version:#x}/{inv_version:#x}")
    if length > MAX_PAYLOAD_LEN:
        raise DoIPProtocolError(f"payload length {length} exceeds sanity bound")
    return payload_type, length


def encode_routing_activation_request(source_address: int, activation_type: int = 0x00) -> bytes:
    payload = struct.pack(">HB", source_address, activation_type)
    return encode_frame(PAYLOAD_TYPE_ROUTING_ACTIVATION_REQUEST, payload)


def decode_routing_activation_request(payload: bytes) -> tuple[int, int]:
    source_address, activation_type = struct.unpack(">HB", payload[:3])
    return source_address, activation_type


def encode_routing_activation_response(tester_address: int, gateway_address: int, response_code: int) -> bytes:
    payload = struct.pack(">HHB", tester_address, gateway_address, response_code)
    return encode_frame(PAYLOAD_TYPE_ROUTING_ACTIVATION_RESPONSE, payload)


def decode_routing_activation_response(payload: bytes) -> tuple[int, int, int]:
    return struct.unpack(">HHB", payload[:5])


def encode_diagnostic_message(source_address: int, target_address: int, uds_data: bytes) -> bytes:
    payload = struct.pack(">HH", source_address, target_address) + uds_data
    return encode_frame(PAYLOAD_TYPE_DIAGNOSTIC_MESSAGE, payload)


def decode_diagnostic_message(payload: bytes) -> tuple[int, int, bytes]:
    source_address, target_address = struct.unpack(">HH", payload[:4])
    return source_address, target_address, payload[4:]


def encode_diagnostic_ack(source_address: int, target_address: int, positive: bool) -> bytes:
    payload = struct.pack(">HH", source_address, target_address)
    payload_type = PAYLOAD_TYPE_DIAGNOSTIC_MESSAGE_POS_ACK if positive else PAYLOAD_TYPE_DIAGNOSTIC_MESSAGE_NEG_ACK
    return encode_frame(payload_type, payload)
