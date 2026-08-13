# Author: Rayan Hamour (22103817)
"""
Same DoIP-originated unauthorized/abused CAN injection story as
attacks.doip_injection, but driven over a real TCP socket against
doip.socket_gateway.SocketDoIPGateway - a genuine network-level attacker
rather than a Python object handed directly to a method call.
"""

from __future__ import annotations

import time

from carnet.doip.socket_gateway import DoIPSocketClient


def run_socket_doip_injection_attack(
    host: str,
    port: int,
    attacker_address: int,
    duration_s: float,
    rate_hz: float,
    payload: bytes,
    skip_routing_activation: bool = True,
) -> dict:
    client = DoIPSocketClient(host, port, attacker_address)
    try:
        if not skip_routing_activation:
            client.routing_activation()

        interval = 1.0 / rate_hz if rate_hz > 0 else 0.0
        end_time = time.monotonic() + duration_s
        attempts = 0
        forwarded = 0
        while time.monotonic() < end_time:
            ok = client.send_diagnostic(0x1000, payload)
            attempts += 1
            if ok:
                forwarded += 1
            if interval > 0:
                time.sleep(interval)
        return {"attempts": attempts, "forwarded": forwarded, "rejected": attempts - forwarded}
    finally:
        client.close()
