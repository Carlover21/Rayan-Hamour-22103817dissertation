"""
Simplified SecOC-style message authentication (loosely modelled on AUTOSAR
Secure Onboard Communication), not a spec-accurate implementation: real
SecOC uses a configurable truncated CMAC/HMAC length and a windowed
freshness value synchronised out-of-band. Here every authenticated CAN
frame carries 4 bytes of payload, a 1-byte rolling counter, and a 3-byte
truncated HMAC-SHA256 - enough to demonstrate the security property that
matters for this project: only a party holding the per-ID key can produce
a frame the verifier accepts, and a captured frame cannot be replayed once
its counter has been superseded.

Per-arbitration-ID keys are derived from one master key, matching the real
practice of scoping keys tightly (e.g. per-ECU or per-signal) rather than
sharing one key across the whole vehicle. A component that only forwards
traffic (like a diagnostic gateway) and is never given the master key
cannot derive a valid per-ID key even if it is compromised or abused - so
a message it injects or forwards fails verification just like an outsider's
would.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

MAC_LEN = 3
COUNTER_MAX = 256
FRESHNESS_WINDOW = 64  # max allowed forward counter jump before flagged


def derive_id_key(master_key: bytes, arbitration_id: int) -> bytes:
    return hmac.new(master_key, struct.pack(">H", arbitration_id), hashlib.sha256).digest()


def _compute_mac(id_key: bytes, arbitration_id: int, counter: int, payload4: bytes) -> bytes:
    msg = struct.pack(">HB", arbitration_id, counter) + payload4
    return hmac.new(id_key, msg, hashlib.sha256).digest()[:MAC_LEN]


class SecOCContext:
    """Held by legitimate ECUs (to protect outgoing frames) and by the IDS/
    verifier (to check incoming ones). Attacker code is never given a
    reference to this - that absence is what makes forged frames fail."""

    def __init__(self, master_key: bytes):
        self.master_key = master_key
        self._tx_counters: dict[int, int] = {}
        self._rx_last_counter: dict[int, int] = {}

    def protect(self, arbitration_id: int, payload: bytes) -> bytes:
        counter = self._tx_counters.get(arbitration_id, 0)
        self._tx_counters[arbitration_id] = (counter + 1) % COUNTER_MAX
        payload4 = payload[:4].ljust(4, b"\x00")
        id_key = derive_id_key(self.master_key, arbitration_id)
        mac = _compute_mac(id_key, arbitration_id, counter, payload4)
        return payload4 + bytes([counter]) + mac

    def verify(self, arbitration_id: int, data: bytes) -> tuple[bool, str]:
        if len(data) < 4 + 1 + MAC_LEN:
            return False, "short_frame"
        payload4, counter, mac = data[0:4], data[4], data[5 : 5 + MAC_LEN]
        id_key = derive_id_key(self.master_key, arbitration_id)
        expected = _compute_mac(id_key, arbitration_id, counter, payload4)
        if not hmac.compare_digest(mac, expected):
            return False, "mac_invalid"

        last = self._rx_last_counter.get(arbitration_id)
        if last is not None:
            advance = (counter - last) % COUNTER_MAX
            if advance == 0:
                return False, "replay_counter"
            if advance > FRESHNESS_WINDOW:
                return False, "freshness_violation"
        self._rx_last_counter[arbitration_id] = counter
        return True, "ok"

    def reset(self) -> None:
        self._tx_counters.clear()
        self._rx_last_counter.clear()