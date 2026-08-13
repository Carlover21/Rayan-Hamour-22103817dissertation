# Author: Rayan Hamour (22103817)
"""
Shared configuration for the CAN/DoIP in-vehicle network simulation.

Defines the simulated vehicle's ECU topology (CAN arbitration IDs, expected
periods) and IDS detection thresholds. Centralising these here means the
traffic generator, the IDS whitelist, and the evaluation harness all agree
on what "normal" looks like.
"""

from __future__ import annotations

CAN_CHANNEL = "carnet_vbus"
CAN_INTERFACE = "virtual"
CAN_BITRATE = 500_000  # nominal, virtual bus does not enforce timing at this rate

# --- Simulated ECU topology -------------------------------------------------
# Each entry describes one legitimate, periodic CAN message on the bus.
# period_s: nominal transmission interval in seconds.
# jitter_s: +/- random jitter applied around the period to look like real traffic.
# dlc: data length code in bytes (classic CAN: 0-8; CAN-FD: up to 64).
# is_fd: whether this ID is sent as a CAN-FD frame - real vehicles increasingly
# use FD for ADAS/sensor-fusion payloads that don't fit in 8 bytes.
ECU_PROFILE = {
    0x100: {"name": "Engine_RPM_Speed", "period_s": 0.010, "jitter_s": 0.002, "dlc": 8, "is_fd": False},
    0x200: {"name": "Brake_Status", "period_s": 0.020, "jitter_s": 0.004, "dlc": 4, "is_fd": False},
    0x300: {"name": "Steering_Angle", "period_s": 0.020, "jitter_s": 0.004, "dlc": 4, "is_fd": False},
    0x400: {"name": "Body_Control_Doors_Lights", "period_s": 0.100, "jitter_s": 0.010, "dlc": 4, "is_fd": False},
    0x500: {"name": "Battery_Temp_Voltage", "period_s": 0.200, "jitter_s": 0.020, "dlc": 6, "is_fd": False},
    0x600: {"name": "ADAS_Sensor_Fusion", "period_s": 0.020, "jitter_s": 0.002, "dlc": 32, "is_fd": True},
    0x7E0: {"name": "Diagnostic_Gateway_Response", "period_s": None, "jitter_s": 0.0, "dlc": 8, "is_fd": False},
}

# The set of arbitration IDs the IDS considers legitimate. Anything else
# appearing on the bus is flagged as an unknown-ID violation.
KNOWN_IDS = set(ECU_PROFILE.keys())

# IDs that are only ever expected as a *response* to a DoIP-triggered
# diagnostic request, never as spontaneous periodic traffic.
DIAGNOSTIC_ONLY_IDS = {0x7E0}

# --- DoIP (mocked) ----------------------------------------------------------
# Logical addressing loosely modelled on ISO 13400 (source/target testers and
# ECUs), used only to route a mocked diagnostic message onto the CAN bus.
DOIP_GATEWAY_LOGICAL_ADDRESS = 0x1000
DOIP_TESTER_LOGICAL_ADDRESS = 0x0E00
DOIP_ROUTE_TARGET_CAN_ID = 0x7E0  # CAN ID the gateway emits after routing activation

# --- IDS thresholds ----------------------------------------------------------
IDS_CONFIG = {
    # Sliding window (seconds) used for rate-based detection.
    "window_s": 1.0,
    # Max allowed messages per known ID per window before flagging flooding.
    # Derived generously above each ECU_PROFILE period so normal jitter never
    # trips it, but a flood attack (sent far faster than nominal) will.
    "max_msgs_per_window": {
        0x100: 150,   # nominal ~100/window
        0x200: 80,    # nominal ~50/window
        0x300: 80,
        0x400: 20,
        0x500: 10,
        0x600: 80,   # nominal ~50/window
        0x7E0: 20,
    },
    "default_max_msgs_per_window": 50,
    # Allowed timing deviation (as a fraction of nominal period) before a
    # message is flagged as a pattern/timing anomaly, independent of rate.
    "timing_deviation_ratio": 4.0,
}

# --- SecOC-style message authentication (simplified) -------------------------
# Off by default so the original rule-based evaluation is unaffected; the
# evaluation harness can flip this on to produce a with/without comparison.
# The master key lives only where legitimate ECUs and the verifier can reach
# it in code - attacker and DoIP-gateway code paths are never given it.
SECOC_ENABLED = False
SECOC_MASTER_KEY = b"dev-only-simulation-master-key-not-for-real-use"

# --- CAN error-handling / bus-off (simplified) --------------------------------
# Real CAN controllers track a transmit error counter (TEC, ISO 11898-1) and
# go bus-off (stop transmitting entirely) once it passes 255. A bus-off
# attack deliberately drives a victim ID's TEC past that threshold.
BUS_OFF_TEC_THRESHOLD = 256
BUS_OFF_TEC_INCREMENT = 8  # TEC added per attacker error-inducing frame

# How many multiples of an ID's nominal period it can go silent for before
# the IDS treats the silence itself as suspicious (e.g. a bus-off attack).
SILENCE_RATIO = 6.0

LOG_DIR = "logs"
RESULTS_DIR = "results"