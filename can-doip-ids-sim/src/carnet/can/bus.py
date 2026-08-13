# Author: Rayan Hamour (22103817)
"""
Virtual CAN bus helpers.

python-can''s "virtual" interface routes messages in-process between every
can.Bus instance opened on the same channel name, which is enough to model
several ECUs talking on one shared bus without any real CAN/SocketCAN
hardware (not available on Windows).
"""

from __future__ import annotations

import can

from carnet.config import CAN_CHANNEL, CAN_INTERFACE


def create_bus() -> can.Bus:
    """Open a handle onto the shared virtual bus. Each ECU/IDS/etc gets its own."""
    return can.Bus(interface=CAN_INTERFACE, channel=CAN_CHANNEL, receive_own_messages=False)


def create_notifier(bus: can.Bus, listeners: list[can.Listener]) -> can.Notifier:
    """Start a background dispatch loop delivering bus messages to listeners."""
    return can.Notifier(bus, listeners)