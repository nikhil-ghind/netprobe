"""Scapy-based construction and validation of TCP/IP packets.

Responsibilities (implemented in Phase 2):
    * Build IP/TCP layers for SYN, SYN-ACK, ACK, RST and data segments with
      correct sequence/ack-number bookkeeping and window sizing.
    * Validate an observed packet's flags, sequence numbers and checksums
      against what a handshake stage expects.

This module intentionally has no dependency on the handshake state machine
in :mod:`netprobe.handshake` -- it is pure packet construction/validation so
it can be unit tested without opening any sockets.
"""

from __future__ import annotations
