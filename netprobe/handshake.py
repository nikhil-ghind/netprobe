"""TCP three-way handshake state machine.

Responsibilities (implemented in Phase 2, extended in Phase 3):
    * Drive a handshake attempt (SYN -> SYN-ACK -> ACK) using packets built by
      :mod:`netprobe.packet_builder`.
    * Track state transitions (CLOSED -> SYN_SENT -> ESTABLISHED / FAILED).
    * Record per-leg timestamps for latency measurement.
    * Raise typed exceptions from :mod:`netprobe.exceptions` on failure.
    * (Phase 3) Run under a :class:`netprobe.loss_simulator.LossSimulator`
      and retry according to :class:`netprobe.config.RetransmissionPolicy`.
"""

from __future__ import annotations
