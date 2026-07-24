"""Configurable packet-loss / jitter injection layer.

Responsibilities (implemented in Phase 3):
    * Wrap packet send/receive calls and probabilistically drop packets
      according to a :class:`netprobe.config.LossConfig` (0-100% loss rate,
      default stress scenarios exercise up to 30%).
    * Support a seedable RNG for reproducible runs.
    * Support asymmetric loss (uplink vs downlink) and optional jitter.
"""

from __future__ import annotations
