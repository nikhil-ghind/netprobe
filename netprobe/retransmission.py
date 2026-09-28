"""Retransmission detection and retry/backoff logic.

Responsibilities (implemented in Phase 3):
    * Track sent segments by sequence number and detect duplicate sends
      within a timeout window (i.e. "this is a retransmission, not a new
      segment").
    * Apply exponential backoff between retries per
      :class:`netprobe.config.RetransmissionPolicy`.
    * Count retransmissions per handshake session for reporting.
"""

from __future__ import annotations
