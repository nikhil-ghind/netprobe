"""RTT / latency measurement utilities.

Responsibilities (implemented in Phase 3):
    * Measure per-leg and end-to-end handshake latency from the timestamps
      recorded by :mod:`netprobe.handshake`.
    * Compute running statistics (min/max/mean/p95/stddev) across repeated
      trials for use in scenario reports.
"""

from __future__ import annotations
