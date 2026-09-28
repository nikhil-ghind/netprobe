"""Scenario runner: executes named scenarios and aggregates results.

Responsibilities (implemented in Phase 4):
    * Run a named scenario (e.g. "clean handshake", "handshake under 30%
      loss", "retransmission stress") for N trials per
      :class:`netprobe.config.ScenarioConfig`.
    * Aggregate results into a ``ScenarioResult`` (success rate,
      retransmission counts, latency stats) for reporting and pytest
      assertions.
"""

from __future__ import annotations
