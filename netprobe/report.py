"""Rendering of scenario results as human-readable and JSON reports.

Responsibilities (implemented in Phase 5):
    * Render a ``ScenarioResult`` (from :mod:`netprobe.scenarios`) as a
      human-readable table for terminal output.
    * Serialize results to JSON for CI archiving and diffing across runs.
"""

from __future__ import annotations
