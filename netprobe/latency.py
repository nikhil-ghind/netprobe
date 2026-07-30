"""RTT / latency measurement utilities.

``LatencyStats`` summarizes a collection of latency samples (seconds) the
way a scenario report wants to present them: count, min/max/mean and a p95
tail-latency figure, which matters more than the mean when the point of a
scenario is to show how packet loss and retransmission affect worst-case
handshake completion time.
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Iterable, Optional

from netprobe.handshake import HandshakeResult


@dataclass(frozen=True)
class LatencyStats:
    count: int
    minimum: float
    maximum: float
    mean: float
    median: float
    stddev: float
    p95: float

    @classmethod
    def from_samples(cls, samples: Iterable[float]) -> "LatencyStats":
        """Compute stats from a non-empty iterable of latency samples
        (seconds). Raises ``ValueError`` on an empty input, since "stats of
        zero samples" has no sensible value for min/max/mean."""
        values = sorted(samples)
        if not values:
            raise ValueError("cannot compute LatencyStats from zero samples")

        return cls(
            count=len(values),
            minimum=values[0],
            maximum=values[-1],
            mean=statistics.fmean(values),
            median=statistics.median(values),
            stddev=statistics.pstdev(values) if len(values) > 1 else 0.0,
            p95=percentile(values, 0.95),
        )

    def as_dict(self) -> dict:
        return {
            "count": self.count,
            "min_ms": self.minimum * 1000,
            "max_ms": self.maximum * 1000,
            "mean_ms": self.mean * 1000,
            "median_ms": self.median * 1000,
            "stddev_ms": self.stddev * 1000,
            "p95_ms": self.p95 * 1000,
        }


def percentile(sorted_values: list[float], fraction: float) -> float:
    """Nearest-rank percentile of an already-sorted list, using linear
    interpolation between the two nearest ranks (matches ``numpy``'s default
    'linear' method, without requiring numpy as a dependency)."""
    if not sorted_values:
        raise ValueError("cannot compute a percentile of an empty sequence")
    if not (0.0 <= fraction <= 1.0):
        raise ValueError(f"fraction must be in [0, 1], got {fraction}")
    if len(sorted_values) == 1:
        return sorted_values[0]

    rank = fraction * (len(sorted_values) - 1)
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return sorted_values[int(rank)]
    weight = rank - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


class LatencyCollector:
    """Accumulates latency samples across repeated trials of a scenario and
    produces a :class:`LatencyStats` summary on demand.

    Kept deliberately simple (a growing list) rather than a streaming/online
    algorithm: NetProbe scenarios run at most a few thousand trials, so the
    memory cost of keeping raw samples is negligible and it lets
    :meth:`stats` recompute an exact p95 rather than an approximation.
    """

    def __init__(self):
        self._samples: list[float] = []

    def add(self, seconds: float) -> None:
        self._samples.append(seconds)

    def add_from_result(self, result: HandshakeResult) -> None:
        """Record the end-to-end handshake time from a
        :class:`~netprobe.handshake.HandshakeResult`, if it completed."""
        rtt = result.timing.total_handshake_time
        if rtt is not None:
            self.add(rtt)

    @property
    def samples(self) -> list[float]:
        return list(self._samples)

    def stats(self) -> Optional[LatencyStats]:
        """Return a :class:`LatencyStats` summary, or ``None`` if no samples
        have been recorded yet (e.g. every trial in a scenario timed out)."""
        if not self._samples:
            return None
        return LatencyStats.from_samples(self._samples)
