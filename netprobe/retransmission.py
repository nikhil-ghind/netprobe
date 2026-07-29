"""Retransmission detection and retry/backoff logic.

Two related but distinct concerns live here:

1. :class:`RetransmissionTracker` -- structural duplicate-send detection.
   Given a stream of outbound segments, decide whether a given segment is a
   retransmission of one already sent (same 4-tuple/seq/flags per
   :func:`netprobe.packet_builder.is_retransmission_candidate`) within a
   configurable timeout window, the way a real TCP stack or a packet capture
   analyzer would flag retransmissions.

2. :func:`run_handshake_with_retries` -- the retry loop that drives
   :class:`netprobe.handshake.HandshakeSession` attempts across a lossy
   transport, applying :class:`netprobe.config.RetransmissionPolicy`'s
   exponential backoff between attempts and giving up with
   :class:`~netprobe.exceptions.RetransmissionLimitExceeded` once the retry
   budget is exhausted.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from scapy.packet import Packet

from netprobe.config import NetworkConfig, RetransmissionPolicy
from netprobe.exceptions import RetransmissionLimitExceeded
from netprobe.handshake import HandshakeResult, HandshakeSession, HandshakeState, Transport
from netprobe.packet_builder import is_retransmission_candidate


@dataclass
class _TrackedSegment:
    packet: Packet
    sent_at: float


class RetransmissionTracker:
    """Detects duplicate outbound segments within a timeout window.

    A segment is considered a retransmission if a structurally identical
    segment (same destination, ports, sequence number and flags) was
    recorded within ``window`` seconds of the current one. Segments outside
    the window are treated as unrelated (e.g. a genuinely new connection
    attempt that happens to reuse a sequence number), matching how
    retransmission timers work in practice: a segment observed well after
    the RTO isn't "the same" retransmission event any more, it's a
    fresh decision by the sender.
    """

    def __init__(self, window: float = 5.0):
        self.window = window
        self._segments: list[_TrackedSegment] = []
        self.retransmission_count = 0

    def record(self, pkt: Packet, now: Optional[float] = None) -> bool:
        """Record an outbound packet and return whether it is a
        retransmission of a previously recorded one within the window."""
        ts = now if now is not None else time.monotonic()
        self._prune(ts)

        is_retransmission = any(
            is_retransmission_candidate(pkt, tracked.packet) for tracked in self._segments
        )
        if is_retransmission:
            self.retransmission_count += 1

        self._segments.append(_TrackedSegment(packet=pkt, sent_at=ts))
        return is_retransmission

    def _prune(self, now: float) -> None:
        cutoff = now - self.window
        self._segments = [s for s in self._segments if s.sent_at >= cutoff]

    def reset(self) -> None:
        self._segments.clear()
        self.retransmission_count = 0


@dataclass
class RetryOutcome:
    """Result of :func:`run_handshake_with_retries`: the final handshake
    result plus how many attempts/retransmissions it took to get there."""

    result: HandshakeResult
    attempts: int
    retransmissions: int


def run_handshake_with_retries(
    config: NetworkConfig,
    policy: RetransmissionPolicy,
    transport: Transport,
    sleep_fn=time.sleep,
) -> RetryOutcome:
    """Attempt a handshake, retrying with exponential backoff on failure.

    Each attempt uses a fresh :class:`~netprobe.handshake.HandshakeSession`
    (so it gets a new client ISN and source port, like a real TCP stack
    retrying a failed SYN), run over the same ``transport`` (typically a
    :class:`netprobe.loss_simulator.LossSimulatingTransport` so retries are
    themselves subject to loss). Stops as soon as an attempt succeeds.

    ``sleep_fn`` defaults to :func:`time.sleep` and is overridable so tests
    can assert on the backoff schedule without actually waiting.

    Raises :class:`~netprobe.exceptions.RetransmissionLimitExceeded` if
    every attempt (the first plus ``policy.max_retries`` retries) fails;
    the exception's ``attempts`` reflects the total number tried.
    """
    last_result: Optional[HandshakeResult] = None
    total_attempts = policy.max_retries + 1

    for attempt_number in range(1, total_attempts + 1):
        session = HandshakeSession(config, transport=transport)
        last_result = session.attempt()

        if last_result.state is HandshakeState.ESTABLISHED:
            return RetryOutcome(
                result=last_result,
                attempts=attempt_number,
                retransmissions=attempt_number - 1,
            )

        if attempt_number < total_attempts:
            sleep_fn(policy.backoff_for_attempt(attempt_number))

    assert last_result is not None  # total_attempts >= 1 always
    raise RetransmissionLimitExceeded(
        seq=last_result.client_isn or 0,
        attempts=total_attempts,
        limit=policy.max_retries,
    )
