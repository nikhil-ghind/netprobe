"""Configurable packet-loss / jitter injection layer.

``LossSimulatingTransport`` wraps any :class:`netprobe.handshake.Transport`
(real or fake) and probabilistically drops packets and/or delays them,
according to a :class:`netprobe.config.LossConfig`. It implements the same
``Transport`` protocol itself, so it's a drop-in wrapper:

    real = ScapyTransport()
    lossy = LossSimulatingTransport(real, LossConfig(loss_rate=0.3, seed=7))
    session = HandshakeSession(config, transport=lossy)

Loss is applied independently in each direction:
    * ``send()`` (client -> server / "uplink") can drop the outbound packet
      before it ever reaches the wrapped transport.
    * ``sr1()`` applies uplink loss to the outbound packet the same way, and
      if it wasn't dropped and the wrapped transport got a reply, applies
      downlink loss to decide whether that reply "arrives" back at the
      caller.

A single seeded RNG (``random.Random(seed)``) is reused across all
decisions on one simulator instance, so a full scenario run with a fixed
seed is reproducible end to end, which is what makes packet-loss regression
testing meaningful (the same seed should reproduce the same drop pattern).
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Optional

from scapy.packet import Packet

from netprobe.config import LossConfig
from netprobe.handshake import Transport


@dataclass
class LossStats:
    """Running counters of what a :class:`LossSimulatingTransport` has done,
    useful for scenario reports and for asserting observed drop rates land
    close to the configured ``loss_rate`` over many trials."""

    uplink_sent: int = 0
    uplink_dropped: int = 0
    downlink_sent: int = 0
    downlink_dropped: int = 0

    @property
    def uplink_drop_rate(self) -> float:
        return self.uplink_dropped / self.uplink_sent if self.uplink_sent else 0.0

    @property
    def downlink_drop_rate(self) -> float:
        return self.downlink_dropped / self.downlink_sent if self.downlink_sent else 0.0

    @property
    def total_sent(self) -> int:
        return self.uplink_sent + self.downlink_sent

    @property
    def total_dropped(self) -> int:
        return self.uplink_dropped + self.downlink_dropped

    @property
    def overall_drop_rate(self) -> float:
        return self.total_dropped / self.total_sent if self.total_sent else 0.0


class LossSimulatingTransport:
    """Wraps a :class:`~netprobe.handshake.Transport` and injects loss/jitter
    according to a :class:`~netprobe.config.LossConfig`.

    Sleeps used for jitter are real (``time.sleep``) since this class is
    meant to sit in front of a real transport during actual scenario runs;
    unit tests should use ``LossConfig(jitter=0.0)`` (the default) to keep
    runtime negligible, since jitter doesn't affect drop-rate assertions.
    """

    def __init__(
        self,
        inner: Transport,
        loss_config: LossConfig,
        rng: Optional[random.Random] = None,
    ):
        self.inner = inner
        self.loss_config = loss_config
        self._rng = rng if rng is not None else random.Random(loss_config.seed)
        self.stats = LossStats()

    def _roll_drop(self, rate: float) -> bool:
        if rate <= 0.0:
            return False
        if rate >= 1.0:
            return True
        return self._rng.random() < rate

    def _apply_jitter(self) -> None:
        if self.loss_config.jitter > 0:
            delay = self._rng.uniform(0.0, self.loss_config.jitter)
            if delay > 0:
                time.sleep(delay)

    def send(self, pkt: Packet) -> None:
        """Fire-and-forget send, subject to uplink loss only (there is no
        response to lose on the downlink side of a one-way send)."""
        self.stats.uplink_sent += 1
        if self._roll_drop(self.loss_config.effective_uplink_loss_rate):
            self.stats.uplink_dropped += 1
            return
        self._apply_jitter()
        self.inner.send(pkt)

    def sr1(self, pkt: Packet, timeout: float) -> Optional[Packet]:
        """Send-and-wait, subject to uplink loss on the request and downlink
        loss on the response.

        Returns ``None`` (indistinguishable from a real timeout, by design)
        whenever either the outbound packet or the inbound reply is dropped.
        """
        self.stats.uplink_sent += 1
        if self._roll_drop(self.loss_config.effective_uplink_loss_rate):
            self.stats.uplink_dropped += 1
            return None

        self._apply_jitter()
        response = self.inner.sr1(pkt, timeout=timeout)
        if response is None:
            return None

        self.stats.downlink_sent += 1
        if self._roll_drop(self.loss_config.effective_downlink_loss_rate):
            self.stats.downlink_dropped += 1
            return None

        self._apply_jitter()
        return response
