"""In-memory fake transports used across the test suite.

These implement the :class:`netprobe.handshake.Transport` protocol without
touching a real socket, so the handshake/retransmission/scenario logic can
be exercised deterministically and without root privileges. Production code
never imports this module.
"""

from __future__ import annotations

import itertools
from typing import Optional

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


class FakeTransport:
    """Stands in for a real TCP peer.

    On ``sr1``, replies to a SYN with a SYN-ACK (or whatever
    ``response_flags``/``corrupt_ack`` say to send instead), so tests can
    steer a :class:`~netprobe.handshake.HandshakeSession` through every
    branch of its state machine without a network.
    """

    def __init__(
        self,
        respond: bool = True,
        response_flags: str = "SA",
        corrupt_ack: bool = False,
        server_isn: Optional[int] = None,
    ):
        self.respond = respond
        self.response_flags = response_flags
        self.corrupt_ack = corrupt_ack
        self.server_isn = server_isn
        self.sent_packets: list[Packet] = []
        self._isn_counter = itertools.count(1000)

    def send(self, pkt: Packet) -> None:
        self.sent_packets.append(pkt)

    def sr1(self, pkt: Packet, timeout: float) -> Optional[Packet]:
        self.sent_packets.append(pkt)
        if not self.respond:
            return None

        s_isn = self.server_isn if self.server_isn is not None else next(self._isn_counter)
        ack = pkt.seq + 1
        if self.corrupt_ack:
            ack += 1

        return IP(src=pkt.dst, dst="198.51.100.1") / TCP(
            sport=pkt.dport,
            dport=pkt.sport,
            flags=self.response_flags,
            seq=s_isn,
            ack=ack,
            window=8192,
        )


class FlakyTransport:
    """Wraps another transport and fails the first ``fail_count`` ``sr1``
    calls (returns ``None``, as if the SYN-ACK were lost) before delegating
    normally, used to test the retry/backoff loop in
    :mod:`netprobe.retransmission` deterministically (as opposed to relying
    on a seeded probabilistic :class:`~netprobe.loss_simulator.LossSimulatingTransport`).
    """

    def __init__(self, inner: FakeTransport, fail_count: int):
        self.inner = inner
        self.fail_count = fail_count
        self.calls = 0

    def send(self, pkt: Packet) -> None:
        self.inner.send(pkt)

    def sr1(self, pkt: Packet, timeout: float) -> Optional[Packet]:
        self.calls += 1
        if self.calls <= self.fail_count:
            return None
        return self.inner.sr1(pkt, timeout)
