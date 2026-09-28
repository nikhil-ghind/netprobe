"""TCP three-way handshake state machine.

The state machine itself never calls Scapy's ``sr1``/``send`` directly.
Instead it talks to a small :class:`Transport` protocol, which lets
Phase 4's pytest suite drive a `HandshakeSession` against an in-memory fake
transport (no raw sockets, no root) while production code uses
:class:`ScapyTransport`, which does the real send/receive over the network.

State transitions::

    CLOSED --send SYN--> SYN_SENT --recv SYN-ACK, send ACK--> ESTABLISHED
    CLOSED --send SYN--> SYN_SENT --timeout/bad response--> FAILED
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Optional, Protocol

from scapy.packet import Packet

from netprobe.config import NetworkConfig
from netprobe.exceptions import HandshakeTimeout
from netprobe.packet_builder import (
    HandshakeExpectation,
    build_ack,
    build_syn,
    validate_response,
)


class HandshakeState(enum.Enum):
    CLOSED = "CLOSED"
    SYN_SENT = "SYN_SENT"
    ESTABLISHED = "ESTABLISHED"
    FAILED = "FAILED"


class Transport(Protocol):
    """Minimal send/receive surface the handshake state machine needs.

    Implementations may drop or delay packets (see
    :mod:`netprobe.loss_simulator`); the state machine only cares whether a
    response arrived within ``timeout`` or not.
    """

    def send(self, pkt: Packet) -> None:
        """Send ``pkt`` without waiting for a response."""

    def sr1(self, pkt: Packet, timeout: float) -> Optional[Packet]:
        """Send ``pkt`` and wait up to ``timeout`` seconds for a single
        matching response, returning ``None`` on timeout."""


class ScapyTransport:
    """Real transport backed by Scapy's raw-socket send/receive.

    Sending raw TCP/IP packets requires ``CAP_NET_RAW`` (or root); this is
    exactly the piece the test suite replaces with an in-memory fake so the
    rest of NetProbe's logic can be exercised without elevated privileges.
    """

    def send(self, pkt: Packet) -> None:
        from scapy.sendrecv import send as scapy_send

        scapy_send(pkt, verbose=False)

    def sr1(self, pkt: Packet, timeout: float) -> Optional[Packet]:
        from scapy.sendrecv import sr1 as scapy_sr1

        return scapy_sr1(pkt, timeout=timeout, verbose=False)


@dataclass
class HandshakeTiming:
    """Wall-clock timestamps (seconds, from :func:`time.monotonic`) for each
    leg of a handshake attempt, used by :mod:`netprobe.latency` to compute
    RTT statistics."""

    syn_sent_at: Optional[float] = None
    syn_ack_received_at: Optional[float] = None
    ack_sent_at: Optional[float] = None

    @property
    def syn_to_syn_ack_rtt(self) -> Optional[float]:
        """Time from sending SYN to receiving SYN-ACK, i.e. the network RTT
        for the first two legs of the handshake."""
        if self.syn_sent_at is None or self.syn_ack_received_at is None:
            return None
        return self.syn_ack_received_at - self.syn_sent_at

    @property
    def total_handshake_time(self) -> Optional[float]:
        """Time from sending SYN to sending the final ACK, i.e. how long the
        full three-way handshake took from this side's perspective."""
        if self.syn_sent_at is None or self.ack_sent_at is None:
            return None
        return self.ack_sent_at - self.syn_sent_at


@dataclass
class HandshakeResult:
    """Outcome of a single :meth:`HandshakeSession.attempt` call."""

    state: HandshakeState
    timing: HandshakeTiming = field(default_factory=HandshakeTiming)
    client_isn: Optional[int] = None
    server_isn: Optional[int] = None
    error: Optional[Exception] = None

    @property
    def succeeded(self) -> bool:
        return self.state is HandshakeState.ESTABLISHED


class HandshakeSession:
    """Drives one TCP three-way handshake attempt against ``config.target``.

    Usage::

        session = HandshakeSession(config, transport=ScapyTransport())
        result = session.attempt()
        if result.succeeded:
            print(result.timing.total_handshake_time)

    A single ``HandshakeSession`` represents one attempt; callers that want
    to retry under packet loss construct a fresh session per attempt (or use
    :mod:`netprobe.retransmission` to drive retries across attempts) so that
    each attempt gets its own client ISN and source port, matching how a
    real TCP stack starts a new connection attempt after a failed one.
    """

    def __init__(self, config: NetworkConfig, transport: Optional[Transport] = None):
        self.config = config
        self.transport = transport or ScapyTransport()
        self.state = HandshakeState.CLOSED

    def attempt(self) -> HandshakeResult:
        """Run one full handshake attempt and return its result.

        Never raises for ordinary network-shaped failures (timeout,
        unexpected flags, sequence mismatch); those are captured on
        ``HandshakeResult.error`` with ``state == FAILED`` so callers such as
        :mod:`netprobe.retransmission` can decide whether to retry. Only
        programming errors (e.g. a malformed ``NetworkConfig``, already
        validated at construction time) propagate as exceptions.
        """
        timing = HandshakeTiming()

        syn_pkt, expectation = build_syn(self.config)
        client_isn = syn_pkt.seq
        client_sport = syn_pkt.sport

        self.state = HandshakeState.SYN_SENT
        timing.syn_sent_at = time.monotonic()

        response = self.transport.sr1(syn_pkt, timeout=self.config.timeout)

        if response is None:
            self.state = HandshakeState.FAILED
            error = HandshakeTimeout(stage="syn_ack", timeout=self.config.timeout)
            return HandshakeResult(
                state=self.state,
                timing=timing,
                client_isn=client_isn,
                error=error,
            )

        timing.syn_ack_received_at = time.monotonic()

        try:
            validate_response(response, expectation)
        except Exception as exc:  # UnexpectedFlags / SequenceMismatch
            self.state = HandshakeState.FAILED
            return HandshakeResult(
                state=self.state,
                timing=timing,
                client_isn=client_isn,
                error=exc,
            )

        server_isn = response.seq

        ack_pkt = build_ack(
            self.config,
            client_isn=client_isn,
            server_isn=server_isn,
            source_port=client_sport,
        )
        self.transport.send(ack_pkt)
        timing.ack_sent_at = time.monotonic()

        self.state = HandshakeState.ESTABLISHED
        return HandshakeResult(
            state=self.state,
            timing=timing,
            client_isn=client_isn,
            server_isn=server_isn,
        )
