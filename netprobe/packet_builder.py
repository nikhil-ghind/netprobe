"""Scapy-based construction and validation of TCP/IP packets.

This module is pure packet construction/validation: it has no dependency on
the handshake state machine in :mod:`netprobe.handshake`, and it never opens
a socket or touches the network itself, so it can be unit tested with plain
in-memory Scapy packets.

Sequence-number convention used throughout: an "ISN" (initial sequence
number) identifies the first byte of a stream's data. A SYN and a FIN each
"consume" one sequence number even though they carry no payload, which is
why the client's ACK in the third leg of the handshake acknowledges
``server_isn + 1`` rather than ``server_isn``.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from netprobe.config import NetworkConfig
from netprobe.exceptions import ChecksumError, SequenceMismatch, UnexpectedFlags

# Canonical TCP flag combinations used by the handshake and RST/data paths.
FLAG_SYN = "S"
FLAG_SYN_ACK = "SA"
FLAG_ACK = "A"
FLAG_RST = "R"
FLAG_RST_ACK = "RA"
FLAG_FIN = "F"
FLAG_FIN_ACK = "FA"
FLAG_PSH_ACK = "PA"

MAX_SEQ = 2**32 - 1


def random_isn() -> int:
    """Return a random 32-bit initial sequence number.

    Real TCP stacks derive the ISN from a clock plus a per-connection hash
    for anti-spoofing reasons; for a validation/regression tool a uniformly
    random ISN is sufficient and keeps the choice reproducible when the
    caller seeds Python's ``random`` module.
    """
    return random.randint(0, MAX_SEQ)


def seq_add(seq: int, delta: int) -> int:
    """Add ``delta`` to a sequence number with 32-bit wraparound, matching
    TCP's modular sequence-number arithmetic (RFC 793 §3.3)."""
    return (seq + delta) & MAX_SEQ


@dataclass(frozen=True)
class HandshakeExpectation:
    """What the next inbound segment of a handshake is expected to look like.

    Produced alongside each outbound packet built by this module so that
    :mod:`netprobe.handshake` can validate a response with
    :func:`validate_response` without recomputing sequence-number math
    itself.
    """

    stage: str
    expected_flags: str
    expected_ack: int | None = None
    expected_seq: int | None = None


def build_syn(config: NetworkConfig, *, seq: int | None = None, source_port: int | None = None):
    """Build the first leg of the handshake: a bare SYN segment.

    Returns a ``(packet, expectation)`` pair where ``expectation`` describes
    the SYN-ACK that should come back: flags ``SA`` and an ack number equal
    to ``seq + 1`` (the client's ISN, plus one for the consumed SYN).
    """
    isn = random_isn() if seq is None else seq
    sport = source_port if source_port is not None else random.randint(1024, 65535)
    pkt = (
        IP(dst=config.target_host)
        / TCP(
            sport=sport,
            dport=config.target_port,
            flags=FLAG_SYN,
            seq=isn,
            ack=0,
            window=config.window_size,
        )
    )
    expectation = HandshakeExpectation(
        stage="syn_ack",
        expected_flags=FLAG_SYN_ACK,
        expected_ack=seq_add(isn, 1),
    )
    return pkt, expectation


def build_syn_ack(config: NetworkConfig, *, client_isn: int, server_isn: int | None = None):
    """Build the second leg: a SYN-ACK responding to a client SYN.

    ``client_isn`` is the sequence number seen on the inbound SYN. Returns
    a ``(packet, expectation)`` pair where ``expectation`` describes the
    final ACK that should complete the handshake: flags ``A``, ack equal to
    ``server_isn + 1``, and seq equal to ``client_isn + 1``.
    """
    s_isn = random_isn() if server_isn is None else server_isn
    pkt = (
        IP(dst=config.target_host)
        / TCP(
            sport=config.target_port,
            dport=0,  # filled in by the caller once the client's sport is known
            flags=FLAG_SYN_ACK,
            seq=s_isn,
            ack=seq_add(client_isn, 1),
            window=config.window_size,
        )
    )
    expectation = HandshakeExpectation(
        stage="ack",
        expected_flags=FLAG_ACK,
        expected_ack=seq_add(s_isn, 1),
        expected_seq=seq_add(client_isn, 1),
    )
    return pkt, expectation


def build_ack(
    config: NetworkConfig,
    *,
    client_isn: int,
    server_isn: int,
    source_port: int,
) -> Packet:
    """Build the third leg: the final ACK that establishes the connection.

    ``client_isn``/``server_isn`` are the ISNs exchanged in legs one and two;
    the ACK's own seq is ``client_isn + 1`` and it acknowledges
    ``server_isn + 1``.
    """
    return (
        IP(dst=config.target_host)
        / TCP(
            sport=source_port,
            dport=config.target_port,
            flags=FLAG_ACK,
            seq=seq_add(client_isn, 1),
            ack=seq_add(server_isn, 1),
            window=config.window_size,
        )
    )


def build_rst(config: NetworkConfig, *, seq: int, source_port: int, ack: int = 0) -> Packet:
    """Build an RST segment, e.g. to abort a session or reject a connection."""
    flags = FLAG_RST_ACK if ack else FLAG_RST
    return (
        IP(dst=config.target_host)
        / TCP(
            sport=source_port,
            dport=config.target_port,
            flags=flags,
            seq=seq,
            ack=ack,
            window=config.window_size,
        )
    )


def build_data(
    config: NetworkConfig,
    *,
    seq: int,
    ack: int,
    source_port: int,
    payload: bytes = b"",
) -> Packet:
    """Build a PSH-ACK data segment carrying ``payload`` on an established
    connection, used by retransmission tests to exercise duplicate-send
    detection on segments with actual data."""
    pkt = (
        IP(dst=config.target_host)
        / TCP(
            sport=source_port,
            dport=config.target_port,
            flags=FLAG_PSH_ACK,
            seq=seq,
            ack=ack,
            window=config.window_size,
        )
    )
    if payload:
        pkt = pkt / payload
    return pkt


def extract_flags(pkt: Packet) -> str:
    """Return the TCP flags of ``pkt`` as Scapy's short-string representation
    (e.g. ``"SA"``), raising ``UnexpectedFlags`` if ``pkt`` has no TCP layer."""
    if not pkt.haslayer(TCP):
        raise UnexpectedFlags(stage="unknown", expected="<any TCP>", actual="<no TCP layer>")
    return str(pkt[TCP].flags)


def validate_response(pkt: Packet, expectation: HandshakeExpectation) -> None:
    """Validate an inbound packet against a :class:`HandshakeExpectation`.

    Raises :class:`~netprobe.exceptions.UnexpectedFlags` if the flags don't
    match, or :class:`~netprobe.exceptions.SequenceMismatch` if the
    ack/seq numbers don't match. Returns ``None`` on success.
    """
    actual_flags = extract_flags(pkt)
    if actual_flags != expectation.expected_flags:
        raise UnexpectedFlags(
            stage=expectation.stage,
            expected=expectation.expected_flags,
            actual=actual_flags,
        )

    tcp = pkt[TCP]
    if expectation.expected_ack is not None and tcp.ack != expectation.expected_ack:
        raise SequenceMismatch(
            stage=expectation.stage,
            expected=expectation.expected_ack,
            actual=tcp.ack,
            field="ack",
        )
    if expectation.expected_seq is not None and tcp.seq != expectation.expected_seq:
        raise SequenceMismatch(
            stage=expectation.stage,
            expected=expectation.expected_seq,
            actual=tcp.seq,
            field="seq",
        )


def validate_checksum(pkt: Packet) -> None:
    """Recompute and verify a packet's IP and TCP checksums.

    Scapy fills in checksums lazily when a packet is serialized, so this
    forces a round-trip through ``bytes()`` and re-parses it, comparing the
    recomputed checksum fields against the original. Raises
    :class:`~netprobe.exceptions.ChecksumError` on mismatch.
    """
    if not pkt.haslayer(IP):
        raise ChecksumError("packet has no IP layer to checksum")

    original_ip_chksum = pkt[IP].chksum
    original_tcp_chksum = pkt[TCP].chksum if pkt.haslayer(TCP) else None

    raw = bytes(pkt)
    reparsed = IP(raw)

    if original_ip_chksum is not None and reparsed.chksum != original_ip_chksum:
        raise ChecksumError(
            f"IP checksum mismatch: packet claims {original_ip_chksum:#06x}, "
            f"recomputed {reparsed.chksum:#06x}"
        )
    if (
        original_tcp_chksum is not None
        and reparsed.haslayer(TCP)
        and reparsed[TCP].chksum != original_tcp_chksum
    ):
        raise ChecksumError(
            f"TCP checksum mismatch: packet claims {original_tcp_chksum:#06x}, "
            f"recomputed {reparsed[TCP].chksum:#06x}"
        )


def is_retransmission_candidate(a: Packet, b: Packet) -> bool:
    """Return True if two outbound TCP segments look like the same logical
    segment sent twice (same 4-tuple, seq and flags) -- the structural check
    used by :mod:`netprobe.retransmission` before applying its timing
    window. Payload is deliberately not compared: a retransmission of a data
    segment must carry identical bytes, but comparing seq/flags/ports is
    sufficient to identify *which* segment it is a retransmission of."""
    if not (a.haslayer(TCP) and b.haslayer(TCP)):
        return False
    ta, tb = a[TCP], b[TCP]
    ia, ib = a[IP], b[IP]
    return (
        ia.dst == ib.dst
        and ta.sport == tb.sport
        and ta.dport == tb.dport
        and ta.seq == tb.seq
        and str(ta.flags) == str(tb.flags)
    )


def pack_isn(isn: int) -> bytes:
    """Serialize a sequence number to 4 network-order bytes, useful for
    embedding/comparing ISNs in test fixtures and logs."""
    return struct.pack("!I", isn & MAX_SEQ)
