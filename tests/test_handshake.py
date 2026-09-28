from __future__ import annotations

import pytest

from netprobe.exceptions import HandshakeTimeout, SequenceMismatch, UnexpectedFlags
from netprobe.handshake import HandshakeSession, HandshakeState
from tests.fakes import FakeTransport


def test_successful_handshake_reaches_established(network_config):
    transport = FakeTransport(server_isn=5000)
    session = HandshakeSession(network_config, transport=transport)

    result = session.attempt()

    assert result.succeeded
    assert result.state is HandshakeState.ESTABLISHED
    assert result.server_isn == 5000
    assert result.error is None
    # Two packets should have gone out: the SYN (via sr1) and the final ACK (via send).
    assert len(transport.sent_packets) == 2
    assert transport.sent_packets[0].flags == "S"
    assert transport.sent_packets[1].flags == "A"


def test_successful_handshake_records_timing(network_config):
    transport = FakeTransport(server_isn=5000)
    session = HandshakeSession(network_config, transport=transport)

    result = session.attempt()

    assert result.timing.syn_sent_at is not None
    assert result.timing.syn_ack_received_at is not None
    assert result.timing.ack_sent_at is not None
    assert result.timing.syn_to_syn_ack_rtt is not None
    assert result.timing.syn_to_syn_ack_rtt >= 0
    assert result.timing.total_handshake_time is not None
    assert result.timing.total_handshake_time >= result.timing.syn_to_syn_ack_rtt


def test_handshake_times_out_when_no_response(network_config):
    transport = FakeTransport(respond=False)
    session = HandshakeSession(network_config, transport=transport)

    result = session.attempt()

    assert not result.succeeded
    assert result.state is HandshakeState.FAILED
    assert isinstance(result.error, HandshakeTimeout)
    assert result.error.stage == "syn_ack"


def test_handshake_fails_on_unexpected_flags(network_config):
    transport = FakeTransport(response_flags="R")
    session = HandshakeSession(network_config, transport=transport)

    result = session.attempt()

    assert not result.succeeded
    assert result.state is HandshakeState.FAILED
    assert isinstance(result.error, UnexpectedFlags)


def test_handshake_fails_on_sequence_mismatch(network_config):
    transport = FakeTransport(corrupt_ack=True)
    session = HandshakeSession(network_config, transport=transport)

    result = session.attempt()

    assert not result.succeeded
    assert result.state is HandshakeState.FAILED
    assert isinstance(result.error, SequenceMismatch)


def test_session_state_reflects_last_attempt(network_config):
    transport = FakeTransport(server_isn=5000)
    session = HandshakeSession(network_config, transport=transport)

    assert session.state is HandshakeState.CLOSED
    session.attempt()
    assert session.state is HandshakeState.ESTABLISHED


def test_each_attempt_uses_a_fresh_client_isn(network_config):
    transport = FakeTransport(server_isn=5000)
    session = HandshakeSession(network_config, transport=transport)

    result1 = session.attempt()
    result2 = session.attempt()

    # Extremely unlikely to collide by chance with 32-bit random ISNs;
    # this guards against accidentally reusing state across attempts.
    assert result1.client_isn != result2.client_isn
