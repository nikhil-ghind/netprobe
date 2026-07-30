from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP

from netprobe.exceptions import SequenceMismatch, UnexpectedFlags
from netprobe.packet_builder import (
    HandshakeExpectation,
    MAX_SEQ,
    build_ack,
    build_data,
    build_rst,
    build_syn,
    build_syn_ack,
    extract_flags,
    is_retransmission_candidate,
    seq_add,
    validate_response,
)


def test_seq_add_wraps_at_32_bits():
    assert seq_add(MAX_SEQ, 1) == 0
    assert seq_add(MAX_SEQ - 1, 2) == 0
    assert seq_add(0, 1) == 1


def test_build_syn_sets_flags_and_expectation(network_config):
    pkt, expectation = build_syn(network_config, seq=1000)

    assert pkt[TCP].flags == "S"
    assert pkt[TCP].seq == 1000
    assert pkt[TCP].ack == 0
    assert pkt[IP].dst == network_config.target_host
    assert pkt[TCP].dport == network_config.target_port

    assert expectation.stage == "syn_ack"
    assert expectation.expected_flags == "SA"
    assert expectation.expected_ack == 1001


def test_build_syn_random_isn_in_range(network_config):
    pkt, _ = build_syn(network_config)
    assert 0 <= pkt[TCP].seq <= MAX_SEQ


def test_build_syn_ack_expectation_matches_third_leg(network_config):
    pkt, expectation = build_syn_ack(network_config, client_isn=1000, server_isn=5000)

    assert pkt[TCP].flags == "SA"
    assert pkt[TCP].seq == 5000
    assert pkt[TCP].ack == 1001

    assert expectation.stage == "ack"
    assert expectation.expected_flags == "A"
    assert expectation.expected_ack == 5001
    assert expectation.expected_seq == 1001


def test_build_ack_final_leg_fields(network_config):
    pkt = build_ack(network_config, client_isn=1000, server_isn=5000, source_port=44000)

    assert pkt[TCP].flags == "A"
    assert pkt[TCP].seq == 1001
    assert pkt[TCP].ack == 5001
    assert pkt[TCP].sport == 44000


def test_build_rst_uses_rst_ack_when_ack_given(network_config):
    bare = build_rst(network_config, seq=1, source_port=1234)
    acked = build_rst(network_config, seq=1, source_port=1234, ack=42)

    assert bare[TCP].flags == "R"
    assert acked[TCP].flags == "RA"
    assert acked[TCP].ack == 42


def test_build_data_includes_payload(network_config):
    pkt = build_data(
        network_config, seq=1, ack=1, source_port=1234, payload=b"hello"
    )
    assert pkt[TCP].flags == "PA"
    assert bytes(pkt[TCP].payload) == b"hello"


def test_build_data_without_payload_has_no_raw_layer(network_config):
    pkt = build_data(network_config, seq=1, ack=1, source_port=1234)
    assert not bytes(pkt[TCP].payload)


def test_extract_flags_raises_without_tcp_layer():
    with pytest.raises(UnexpectedFlags):
        extract_flags(IP(dst="192.0.2.1"))


def test_validate_response_success(network_config):
    _, expectation = build_syn(network_config, seq=1000)
    response = IP(dst="10.0.0.1") / TCP(flags="SA", seq=5000, ack=1001)
    validate_response(response, expectation)  # should not raise


def test_validate_response_wrong_flags_raises(network_config):
    _, expectation = build_syn(network_config, seq=1000)
    response = IP(dst="10.0.0.1") / TCP(flags="R", seq=0, ack=0)
    with pytest.raises(UnexpectedFlags):
        validate_response(response, expectation)


def test_validate_response_wrong_ack_raises(network_config):
    _, expectation = build_syn(network_config, seq=1000)
    response = IP(dst="10.0.0.1") / TCP(flags="SA", seq=5000, ack=9999)
    with pytest.raises(SequenceMismatch):
        validate_response(response, expectation)


def test_validate_response_checks_expected_seq_when_present():
    expectation = HandshakeExpectation(
        stage="ack", expected_flags="A", expected_ack=5001, expected_seq=1001
    )
    good = IP(dst="10.0.0.1") / TCP(flags="A", seq=1001, ack=5001)
    validate_response(good, expectation)

    bad = IP(dst="10.0.0.1") / TCP(flags="A", seq=9999, ack=5001)
    with pytest.raises(SequenceMismatch) as exc_info:
        validate_response(bad, expectation)
    assert exc_info.value.field == "seq"


def test_is_retransmission_candidate_true_for_identical_segment(network_config):
    pkt1, _ = build_syn(network_config, seq=1000, source_port=44000)
    pkt2, _ = build_syn(network_config, seq=1000, source_port=44000)
    assert is_retransmission_candidate(pkt1, pkt2)


def test_is_retransmission_candidate_false_for_different_seq(network_config):
    pkt1, _ = build_syn(network_config, seq=1000, source_port=44000)
    pkt2, _ = build_syn(network_config, seq=2000, source_port=44000)
    assert not is_retransmission_candidate(pkt1, pkt2)


def test_is_retransmission_candidate_false_without_tcp_layer():
    assert not is_retransmission_candidate(IP(dst="1.2.3.4"), IP(dst="1.2.3.4"))
