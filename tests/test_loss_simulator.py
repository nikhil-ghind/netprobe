from __future__ import annotations

import pytest

from netprobe.config import LossConfig
from netprobe.loss_simulator import LossSimulatingTransport
from tests.fakes import FakeTransport

TRIALS = 2000


def test_zero_loss_never_drops(network_config):
    transport = LossSimulatingTransport(FakeTransport(server_isn=1), LossConfig(loss_rate=0.0))
    for _ in range(50):
        pkt, _ = _syn(network_config)
        assert transport.sr1(pkt, timeout=0.1) is not None
    assert transport.stats.overall_drop_rate == 0.0


def test_full_loss_always_drops(network_config):
    transport = LossSimulatingTransport(FakeTransport(server_isn=1), LossConfig(loss_rate=1.0))
    for _ in range(50):
        pkt, _ = _syn(network_config)
        assert transport.sr1(pkt, timeout=0.1) is None
    assert transport.stats.overall_drop_rate == 1.0


def test_configured_loss_rate_is_approximated_over_many_trials(network_config):
    config = LossConfig(loss_rate=0.30, seed=42)
    transport = LossSimulatingTransport(FakeTransport(server_isn=1), config)

    for _ in range(TRIALS):
        pkt, _ = _syn(network_config)
        transport.sr1(pkt, timeout=0.1)

    # With 2000 trials, the observed rate should land close to 0.30; allow
    # a generous tolerance so the test isn't flaky while still catching a
    # broken drop probability (e.g. always/never dropping, or an inverted
    # comparison).
    assert transport.stats.overall_drop_rate == pytest.approx(0.30, abs=0.05)


def test_same_seed_produces_same_drop_sequence(network_config):
    config = LossConfig(loss_rate=0.30, seed=7)
    t1 = LossSimulatingTransport(FakeTransport(server_isn=1), config)
    t2 = LossSimulatingTransport(FakeTransport(server_isn=1), config)

    results1 = []
    results2 = []
    for _ in range(100):
        pkt1, _ = _syn(network_config)
        pkt2, _ = _syn(network_config)
        results1.append(t1.sr1(pkt1, timeout=0.1) is None)
        results2.append(t2.sr1(pkt2, timeout=0.1) is None)

    assert results1 == results2


def test_asymmetric_loss_rates_are_independent(network_config):
    config = LossConfig(uplink_loss_rate=1.0, downlink_loss_rate=0.0, seed=1)
    transport = LossSimulatingTransport(FakeTransport(server_isn=1), config)

    pkt, _ = _syn(network_config)
    response = transport.sr1(pkt, timeout=0.1)

    # Uplink always drops, so the request never even reaches the peer;
    # downlink loss rate is irrelevant here.
    assert response is None
    assert transport.stats.uplink_dropped == 1
    assert transport.stats.downlink_sent == 0


def test_send_only_applies_uplink_loss(network_config):
    config = LossConfig(loss_rate=1.0)
    inner = FakeTransport(server_isn=1)
    transport = LossSimulatingTransport(inner, config)

    pkt, _ = _syn(network_config)
    transport.send(pkt)

    assert inner.sent_packets == []  # dropped before reaching inner transport
    assert transport.stats.uplink_dropped == 1
    assert transport.stats.downlink_sent == 0


def test_loss_config_effective_rates_fall_back_to_loss_rate():
    config = LossConfig(loss_rate=0.4)
    assert config.effective_uplink_loss_rate == 0.4
    assert config.effective_downlink_loss_rate == 0.4

    overridden = LossConfig(loss_rate=0.4, uplink_loss_rate=0.1, downlink_loss_rate=0.9)
    assert overridden.effective_uplink_loss_rate == 0.1
    assert overridden.effective_downlink_loss_rate == 0.9


def _syn(network_config):
    from netprobe.packet_builder import build_syn

    return build_syn(network_config)
