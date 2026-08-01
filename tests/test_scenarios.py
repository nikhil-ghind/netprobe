from __future__ import annotations

from netprobe.config import LossConfig, RetransmissionPolicy, ScenarioConfig
from netprobe.scenarios import ScenarioRunner, default_scenarios
from tests.fakes import FakeTransport


def test_clean_scenario_always_succeeds(scenario_config, network_config):
    config = ScenarioConfig(
        name="clean",
        network=network_config,
        loss=LossConfig(loss_rate=0.0),
        retransmission=RetransmissionPolicy(max_retries=1, base_backoff=0.001),
        trials=10,
    )
    runner = ScenarioRunner(config, base_transport=FakeTransport(server_isn=1))

    result = runner.run()

    assert result.trials == 10
    assert result.successes == 10
    assert result.failures == 0
    assert result.success_rate == 1.0
    assert result.latency is not None
    assert result.latency.count == 10
    assert result.loss_stats.overall_drop_rate == 0.0


def test_always_lossy_scenario_always_fails(network_config):
    config = ScenarioConfig(
        name="always-lossy",
        network=network_config,
        loss=LossConfig(loss_rate=1.0),
        retransmission=RetransmissionPolicy(max_retries=1, base_backoff=0.001),
        trials=5,
    )
    runner = ScenarioRunner(config, base_transport=FakeTransport(server_isn=1))

    result = runner.run()

    assert result.successes == 0
    assert result.failures == 5
    assert result.success_rate == 0.0
    assert result.latency is None
    assert "RetransmissionLimitExceeded" in result.errors
    assert result.errors["RetransmissionLimitExceeded"] == 5


def test_partial_loss_scenario_mixes_successes_and_failures(network_config):
    config = ScenarioConfig(
        name="partial-loss",
        network=network_config,
        loss=LossConfig(loss_rate=0.30, seed=123),
        retransmission=RetransmissionPolicy(max_retries=1, base_backoff=0.001),
        trials=200,
    )
    runner = ScenarioRunner(config, base_transport=FakeTransport(server_isn=1))

    result = runner.run()

    assert result.successes + result.failures == 200
    # Not a hard probability bound, just a sanity check that a 30% symmetric
    # loss with only one retry does not make every trial succeed or fail.
    assert 0 < result.successes < 200
    assert result.loss_stats.total_sent > 0


def test_scenario_result_as_dict_is_json_serializable(network_config):
    import json

    config = ScenarioConfig(
        name="clean",
        network=network_config,
        loss=LossConfig(loss_rate=0.0),
        trials=3,
    )
    runner = ScenarioRunner(config, base_transport=FakeTransport(server_isn=1))
    result = runner.run()

    json.dumps(result.as_dict())  # should not raise


def test_default_scenarios_builds_headline_set():
    scenarios = default_scenarios("192.0.2.10")
    names = [s.name for s in scenarios]

    assert names == [
        "clean-handshake",
        "handshake-10pct-loss",
        "handshake-30pct-loss",
        "retransmission-stress",
    ]
    loss_by_name = {s.name: s.loss.loss_rate for s in scenarios}
    assert loss_by_name["clean-handshake"] == 0.0
    assert loss_by_name["handshake-30pct-loss"] == 0.30
    assert loss_by_name["retransmission-stress"] == 0.30
    for scenario in scenarios:
        assert scenario.network.target_host == "192.0.2.10"
