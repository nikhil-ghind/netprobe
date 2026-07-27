"""Shared pytest fixtures for the NetProbe test suite.

Most tests in this suite exercise packet construction, state-machine logic,
retransmission/backoff math, latency statistics and loss simulation
*without* opening real raw sockets, so they run without root privileges and
without a network. Tests that do need real raw sockets (CAP_NET_RAW) are
marked ``@pytest.mark.root_required`` and are excluded by the default pytest
``addopts`` in ``pyproject.toml``; run them explicitly with
``pytest -m root_required`` on a host/container with the right privileges.
"""

from __future__ import annotations

import random

import pytest

from netprobe.config import LossConfig, NetworkConfig, RetransmissionPolicy, ScenarioConfig


@pytest.fixture
def network_config() -> NetworkConfig:
    """A representative, valid NetworkConfig for use in unit tests."""
    return NetworkConfig(
        target_host="192.0.2.1",
        target_port=443,
        interface=None,
        source_port=0,
        timeout=0.5,
        window_size=65535,
    )


@pytest.fixture
def retransmission_policy() -> RetransmissionPolicy:
    """A fast-retrying policy suitable for unit tests (small backoffs)."""
    return RetransmissionPolicy(
        max_retries=3,
        base_backoff=0.01,
        backoff_multiplier=2.0,
        max_backoff=0.1,
    )


@pytest.fixture
def loss_config() -> LossConfig:
    """A deterministic, seeded loss configuration at NetProbe's headline
    30% loss-rate scenario."""
    return LossConfig(loss_rate=0.30, jitter=0.0, seed=1234)


@pytest.fixture
def scenario_config(network_config, loss_config, retransmission_policy) -> ScenarioConfig:
    return ScenarioConfig(
        name="test-scenario",
        network=network_config,
        loss=loss_config,
        retransmission=retransmission_policy,
        trials=5,
    )


@pytest.fixture
def seeded_rng() -> random.Random:
    """A seeded RNG for tests that need reproducible randomness without
    depending on the global ``random`` module state."""
    return random.Random(2026)
