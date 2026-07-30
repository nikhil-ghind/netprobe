"""Scenario runner: executes named scenarios and aggregates results.

A "scenario" is a :class:`netprobe.config.ScenarioConfig` -- a target, a
loss profile, a retransmission policy and a trial count -- run repeatedly to
produce statistically meaningful success-rate and latency numbers, the way
NetProbe's headline scenarios ("clean handshake", "handshake under 30%
loss", "retransmission stress") are meant to be used for regression
testing: run the same named scenario before and after a change and diff the
``ScenarioResult``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from netprobe.config import ScenarioConfig
from netprobe.exceptions import RetransmissionLimitExceeded
from netprobe.handshake import ScapyTransport, Transport
from netprobe.latency import LatencyCollector, LatencyStats
from netprobe.loss_simulator import LossSimulatingTransport, LossStats
from netprobe.retransmission import run_handshake_with_retries


@dataclass
class ScenarioResult:
    """Aggregated outcome of running a scenario for ``trials`` attempts."""

    name: str
    trials: int
    successes: int
    failures: int
    retransmissions_total: int
    latency: Optional[LatencyStats]
    loss_stats: LossStats
    errors: dict[str, int] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        return self.successes / self.trials if self.trials else 0.0

    @property
    def mean_retransmissions_per_trial(self) -> float:
        return self.retransmissions_total / self.trials if self.trials else 0.0

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "trials": self.trials,
            "successes": self.successes,
            "failures": self.failures,
            "success_rate": self.success_rate,
            "retransmissions_total": self.retransmissions_total,
            "mean_retransmissions_per_trial": self.mean_retransmissions_per_trial,
            "latency": self.latency.as_dict() if self.latency else None,
            "loss": {
                "uplink_drop_rate": self.loss_stats.uplink_drop_rate,
                "downlink_drop_rate": self.loss_stats.downlink_drop_rate,
                "overall_drop_rate": self.loss_stats.overall_drop_rate,
                "total_sent": self.loss_stats.total_sent,
                "total_dropped": self.loss_stats.total_dropped,
            },
            "errors": dict(self.errors),
        }


class ScenarioRunner:
    """Runs a :class:`~netprobe.config.ScenarioConfig` for its configured
    number of trials and aggregates the results.

    ``base_transport`` defaults to :class:`~netprobe.handshake.ScapyTransport`
    (real raw sockets) but tests pass an in-memory fake so a full scenario
    -- including its loss simulation and retry behavior -- can be exercised
    without root privileges or a network.

    A single :class:`~netprobe.loss_simulator.LossSimulatingTransport` is
    created per :meth:`run` call and reused across all trials, both so its
    seeded RNG produces one reproducible drop sequence for the whole
    scenario, and so ``loss_stats`` in the result reflects totals across
    every trial rather than just the last one.
    """

    def __init__(self, config: ScenarioConfig, base_transport: Optional[Transport] = None):
        self.config = config
        self.base_transport = base_transport or ScapyTransport()

    def run(self) -> ScenarioResult:
        lossy_transport = LossSimulatingTransport(self.base_transport, self.config.loss)
        latency = LatencyCollector()

        successes = 0
        failures = 0
        retransmissions_total = 0
        errors: dict[str, int] = {}

        for _ in range(self.config.trials):
            try:
                outcome = run_handshake_with_retries(
                    self.config.network,
                    self.config.retransmission,
                    lossy_transport,
                )
            except RetransmissionLimitExceeded as exc:
                failures += 1
                errors[type(exc).__name__] = errors.get(type(exc).__name__, 0) + 1
                continue

            successes += 1
            retransmissions_total += outcome.retransmissions
            latency.add_from_result(outcome.result)

        return ScenarioResult(
            name=self.config.name,
            trials=self.config.trials,
            successes=successes,
            failures=failures,
            retransmissions_total=retransmissions_total,
            latency=latency.stats(),
            loss_stats=lossy_transport.stats,
            errors=errors,
        )


def default_scenarios(target_host: str, target_port: int = 443) -> list[ScenarioConfig]:
    """Build NetProbe's headline set of scenarios against a target, for use
    by the CLI's default ``netprobe run`` invocation and as example
    configurations in documentation.

    * ``clean-handshake``: no simulated loss, a baseline for comparison.
    * ``handshake-10pct-loss`` / ``handshake-30pct-loss``: NetProbe's
      namesake stress scenarios, symmetric loss at 10% and 30%.
    * ``retransmission-stress``: 30% loss with a tighter retry budget, to
      surface how quickly retransmissions exhaust the retry policy.
    """
    from netprobe.config import LossConfig, NetworkConfig, RetransmissionPolicy

    network = NetworkConfig(target_host=target_host, target_port=target_port)

    return [
        ScenarioConfig(
            name="clean-handshake",
            network=network,
            loss=LossConfig(loss_rate=0.0),
            trials=20,
        ),
        ScenarioConfig(
            name="handshake-10pct-loss",
            network=network,
            loss=LossConfig(loss_rate=0.10, seed=10),
            trials=20,
        ),
        ScenarioConfig(
            name="handshake-30pct-loss",
            network=network,
            loss=LossConfig(loss_rate=0.30, seed=30),
            trials=20,
        ),
        ScenarioConfig(
            name="retransmission-stress",
            network=network,
            loss=LossConfig(loss_rate=0.30, seed=99),
            retransmission=RetransmissionPolicy(max_retries=2, base_backoff=0.05),
            trials=20,
        ),
    ]
