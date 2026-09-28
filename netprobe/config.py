"""Configuration dataclasses for NetProbe scenarios and network parameters.

These are plain, validated dataclasses so they can be constructed directly in
tests, built from CLI arguments, or (de)serialized to/from JSON for
reproducible scenario definitions.
"""

from __future__ import annotations

import dataclasses

from netprobe.exceptions import InvalidScenarioConfig


@dataclasses.dataclass(frozen=True)
class NetworkConfig:
    """Parameters describing the target and transport for a handshake attempt.

    Attributes:
        target_host: Destination IP address or hostname.
        target_port: Destination TCP port.
        interface: Network interface to send/sniff on (``None`` lets Scapy
            pick the interface via routing).
        source_port: Source TCP port to use; ``0`` means "choose randomly per
            session" (done by the caller, not Scapy).
        timeout: Seconds to wait for a response before declaring a timeout.
        window_size: TCP window size advertised in outgoing segments.
    """

    target_host: str
    target_port: int
    interface: str | None = None
    source_port: int = 0
    timeout: float = 2.0
    window_size: int = 65535

    def __post_init__(self) -> None:
        if not self.target_host:
            raise InvalidScenarioConfig("target_host must be a non-empty string")
        if not (0 < self.target_port <= 65535):
            raise InvalidScenarioConfig(
                f"target_port must be in (0, 65535], got {self.target_port}"
            )
        if self.source_port and not (0 < self.source_port <= 65535):
            raise InvalidScenarioConfig(
                f"source_port must be 0 or in (0, 65535], got {self.source_port}"
            )
        if self.timeout <= 0:
            raise InvalidScenarioConfig(f"timeout must be positive, got {self.timeout}")
        if not (0 < self.window_size <= 65535):
            raise InvalidScenarioConfig(
                f"window_size must be in (0, 65535], got {self.window_size}"
            )


@dataclasses.dataclass(frozen=True)
class RetransmissionPolicy:
    """Controls retry/backoff behavior when segments appear to be lost.

    Attributes:
        max_retries: Maximum number of retransmission attempts per segment
            before giving up and raising ``RetransmissionLimitExceeded``.
        base_backoff: Initial backoff delay (seconds) before the first retry.
        backoff_multiplier: Multiplier applied to the backoff delay after
            each retry (exponential backoff).
        max_backoff: Upper bound on the backoff delay regardless of how many
            retries have occurred.
    """

    max_retries: int = 5
    base_backoff: float = 0.1
    backoff_multiplier: float = 2.0
    max_backoff: float = 5.0

    def __post_init__(self) -> None:
        if self.max_retries < 0:
            raise InvalidScenarioConfig(
                f"max_retries must be >= 0, got {self.max_retries}"
            )
        if self.base_backoff <= 0:
            raise InvalidScenarioConfig(
                f"base_backoff must be positive, got {self.base_backoff}"
            )
        if self.backoff_multiplier < 1:
            raise InvalidScenarioConfig(
                f"backoff_multiplier must be >= 1, got {self.backoff_multiplier}"
            )
        if self.max_backoff < self.base_backoff:
            raise InvalidScenarioConfig(
                "max_backoff must be >= base_backoff "
                f"({self.max_backoff} < {self.base_backoff})"
            )

    def backoff_for_attempt(self, attempt: int) -> float:
        """Return the backoff delay (seconds) before retry number ``attempt``
        (1-indexed: the delay before the *first* retry is ``attempt=1``)."""
        if attempt < 1:
            raise ValueError("attempt must be >= 1")
        delay = self.base_backoff * (self.backoff_multiplier ** (attempt - 1))
        return min(delay, self.max_backoff)


@dataclasses.dataclass(frozen=True)
class LossConfig:
    """Parameters for the packet-loss / jitter simulation layer.

    Attributes:
        loss_rate: Probability in [0, 1] that any given packet is dropped.
            NetProbe's default stress scenarios exercise up to 0.30 (30%).
        uplink_loss_rate: Optional override for client->server loss; falls
            back to ``loss_rate`` when ``None``.
        downlink_loss_rate: Optional override for server->client loss; falls
            back to ``loss_rate`` when ``None``.
        jitter: Maximum extra random delay (seconds) added to a packet that
            is *not* dropped, to simulate variable latency. ``0`` disables it.
        seed: RNG seed. A fixed seed makes loss simulation reproducible
            across runs, which matters for regression testing.
    """

    loss_rate: float = 0.0
    uplink_loss_rate: float | None = None
    downlink_loss_rate: float | None = None
    jitter: float = 0.0
    seed: int | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("loss_rate", self.loss_rate),
            ("uplink_loss_rate", self.uplink_loss_rate),
            ("downlink_loss_rate", self.downlink_loss_rate),
        ):
            if value is not None and not (0.0 <= value <= 1.0):
                raise InvalidScenarioConfig(f"{name} must be in [0, 1], got {value}")
        if self.jitter < 0:
            raise InvalidScenarioConfig(f"jitter must be >= 0, got {self.jitter}")

    @property
    def effective_uplink_loss_rate(self) -> float:
        return self.loss_rate if self.uplink_loss_rate is None else self.uplink_loss_rate

    @property
    def effective_downlink_loss_rate(self) -> float:
        return (
            self.loss_rate
            if self.downlink_loss_rate is None
            else self.downlink_loss_rate
        )


@dataclasses.dataclass(frozen=True)
class ScenarioConfig:
    """Top-level configuration for a single named scenario run.

    Combines network, retransmission and loss configuration with how many
    trials to execute, so a `ScenarioRunner` has everything it needs from one
    object (and this object round-trips cleanly to/from JSON for the CLI).
    """

    name: str
    network: NetworkConfig
    loss: LossConfig = dataclasses.field(default_factory=LossConfig)
    retransmission: RetransmissionPolicy = dataclasses.field(
        default_factory=RetransmissionPolicy
    )
    trials: int = 10

    def __post_init__(self) -> None:
        if not self.name:
            raise InvalidScenarioConfig("scenario name must be non-empty")
        if self.trials <= 0:
            raise InvalidScenarioConfig(f"trials must be positive, got {self.trials}")
