"""Typed exceptions raised across NetProbe's handshake and transport layers."""


class NetProbeError(Exception):
    """Base class for all NetProbe-specific errors."""


class HandshakeError(NetProbeError):
    """Base class for errors that occur while driving a TCP handshake."""


class HandshakeTimeout(HandshakeError):
    """Raised when no response is received within the configured timeout.

    This can legitimately happen even against a healthy peer when the
    :class:`~netprobe.loss_simulator.LossSimulator` drops a packet, so callers
    that expect loss should catch this and hand it to the retransmission
    policy rather than treating it as a hard failure.
    """

    def __init__(self, stage: str, timeout: float):
        self.stage = stage
        self.timeout = timeout
        super().__init__(
            f"timed out waiting for a response during '{stage}' after {timeout:.3f}s"
        )


class UnexpectedFlags(HandshakeError):
    """Raised when a received segment's TCP flags don't match what the state
    machine expected for the current stage (e.g. an RST instead of SYN-ACK)."""

    def __init__(self, stage: str, expected: str, actual: str):
        self.stage = stage
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"unexpected TCP flags during '{stage}': expected {expected!r}, "
            f"got {actual!r}"
        )


class SequenceMismatch(HandshakeError):
    """Raised when a received segment's sequence/ack numbers don't line up
    with what the handshake state machine computed as expected."""

    def __init__(self, stage: str, expected: int, actual: int, field: str = "ack"):
        self.stage = stage
        self.expected = expected
        self.actual = actual
        self.field = field
        super().__init__(
            f"sequence mismatch during '{stage}': expected {field}={expected}, "
            f"got {field}={actual}"
        )


class ChecksumError(NetProbeError):
    """Raised when a constructed or observed packet fails checksum validation."""


class RetransmissionLimitExceeded(NetProbeError):
    """Raised when a segment has been retransmitted more times than the
    configured retry budget allows, and the session gives up."""

    def __init__(self, seq: int, attempts: int, limit: int):
        self.seq = seq
        self.attempts = attempts
        self.limit = limit
        super().__init__(
            f"segment seq={seq} exceeded retransmission limit "
            f"({attempts} attempts > {limit} allowed)"
        )


class InvalidScenarioConfig(NetProbeError):
    """Raised when a scenario or network configuration is invalid, e.g. a
    loss rate outside [0, 1] or a negative timeout."""
