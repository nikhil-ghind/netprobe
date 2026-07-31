from __future__ import annotations

import pytest

from netprobe.config import RetransmissionPolicy
from netprobe.exceptions import RetransmissionLimitExceeded
from netprobe.packet_builder import build_syn
from netprobe.retransmission import RetransmissionTracker, run_handshake_with_retries
from tests.fakes import FakeTransport, FlakyTransport


# --- RetransmissionPolicy backoff math -------------------------------------


def test_backoff_grows_exponentially():
    policy = RetransmissionPolicy(base_backoff=0.1, backoff_multiplier=2.0, max_backoff=10.0)
    assert policy.backoff_for_attempt(1) == pytest.approx(0.1)
    assert policy.backoff_for_attempt(2) == pytest.approx(0.2)
    assert policy.backoff_for_attempt(3) == pytest.approx(0.4)


def test_backoff_is_capped_at_max_backoff():
    policy = RetransmissionPolicy(base_backoff=1.0, backoff_multiplier=10.0, max_backoff=5.0)
    assert policy.backoff_for_attempt(5) == 5.0


def test_backoff_rejects_attempt_below_one():
    policy = RetransmissionPolicy()
    with pytest.raises(ValueError):
        policy.backoff_for_attempt(0)


# --- RetransmissionTracker structural duplicate detection -------------------


def test_tracker_flags_identical_segment_within_window(network_config):
    tracker = RetransmissionTracker(window=5.0)
    pkt, _ = build_syn(network_config, seq=1000, source_port=44000)

    assert tracker.record(pkt, now=0.0) is False
    assert tracker.record(pkt, now=1.0) is True
    assert tracker.retransmission_count == 1


def test_tracker_ignores_segment_outside_window(network_config):
    tracker = RetransmissionTracker(window=2.0)
    pkt, _ = build_syn(network_config, seq=1000, source_port=44000)

    assert tracker.record(pkt, now=0.0) is False
    assert tracker.record(pkt, now=10.0) is False
    assert tracker.retransmission_count == 0


def test_tracker_does_not_flag_distinct_segments(network_config):
    tracker = RetransmissionTracker(window=5.0)
    pkt1, _ = build_syn(network_config, seq=1000, source_port=44000)
    pkt2, _ = build_syn(network_config, seq=2000, source_port=44000)

    assert tracker.record(pkt1, now=0.0) is False
    assert tracker.record(pkt2, now=0.1) is False
    assert tracker.retransmission_count == 0


def test_tracker_reset_clears_state(network_config):
    tracker = RetransmissionTracker(window=5.0)
    pkt, _ = build_syn(network_config, seq=1000, source_port=44000)
    tracker.record(pkt, now=0.0)
    tracker.record(pkt, now=0.1)
    assert tracker.retransmission_count == 1

    tracker.reset()
    assert tracker.retransmission_count == 0
    assert tracker.record(pkt, now=0.2) is False


# --- run_handshake_with_retries ---------------------------------------------


def test_retry_succeeds_on_first_attempt(network_config, retransmission_policy):
    transport = FakeTransport(server_isn=5000)
    sleeps = []

    outcome = run_handshake_with_retries(
        network_config, retransmission_policy, transport, sleep_fn=sleeps.append
    )

    assert outcome.result.succeeded
    assert outcome.attempts == 1
    assert outcome.retransmissions == 0
    assert sleeps == []


def test_retry_succeeds_after_two_failures(network_config, retransmission_policy):
    peer = FakeTransport(server_isn=5000)
    transport = FlakyTransport(peer, fail_count=2)
    sleeps = []

    outcome = run_handshake_with_retries(
        network_config, retransmission_policy, transport, sleep_fn=sleeps.append
    )

    assert outcome.result.succeeded
    assert outcome.attempts == 3
    assert outcome.retransmissions == 2
    # One backoff sleep between attempt 1->2 and one between 2->3.
    assert sleeps == [
        retransmission_policy.backoff_for_attempt(1),
        retransmission_policy.backoff_for_attempt(2),
    ]


def test_retry_gives_up_after_exhausting_budget(network_config, retransmission_policy):
    transport = FakeTransport(respond=False)
    sleeps = []

    with pytest.raises(RetransmissionLimitExceeded) as exc_info:
        run_handshake_with_retries(
            network_config, retransmission_policy, transport, sleep_fn=sleeps.append
        )

    assert exc_info.value.attempts == retransmission_policy.max_retries + 1
    assert exc_info.value.limit == retransmission_policy.max_retries
    # 1 + max_retries attempts means max_retries backoff sleeps between them.
    assert len(sleeps) == retransmission_policy.max_retries
