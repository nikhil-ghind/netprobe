from __future__ import annotations

import pytest

from netprobe.handshake import HandshakeResult, HandshakeState, HandshakeTiming
from netprobe.latency import LatencyCollector, LatencyStats, percentile


def test_percentile_matches_known_values():
    values = [10, 20, 30, 40, 50]
    assert percentile(values, 0.0) == 10
    assert percentile(values, 1.0) == 50
    assert percentile(values, 0.5) == 30


def test_percentile_interpolates_between_ranks():
    values = [1, 2, 3, 4]
    # rank = 0.95 * 3 = 2.85 -> interpolate between index 2 (3) and 3 (4)
    assert percentile(values, 0.95) == pytest.approx(3.85)


def test_percentile_single_value():
    assert percentile([42.0], 0.95) == 42.0


def test_percentile_rejects_empty_sequence():
    with pytest.raises(ValueError):
        percentile([], 0.5)


def test_percentile_rejects_out_of_range_fraction():
    with pytest.raises(ValueError):
        percentile([1, 2, 3], 1.5)


def test_latency_stats_from_samples():
    samples = [0.010, 0.020, 0.030, 0.040, 0.050]
    stats = LatencyStats.from_samples(samples)

    assert stats.count == 5
    assert stats.minimum == pytest.approx(0.010)
    assert stats.maximum == pytest.approx(0.050)
    assert stats.mean == pytest.approx(0.030)
    assert stats.median == pytest.approx(0.030)
    assert stats.p95 > stats.median


def test_latency_stats_single_sample_has_zero_stddev():
    stats = LatencyStats.from_samples([0.1])
    assert stats.stddev == 0.0
    assert stats.minimum == stats.maximum == stats.mean == 0.1


def test_latency_stats_rejects_empty_samples():
    with pytest.raises(ValueError):
        LatencyStats.from_samples([])


def test_latency_stats_as_dict_converts_to_milliseconds():
    stats = LatencyStats.from_samples([0.1, 0.2])
    d = stats.as_dict()
    assert d["mean_ms"] == pytest.approx(150.0)
    assert d["min_ms"] == pytest.approx(100.0)
    assert d["max_ms"] == pytest.approx(200.0)


def test_latency_collector_accumulates_samples():
    collector = LatencyCollector()
    collector.add(0.1)
    collector.add(0.2)
    assert collector.samples == [0.1, 0.2]
    assert collector.stats().count == 2


def test_latency_collector_returns_none_with_no_samples():
    collector = LatencyCollector()
    assert collector.stats() is None


def test_latency_collector_add_from_result_only_when_completed():
    collector = LatencyCollector()

    incomplete = HandshakeResult(state=HandshakeState.FAILED, timing=HandshakeTiming())
    collector.add_from_result(incomplete)
    assert collector.samples == []

    complete_timing = HandshakeTiming(
        syn_sent_at=0.0, syn_ack_received_at=0.05, ack_sent_at=0.06
    )
    complete = HandshakeResult(state=HandshakeState.ESTABLISHED, timing=complete_timing)
    collector.add_from_result(complete)
    assert collector.samples == [0.06]
