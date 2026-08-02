from __future__ import annotations

import json

from click.testing import CliRunner

from netprobe.cli import cli


def test_cli_run_help_lists_options():
    result = CliRunner().invoke(cli, ["run", "--help"])
    assert result.exit_code == 0
    assert "--target" in result.output
    assert "--scenario" in result.output


def test_cli_run_rejects_unknown_scenario():
    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["run", "--target", "192.0.2.10", "--scenario", "does-not-exist", "--trials", "1"],
    )
    assert result.exit_code != 0
    assert "unknown scenario" in result.output.lower()


def test_cli_report_reads_json_file(tmp_path):
    payload = [
        {
            "name": "clean-handshake",
            "trials": 10,
            "successes": 10,
            "failures": 0,
            "success_rate": 1.0,
            "retransmissions_total": 0,
            "mean_retransmissions_per_trial": 0.0,
            "latency": {
                "count": 10,
                "min_ms": 1.0,
                "max_ms": 5.0,
                "mean_ms": 3.0,
                "median_ms": 3.0,
                "stddev_ms": 1.0,
                "p95_ms": 4.5,
            },
            "loss": {
                "uplink_drop_rate": 0.0,
                "downlink_drop_rate": 0.0,
                "overall_drop_rate": 0.0,
                "total_sent": 10,
                "total_dropped": 0,
            },
            "errors": {},
        }
    ]
    report_path = tmp_path / "results.json"
    report_path.write_text(json.dumps(payload))

    result = CliRunner().invoke(cli, ["report", str(report_path)])

    assert result.exit_code == 0
    assert "clean-handshake" in result.output
