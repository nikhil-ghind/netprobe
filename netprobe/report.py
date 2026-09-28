"""Rendering of scenario results as human-readable and JSON reports.

Two output shapes:
    * A Rich table for terminal output (``render_table``), meant to be
      glanced at right after a ``netprobe run``.
    * Plain JSON (``result_to_json`` / ``results_to_json``), meant to be
      archived by CI and diffed across runs -- the actual "regression
      testing" artifact this project produces.
"""

from __future__ import annotations

import json
from typing import Iterable

from rich.console import Console
from rich.table import Table

from netprobe.scenarios import ScenarioResult


def render_table(results: Iterable[ScenarioResult]) -> Table:
    """Build a Rich table summarizing one or more scenario results."""
    table = Table(title="NetProbe scenario results")
    table.add_column("Scenario", style="bold")
    table.add_column("Trials", justify="right")
    table.add_column("Success rate", justify="right")
    table.add_column("Retransmits/trial", justify="right")
    table.add_column("Mean RTT (ms)", justify="right")
    table.add_column("p95 RTT (ms)", justify="right")
    table.add_column("Drop rate", justify="right")

    for result in results:
        latency = result.latency
        mean_ms = f"{latency.mean * 1000:.1f}" if latency else "-"
        p95_ms = f"{latency.p95 * 1000:.1f}" if latency else "-"
        table.add_row(
            result.name,
            str(result.trials),
            f"{result.success_rate:.0%}",
            f"{result.mean_retransmissions_per_trial:.2f}",
            mean_ms,
            p95_ms,
            f"{result.loss_stats.overall_drop_rate:.1%}",
        )

    return table


def print_report(results: Iterable[ScenarioResult], console: Console | None = None) -> None:
    """Print a Rich table of ``results`` to ``console`` (or a fresh one)."""
    console = console or Console()
    console.print(render_table(results))


def result_to_json(result: ScenarioResult) -> str:
    """Serialize a single :class:`~netprobe.scenarios.ScenarioResult` to a
    pretty-printed JSON string suitable for saving to disk."""
    return json.dumps(result.as_dict(), indent=2, sort_keys=True)


def results_to_json(results: Iterable[ScenarioResult]) -> str:
    """Serialize a batch of scenario results to a JSON array, the format
    written by ``netprobe run --format json`` and read back by
    ``netprobe report``."""
    return json.dumps([r.as_dict() for r in results], indent=2, sort_keys=True)


def load_results_json(raw: str) -> list[dict]:
    """Parse a JSON report previously written by :func:`results_to_json` (or
    a single object written by :func:`result_to_json`) back into a list of
    plain dicts for re-rendering."""
    data = json.loads(raw)
    if isinstance(data, dict):
        return [data]
    return data


def render_table_from_dicts(rows: Iterable[dict]) -> Table:
    """Render a Rich table directly from parsed JSON dicts (as produced by
    :func:`load_results_json`), for ``netprobe report`` where we no longer
    have live ``ScenarioResult``/``LatencyStats`` objects, just their
    serialized form."""
    table = Table(title="NetProbe scenario results (from report)")
    table.add_column("Scenario", style="bold")
    table.add_column("Trials", justify="right")
    table.add_column("Success rate", justify="right")
    table.add_column("Retransmits/trial", justify="right")
    table.add_column("Mean RTT (ms)", justify="right")
    table.add_column("p95 RTT (ms)", justify="right")
    table.add_column("Drop rate", justify="right")

    for row in rows:
        latency = row.get("latency")
        mean_ms = f"{latency['mean_ms']:.1f}" if latency else "-"
        p95_ms = f"{latency['p95_ms']:.1f}" if latency else "-"
        table.add_row(
            row["name"],
            str(row["trials"]),
            f"{row['success_rate']:.0%}",
            f"{row['mean_retransmissions_per_trial']:.2f}",
            mean_ms,
            p95_ms,
            f"{row['loss']['overall_drop_rate']:.1%}",
        )

    return table
