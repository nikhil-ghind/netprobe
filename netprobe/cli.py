"""Command-line entry point for NetProbe.

    netprobe run --target 192.0.2.10 --port 443
    netprobe run --target 192.0.2.10 --port 443 --scenario handshake-30pct-loss
    netprobe run --target 192.0.2.10 --port 443 --loss 0.3 --trials 50 --format json --output results.json
    netprobe report results.json

Sending raw SYN/ACK segments requires ``CAP_NET_RAW`` (or root); see the
README for how to run this under Docker with the right capabilities.
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from netprobe.config import LossConfig, NetworkConfig, RetransmissionPolicy, ScenarioConfig
from netprobe.report import (
    load_results_json,
    render_table_from_dicts,
    results_to_json,
)
from netprobe.scenarios import ScenarioRunner, default_scenarios

console = Console()


@click.group()
@click.version_option(package_name="netprobe")
def cli() -> None:
    """NetProbe -- TCP/IP handshake, retransmission and latency validation
    under simulated packet loss."""


@cli.command()
@click.option("--target", "target_host", required=True, help="Target host/IP to probe.")
@click.option("--port", "target_port", default=443, show_default=True, help="Target TCP port.")
@click.option("--interface", default=None, help="Network interface to send/sniff on.")
@click.option(
    "--scenario",
    "scenario_names",
    multiple=True,
    help="Run only the named headline scenario(s); repeatable. "
    "Default: run all of NetProbe's headline scenarios.",
)
@click.option("--loss", "loss_rate", type=float, default=None, help="Override loss rate (0-1) for all selected scenarios.")
@click.option("--trials", type=int, default=None, help="Override trial count for all selected scenarios.")
@click.option("--timeout", type=float, default=2.0, show_default=True, help="Per-attempt response timeout, seconds.")
@click.option("--max-retries", type=int, default=None, help="Override max retransmission retries.")
@click.option("--seed", type=int, default=None, help="Override RNG seed for loss simulation (reproducibility).")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    show_default=True,
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the report to this file instead of stdout (JSON format only).",
)
def run(
    target_host: str,
    target_port: int,
    interface: str | None,
    scenario_names: tuple[str, ...],
    loss_rate: float | None,
    trials: int | None,
    timeout: float,
    max_retries: int | None,
    seed: int | None,
    output_format: str,
    output_path: Path | None,
) -> None:
    """Run one or more scenarios against TARGET and report the results."""
    scenarios = default_scenarios(target_host, target_port)

    if scenario_names:
        selected = {name for name in scenario_names}
        scenarios = [s for s in scenarios if s.name in selected]
        missing = selected - {s.name for s in scenarios}
        if missing:
            raise click.BadParameter(
                f"unknown scenario(s): {', '.join(sorted(missing))}", param_hint="--scenario"
            )

    scenarios = [_apply_overrides(s, interface, loss_rate, trials, timeout, max_retries, seed) for s in scenarios]

    results = []
    for scenario in scenarios:
        console.print(f"[bold]Running[/bold] {scenario.name} ({scenario.trials} trials)...")
        results.append(ScenarioRunner(scenario).run())

    if output_format == "json":
        payload = results_to_json(results)
        if output_path:
            output_path.write_text(payload)
            console.print(f"Wrote JSON report to {output_path}")
        else:
            click.echo(payload)
    else:
        from netprobe.report import print_report

        print_report(results, console=console)
        if output_path:
            output_path.write_text(results_to_json(results))
            console.print(f"Wrote JSON report to {output_path}")

    if any(r.failures == r.trials for r in results):
        sys.exit(1)


@cli.command()
@click.argument("report_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def report(report_path: Path) -> None:
    """Re-render a previously saved JSON report (see `netprobe run --format json`)."""
    rows = load_results_json(report_path.read_text())
    console.print(render_table_from_dicts(rows))


def _apply_overrides(
    scenario: ScenarioConfig,
    interface: str | None,
    loss_rate: float | None,
    trials: int | None,
    timeout: float,
    max_retries: int | None,
    seed: int | None,
) -> ScenarioConfig:
    network = NetworkConfig(
        target_host=scenario.network.target_host,
        target_port=scenario.network.target_port,
        interface=interface,
        source_port=scenario.network.source_port,
        timeout=timeout,
        window_size=scenario.network.window_size,
    )
    loss = LossConfig(
        loss_rate=scenario.loss.loss_rate if loss_rate is None else loss_rate,
        uplink_loss_rate=scenario.loss.uplink_loss_rate,
        downlink_loss_rate=scenario.loss.downlink_loss_rate,
        jitter=scenario.loss.jitter,
        seed=scenario.loss.seed if seed is None else seed,
    )
    retransmission = RetransmissionPolicy(
        max_retries=(
            scenario.retransmission.max_retries if max_retries is None else max_retries
        ),
        base_backoff=scenario.retransmission.base_backoff,
        backoff_multiplier=scenario.retransmission.backoff_multiplier,
        max_backoff=scenario.retransmission.max_backoff,
    )
    return ScenarioConfig(
        name=scenario.name,
        network=network,
        loss=loss,
        retransmission=retransmission,
        trials=scenario.trials if trials is None else trials,
    )


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
