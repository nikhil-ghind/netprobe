# NetProbe — Implementation Plan

NetProbe is a Python/Scapy framework for exercising TCP/IP fundamentals: constructing
and validating three-way handshakes, detecting retransmissions, measuring latency, and
doing all of this under configurable, injected packet loss (up to 30%+). Results are
captured with pytest assertions and packaged into a reproducible CLI tool that runs in
Docker on Linux, so the same regression scenarios produce comparable results run to run.

The work is split into five phases. Each phase is a coherent, independently reviewable
chunk of the codebase, committed in several small steps rather than one large commit.

## Phase 1 — Scaffolding & project skeleton

Goal: a working Python package layout, dependency/config plumbing, and stub modules
that later phases fill in, so the shape of the project is reviewable on its own.

Deliverables:
- `netprobe/` Python package with `__init__.py`, `exceptions.py`, `config.py`
  (dataclasses for scenario/network configuration: interface, target host/port,
  loss rate, timeout, retry count, RTT bounds).
- `pyproject.toml` / `setup.py` with package metadata and console-script entry point
  (`netprobe = netprobe.cli:main`).
- `requirements.txt` (scapy, pytest, click, rich/tabulate for report rendering).
- `tests/` package skeleton with `conftest.py` (shared fixtures, marks for
  root-required tests).
- Empty/stub modules for phases 2–5 (`packet_builder.py`, `handshake.py`,
  `retransmission.py`, `latency.py`, `loss_simulator.py`, `scenarios.py`,
  `report.py`, `cli.py`) with docstrings describing their responsibilities.

Files touched: `netprobe/__init__.py`, `netprobe/config.py`, `netprobe/exceptions.py`,
`netprobe/packet_builder.py`, `netprobe/handshake.py`, `netprobe/retransmission.py`,
`netprobe/latency.py`, `netprobe/loss_simulator.py`, `netprobe/scenarios.py`,
`netprobe/report.py`, `netprobe/cli.py`, `pyproject.toml`, `requirements.txt`,
`tests/__init__.py`, `tests/conftest.py`.

## Phase 2 — Core packet & handshake logic

Goal: real Scapy-based construction and validation of TCP/IP packets and the
three-way handshake state machine.

Deliverables:
- `packet_builder.py`: functions to build IP/TCP layers for SYN, SYN-ACK, ACK,
  RST, and data segments, with correct sequence/ack-number bookkeeping, window
  size, and checksum handling; helpers to validate an observed packet's flags,
  sequence numbers, and checksums against expectations.
- `handshake.py`: a `HandshakeSession` state machine (`CLOSED -> SYN_SENT ->
  ESTABLISHED` / `FAILED`) that drives a handshake attempt via Scapy's `sr1`/`send`,
  validates each response against `packet_builder` expectations, records
  timestamps for each leg, and raises typed exceptions (`HandshakeTimeout`,
  `UnexpectedFlags`, `SequenceMismatch`) from `exceptions.py` on failure.

Files touched: `netprobe/packet_builder.py`, `netprobe/handshake.py`,
`netprobe/exceptions.py`.

## Phase 3 — Packet-loss simulation & latency measurement

Goal: a configurable loss-injection layer and latency instrumentation that phase 2's
handshake logic (and later retransmission logic) can run under.

Deliverables:
- `loss_simulator.py`: a `LossSimulator` that wraps packet send/receive calls and
  probabilistically drops packets according to a configured loss rate (0–100%,
  default scenarios up to 30%), with a seedable RNG for reproducible runs, and
  optional asymmetric loss (uplink vs downlink) and jitter injection.
- `retransmission.py`: retransmission detection/logic — tracks sent segments by
  sequence number, detects duplicate sends within a timeout window, applies
  exponential backoff for retries, and counts retransmissions per session.
- `latency.py`: RTT measurement utilities (per-leg and end-to-end handshake
  latency), running statistics (min/max/mean/p95) across repeated trials.
- Integration of `LossSimulator` into `HandshakeSession` so handshakes can be run
  under simulated loss and retried per `retransmission.py`'s policy.

Files touched: `netprobe/loss_simulator.py`, `netprobe/retransmission.py`,
`netprobe/latency.py`, `netprobe/handshake.py`.

## Phase 4 — Scenario runner & pytest suite

Goal: turn the building blocks into runnable scenarios and cover them with a real
pytest suite asserting on handshake correctness, retransmission behavior, latency
bounds, and loss simulation statistics.

Deliverables:
- `scenarios.py`: a `ScenarioRunner` that executes a named scenario (e.g. "clean
  handshake", "handshake under 10% loss", "handshake under 30% loss",
  "retransmission stress") N times and aggregates results into a
  `ScenarioResult` dataclass (success rate, retransmission counts, latency stats).
- `tests/test_packet_builder.py`: assertions on constructed packet fields
  (flags, seq/ack arithmetic, checksums).
- `tests/test_handshake.py`: state machine transitions, timeout/failure paths,
  using a mocked/faked Scapy send layer (no real sockets needed) via
  `conftest.py` fixtures.
- `tests/test_retransmission.py`: duplicate-send detection, backoff schedule.
- `tests/test_latency.py`: RTT stats calculations.
- `tests/test_loss_simulator.py`: statistical assertions on drop rate over many
  trials with a fixed seed.
- `tests/test_scenarios.py`: end-to-end scenario aggregation using the mocked
  transport.
- `pytest.ini` / `pyproject.toml` pytest config, including a `root_required`
  marker for tests that need real raw sockets (skipped by default in CI/sandbox).

Files touched: `netprobe/scenarios.py`, `tests/test_packet_builder.py`,
`tests/test_handshake.py`, `tests/test_retransmission.py`, `tests/test_latency.py`,
`tests/test_loss_simulator.py`, `tests/test_scenarios.py`, `tests/conftest.py`,
`pyproject.toml`.

## Phase 5 — CLI, reporting, Docker packaging & polish

Goal: package everything as a reproducible CLI tool with a Docker image, plus the
repo hygiene files (`.gitignore`, real `README.md`).

Deliverables:
- `cli.py`: a `click`-based CLI (`netprobe run --target <host> --port <port>
  --loss 0.3 --trials 20 --scenario handshake`, `netprobe report <results.json>`)
  that runs scenarios via `ScenarioRunner` and writes/prints a report.
- `report.py`: renders `ScenarioResult` data as a human-readable table (rich/
  tabulate) and as JSON for CI archiving.
- `Dockerfile`: Linux base image, installs `libpcap`/scapy system deps, installs
  the package, sets an entrypoint, documents that the container needs
  `--cap-add=NET_RAW --cap-add=NET_ADMIN` (or `--privileged`) to send raw packets.
- `.gitignore`: Python/Docker-appropriate ignores.
- `README.md`: overview, architecture diagram (Mermaid), usage (local +
  Docker), testing instructions, and required privileges.

Files touched: `netprobe/cli.py`, `netprobe/report.py`, `Dockerfile`,
`.gitignore`, `README.md`.
