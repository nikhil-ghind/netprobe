"""NetProbe: a Scapy-based TCP/IP validation and regression-testing framework.

NetProbe builds and validates TCP/IP three-way handshakes, detects
retransmissions, measures latency, and can run all of the above under
configurable, injected packet loss. Results are packaged into reports via a
CLI, and everything is designed to run reproducibly inside Docker on Linux.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
