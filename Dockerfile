# NetProbe -- reproducible TCP/IP validation under simulated packet loss.
#
# Sending raw SYN/ACK segments requires CAP_NET_RAW (Scapy opens raw
# sockets). Run the container with that capability added, e.g.:
#
#   docker build -t netprobe .
#   docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
#       netprobe run --target 192.0.2.10 --port 443
#
# (--privileged also works but grants far more than NetProbe needs.)

FROM python:3.12-slim AS base

# libpcap0.8 is Scapy's runtime dependency for raw packet I/O; tcpdump is
# included only as an optional debugging aid inside the container and can be
# dropped if image size matters more than that convenience.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libpcap0.8 \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml requirements.txt ./
COPY netprobe ./netprobe
COPY README.md ./

RUN pip install --no-cache-dir .

# A non-root user is preferred for everything except actually sending raw
# packets: CAP_NET_RAW is granted at the container level (see the `docker
# run` example above), not via setuid, so the process can stay unprivileged
# otherwise and still send/receive raw sockets as long as the capability is
# present on the container.
RUN useradd --create-home --shell /bin/bash netprobe
USER netprobe

ENTRYPOINT ["netprobe"]
CMD ["--help"]
