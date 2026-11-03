"""UDP Discovery and HTTP health server for the UniFi Access Proxy."""

import asyncio
import json
import logging
import socket
import struct
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from typing import Any, Dict, Optional

from .device import DeviceConfig
from .protocol import (
    CMD_REQUEST,
    DiscoveryMessage,
    build_ua_hub_response,
)

logger = logging.getLogger("unifi-access-proxy")


class DiscoveryProtocol(asyncio.DatagramProtocol):
    """Asyncio UDP protocol handler for Ubiquiti discovery on port 10001."""

    def __init__(self, config: DeviceConfig, stats: Dict[str, Any]):
        self.config = config
        self.stats = stats
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:  # type: ignore
        self.transport = transport
        logger.info(
            "Discovery listener active on UDP :%d (multicast: %s)",
            self.config.listen_port,
            self.config.multicast_group,
        )

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        self.stats["packets_received"] += 1
        src_ip, src_port = addr

        try:
            msg = DiscoveryMessage.unpack(data)
        except Exception as err:
            logger.debug(
                "Received unparseable UDP packet (%d bytes) from %s:%d: %s",
                len(data),
                src_ip,
                src_port,
                err,
            )
            self.stats["packets_unparseable"] += 1
            return

        is_probe = len(data) == 4 and data[0] in (1, 2) and data[1] == 0
        self.stats["last_packet_time"] = time.time()
        self.stats["last_packet_src"] = f"{src_ip}:{src_port}"

        if is_probe or msg.is_request:
            self.stats["probes_received"] += 1
            logger.info(
                "Discovery PROBE received from %s:%d (v%d, %d bytes)",
                src_ip,
                src_port,
                msg.version,
                len(data),
            )
            if self.config.enable_active_responses:
                self.send_hub_response(addr)
            else:
                logger.info(
                    "Passive observation mode: active responses disabled. Ignoring probe from %s",
                    src_ip,
                )
        else:
            cmd_name = "RESPONSE" if msg.is_response else f"BEACON({msg.cmd})"
            logger.info(
                "Discovery %s packet from %s:%d (model=%s, name=%s, mac=%s, ip=%s)",
                cmd_name,
                src_ip,
                src_port,
                msg.get_string(0x15),
                msg.get_string(0x0B),
                msg.get_mac_and_ipv4()[0],
                msg.get_mac_and_ipv4()[1],
            )
            logger.debug("Packet details: %s", json.dumps(msg.to_dict()))

    def send_hub_response(self, target_addr: Tuple[str, int]) -> None:
        """Sends an emulated UA-Hub discovery response to the prober."""
        if not self.transport:
            return

        resp = build_ua_hub_response(
            mac_str=self.config.mac,
            ip_str=self.config.advertised_ip,
            model=self.config.model,
            hostname=self.config.hostname,
            firmware=self.config.firmware,
            device_id=self.config.device_id,
            adopted=False,
            uptime_seconds=int(time.time() - self.stats["start_time"]),
        )
        wire_bytes = resp.pack()
        self.transport.sendto(wire_bytes, target_addr)
        self.stats["responses_sent"] += 1
        logger.info(
            "Sent emulated %s discovery response (%d bytes) to %s:%d (mac=%s, ip=%s, id=%s)",
            self.config.model,
            len(wire_bytes),
            target_addr[0],
            target_addr[1],
            self.config.mac,
            self.config.advertised_ip,
            self.config.device_id,
        )


class HealthHTTPHandler(BaseHTTPRequestHandler):
    """Minimal HTTP server for Kubernetes liveness & readiness probes."""

    config: DeviceConfig
    stats: Dict[str, Any]

    def do_GET(self) -> None:
        if self.path == "/health" or self.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"healthy"}')
        elif self.path == "/status" or self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = {
                "status": "running",
                "uptime_seconds": int(time.time() - self.stats["start_time"]),
                "config": {
                    "mac": self.config.mac,
                    "advertised_ip": self.config.advertised_ip,
                    "hostname": self.config.hostname,
                    "model": self.config.model,
                    "firmware": self.config.firmware,
                    "device_id": self.config.device_id,
                    "enable_active_responses": self.config.enable_active_responses,
                    "enable_periodic_beacons": self.config.enable_periodic_beacons,
                },
                "stats": self.stats,
            }
            self.wfile.write(json.dumps(payload, indent=2).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress standard HTTP request access logging to keep console clean
        pass


def run_http_server(config: DeviceConfig, stats: Dict[str, Any]) -> HTTPServer:
    handler = type("ConfiguredHandler", (HealthHTTPHandler,), {"config": config, "stats": stats})
    server = HTTPServer(("0.0.0.0", config.http_port), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Health HTTP server listening on :%d (/health, /status)", config.http_port)
    return server


async def run_server(config: DeviceConfig) -> None:
    """Main async entrypoint to run UDP listener and background tasks."""
    stats: Dict[str, Any] = {
        "start_time": time.time(),
        "packets_received": 0,
        "probes_received": 0,
        "packets_unparseable": 0,
        "responses_sent": 0,
        "beacons_sent": 0,
        "last_packet_time": None,
        "last_packet_src": None,
    }

    # Start HTTP health endpoint
    httpd = run_http_server(config, stats)

    loop = asyncio.get_running_loop()

    # Create raw UDP socket configured for SO_REUSEADDR and SO_REUSEPORT (if available)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass

    # Bind to 0.0.0.0:10001
    sock.bind(("0.0.0.0", config.listen_port))
    sock.setblocking(False)

    # Join multicast group 233.89.188.1 on default interface
    try:
        mreq = struct.pack(
            "4s4s",
            socket.inet_aton(config.multicast_group),
            socket.inet_aton("0.0.0.0"),
        )
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        logger.info("Successfully joined multicast group %s", config.multicast_group)
    except Exception as err:
        logger.warning("Could not join multicast group %s: %s", config.multicast_group, err)

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: DiscoveryProtocol(config, stats),
        sock=sock,
    )

    try:
        while True:
            await asyncio.sleep(1)
            if config.enable_periodic_beacons:
                # Optional beaconing if configured
                now = time.time()
                if int(now) % config.beacon_interval_seconds == 0:
                    beacon = build_ua_hub_response(
                        mac_str=config.mac,
                        ip_str=config.advertised_ip,
                        model=config.model,
                        hostname=config.hostname,
                        firmware=config.firmware,
                        device_id=config.device_id,
                        adopted=False,
                        uptime_seconds=int(now - stats["start_time"]),
                    )
                    wire = beacon.pack()
                    transport.sendto(wire, (config.multicast_group, config.listen_port))
                    transport.sendto(wire, ("255.255.255.255", config.listen_port))
                    stats["beacons_sent"] += 2
                    logger.debug("Broadcasted periodic discovery beacon")
    except asyncio.CancelledError:
        logger.info("Discovery server shutting down...")
    finally:
        transport.close()
        httpd.shutdown()
