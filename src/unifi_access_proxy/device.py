"""Device identity and configuration model for the virtual UniFi Access Hub."""

import os
from typing import Optional


class DeviceConfig:
    """Configuration parameters for the virtual Access Hub."""

    def __init__(
        self,
        mac: str = "02:4A:5F:B1:4A:01",
        advertised_ip: str = "10.0.2.92",
        hostname: str = "Virtual-UA-Hub",
        model: str = "UA-Hub",
        firmware: str = "4.3.22+12152",
        device_id: Optional[str] = None,
        controller_host: str = "10.0.0.1",
        listen_port: int = 10001,
        multicast_group: str = "233.89.188.1",
        enable_active_responses: bool = False,
        enable_periodic_beacons: bool = False,
        beacon_interval_seconds: int = 30,
        enable_pcap: bool = False,
        pcap_file: str = "/tmp/discovery.pcap",
        log_level: str = "INFO",
        http_port: int = 8000,
    ):
        self.mac = mac
        self.advertised_ip = advertised_ip
        self.hostname = hostname
        self.model = model
        self.firmware = firmware
        clean_mac = mac.replace(":", "").replace("-", "").lower()
        # Default GUID matches the UA-Hub definition in UniFi Access (4a5e238f-4bae-48d5-84d7-...)
        self.device_id = device_id or f"4a5e238f-4bae-48d5-84d7-{clean_mac}"
        self.controller_host = controller_host
        self.listen_port = listen_port
        self.multicast_group = multicast_group
        self.enable_active_responses = enable_active_responses
        self.enable_periodic_beacons = enable_periodic_beacons
        self.beacon_interval_seconds = beacon_interval_seconds
        self.enable_pcap = enable_pcap
        self.pcap_file = pcap_file
        self.log_level = log_level
        self.http_port = http_port

    @classmethod
    def from_env(cls) -> "DeviceConfig":
        return cls(
            mac=os.getenv("HUB_MAC", "02:4A:5F:B1:4A:01"),
            advertised_ip=os.getenv("HUB_ADVERTISED_IP", "10.0.2.92"),
            hostname=os.getenv("HUB_HOSTNAME", "Virtual-UA-Hub"),
            model=os.getenv("HUB_MODEL", "UA-Hub"),
            firmware=os.getenv("HUB_FIRMWARE", "4.3.22+12152"),
            device_id=os.getenv("HUB_DEVICE_ID"),
            controller_host=os.getenv("CONTROLLER_HOST", "10.0.0.1"),
            listen_port=int(os.getenv("DISCOVERY_PORT", "10001")),
            multicast_group=os.getenv("MULTICAST_GROUP", "233.89.188.1"),
            enable_active_responses=os.getenv("ENABLE_ACTIVE_RESPONSES", "false").lower() in ("true", "1", "yes"),
            enable_periodic_beacons=os.getenv("ENABLE_PERIODIC_BEACONS", "false").lower() in ("true", "1", "yes"),
            beacon_interval_seconds=int(os.getenv("BEACON_INTERVAL_SECONDS", "30")),
            enable_pcap=os.getenv("ENABLE_PCAP", "false").lower() in ("true", "1", "yes"),
            pcap_file=os.getenv("PCAP_FILE", "/tmp/discovery.pcap"),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            http_port=int(os.getenv("HTTP_PORT", "8000")),
        )
