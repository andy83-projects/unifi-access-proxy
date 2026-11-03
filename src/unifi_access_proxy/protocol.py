"""Ubiquiti Discovery Protocol (UDP 10001) encoder/decoder for UniFi Access.

Reverse-engineered from unifi-access-app (unifi.lib.go-uum/discovery) on UniFi OS.

Wire Format:
- Byte 0: Version (0x01 or 0x02)
- Byte 1: Command (0x00=Request, 0x01=Response, 0x02=Beacon)
- Bytes 2-3: Payload length (uint16 big-endian)
Followed by TLV entries:
- Byte 0: Type (uint8)
- Bytes 1-2: Length (uint16 big-endian)
- Bytes 3..: Value (bytes)
"""

import socket
import struct
from typing import Any, Dict, Optional, Tuple

VERSION_V1 = 0x01
VERSION_V2 = 0x02

CMD_REQUEST = 0x00
CMD_RESPONSE = 0x01
CMD_BEACON = 0x02

# Standard & UniFi Access-specific TLV Tags
TAG_MAC = 0x01             # 6 bytes binary MAC address
TAG_MAC_IPV4 = 0x02        # 10 bytes: 6 bytes MAC + 4 bytes IPv4
TAG_FIRMWARE = 0x03        # string: Firmware version
TAG_UPTIME_SECONDS = 0x0A  # uint32 / int32: Uptime in seconds
TAG_HOSTNAME = 0x0B        # string: Device hostname / name
TAG_PLATFORM = 0x0C        # string: Hardware platform (e.g. "UAH")
TAG_MODEL = 0x15           # string: Model name (e.g. "UA-Hub", "UA-Hub-Lite", "UA-Gate")
TAG_APP_VERSION = 0x16     # string: Application version
TAG_ADOPTED = 0x17         # uint8: 0 = unadopted / pending, 1 = adopted
TAG_ID = 0x21              # string: Device ID / GUID (Required by Access finder)
TAG_MQTT_BROKER = 0x22     # string: MQTT broker URL (e.g. "tls://10.0.1.1:12812")
TAG_REVISION = 0x23        # int32: Hardware revision
TAG_PORT = 0x24            # int32: Device listening port (e.g. 12443)
TAG_LOCATION_ID = 0x25     # string: Location ID
TAG_CONTROLLER_ID = 0x26   # string: Controller ID
TAG_UP_TIMESTAMP = 0x27    # int64: Up timestamp (milliseconds or seconds)
TAG_UAH_ID = 0x28          # string: UniFi Access Hub ID
TAG_FIRMWARE_ID = 0x29     # string: Firmware ID
TAG_GUID = 0x2B            # string: GUID
TAG_DEFAULT_CREDS = 0x2C   # uint8: Default credentials flag (1 or 0)
TAG_START_TIME = 0x2D      # int64: Start time in seconds
TAG_HW_TYPE = 0x2E         # string: Hardware type
TAG_BOM_REV = 0x2F         # string: BOM revision
TAG_SUPPORT_UCP4 = 0x3F    # uint8: 1 if device supports UCP4 protocol

TAG_NAMES: Dict[int, str] = {
    TAG_MAC: "MAC",
    TAG_MAC_IPV4: "MAC_IPV4",
    TAG_FIRMWARE: "Firmware",
    TAG_UPTIME_SECONDS: "UptimeSeconds",
    TAG_HOSTNAME: "Hostname",
    TAG_PLATFORM: "Platform",
    TAG_MODEL: "Model",
    TAG_APP_VERSION: "AppVersion",
    TAG_ADOPTED: "Adopted",
    TAG_ID: "ID",
    TAG_MQTT_BROKER: "MqttBroker",
    TAG_REVISION: "Revision",
    TAG_PORT: "Port",
    TAG_LOCATION_ID: "LocationID",
    TAG_CONTROLLER_ID: "ControllerID",
    TAG_UP_TIMESTAMP: "UpTimestamp",
    TAG_UAH_ID: "UahID",
    TAG_FIRMWARE_ID: "FirmwareID",
    TAG_GUID: "GUID",
    TAG_DEFAULT_CREDS: "DefaultCredentials",
    TAG_START_TIME: "StartTimeSeconds",
    TAG_HW_TYPE: "HwType",
    TAG_BOM_REV: "BomRev",
    TAG_SUPPORT_UCP4: "SupportUCP4",
}


def format_mac(raw: bytes) -> str:
    """Format 6 bytes into colon-separated hex MAC."""
    return ":".join(f"{b:02x}" for b in raw)


def parse_mac(mac_str: str) -> bytes:
    """Parse colon/dash separated MAC address to 6 bytes."""
    clean = mac_str.replace(":", "").replace("-", "").replace(".", "")
    if len(clean) != 12:
        raise ValueError(f"Invalid MAC address: {mac_str}")
    return bytes.fromhex(clean)


class DiscoveryMessage:
    """Represents a decoded or to-be-encoded Ubiquiti Discovery packet."""

    def __init__(self, version: int = VERSION_V1, cmd: int = CMD_RESPONSE):
        self.version = version
        self.cmd = cmd
        self.tlvs: Dict[int, bytes] = {}

    @property
    def is_request(self) -> bool:
        return self.cmd == CMD_REQUEST

    @property
    def is_response(self) -> bool:
        return self.cmd == CMD_RESPONSE

    @property
    def is_beacon(self) -> bool:
        return self.cmd == CMD_BEACON

    def set_bytes(self, tag: int, val: bytes) -> None:
        self.tlvs[tag] = val

    def set_string(self, tag: int, val: str) -> None:
        self.tlvs[tag] = val.encode("utf-8")

    def set_uint8(self, tag: int, val: int) -> None:
        self.tlvs[tag] = struct.pack("!B", val & 0xFF)

    def set_uint16(self, tag: int, val: int) -> None:
        self.tlvs[tag] = struct.pack("!H", val & 0xFFFF)

    def set_uint32(self, tag: int, val: int) -> None:
        self.tlvs[tag] = struct.pack("!I", val & 0xFFFFFFFF)

    def set_int32(self, tag: int, val: int) -> None:
        self.tlvs[tag] = struct.pack("!i", val)

    def set_int64(self, tag: int, val: int) -> None:
        self.tlvs[tag] = struct.pack("!q", val)

    def set_mac_and_ipv4(self, mac_bytes: bytes, ip_str: str) -> None:
        """Sets TAG_MAC_IPV4 (10 bytes: 6 bytes MAC + 4 bytes IPv4)."""
        ip_bytes = socket.inet_aton(ip_str)
        self.tlvs[TAG_MAC_IPV4] = mac_bytes[:6] + ip_bytes

    def get_string(self, tag: int, default: str = "") -> str:
        raw = self.tlvs.get(tag)
        if not raw:
            return default
        return raw.decode("utf-8", errors="replace")

    def get_uint8(self, tag: int, default: int = 0) -> int:
        raw = self.tlvs.get(tag)
        if not raw or len(raw) < 1:
            return default
        return struct.unpack("!B", raw[:1])[0]

    def get_uint32(self, tag: int, default: int = 0) -> int:
        raw = self.tlvs.get(tag)
        if not raw or len(raw) < 4:
            return default
        return struct.unpack("!I", raw[:4])[0]

    def get_mac_and_ipv4(self) -> Tuple[Optional[str], Optional[str]]:
        raw = self.tlvs.get(TAG_MAC_IPV4)
        if raw and len(raw) >= 10:
            mac = format_mac(raw[:6])
            ip = socket.inet_ntoa(raw[6:10])
            return mac, ip
        raw_mac = self.tlvs.get(TAG_MAC)
        mac = format_mac(raw_mac[:6]) if raw_mac and len(raw_mac) >= 6 else None
        return mac, None

    def pack(self) -> bytes:
        """Serializes the message into the wire format."""
        payload = bytearray()
        for tag, val in sorted(self.tlvs.items()):
            payload.append(tag & 0xFF)
            payload.extend(struct.pack("!H", len(val)))
            payload.extend(val)

        header = bytearray()
        header.append(self.version & 0xFF)
        header.append(self.cmd & 0xFF)
        header.extend(struct.pack("!H", len(payload)))
        return bytes(header + payload)

    @classmethod
    def unpack(cls, data: bytes) -> "DiscoveryMessage":
        """Parses a raw UDP packet into a DiscoveryMessage."""
        if len(data) < 4:
            raise ValueError(f"Packet too short ({len(data)} bytes, minimum is 4)")

        version = data[0]
        cmd = data[1]
        payload_len = struct.unpack("!H", data[2:4])[0]

        msg = cls(version=version, cmd=cmd)
        if len(data) == 4 and cmd == CMD_REQUEST:
            return msg

        if len(data) < 4 + payload_len:
            raise ValueError(
                f"Packet truncated: header expects {payload_len} payload bytes, got {len(data) - 4}"
            )

        offset = 4
        end = 4 + payload_len
        while offset < end:
            if offset + 3 > end:
                break
            tag = data[offset]
            length = struct.unpack("!H", data[offset + 1 : offset + 3])[0]
            offset += 3
            if offset + length > end:
                break
            val = data[offset : offset + length]
            offset += length
            msg.tlvs[tag] = val

        return msg

    def to_dict(self) -> Dict[str, Any]:
        """Provides a human-readable dictionary representation for logging and APIs."""
        mac, ip = self.get_mac_and_ipv4()
        res: Dict[str, Any] = {
            "version": self.version,
            "cmd": "REQUEST" if self.is_request else ("RESPONSE" if self.is_response else f"BEACON({self.cmd})"),
            "model": self.get_string(TAG_MODEL),
            "hostname": self.get_string(TAG_HOSTNAME),
            "id": self.get_string(TAG_ID),
            "mac": mac,
            "ip": ip,
            "firmware": self.get_string(TAG_FIRMWARE),
            "adopted": bool(self.get_uint8(TAG_ADOPTED)),
            "tlv_count": len(self.tlvs),
            "tlvs": {},
        }
        for tag, val in sorted(self.tlvs.items()):
            tag_name = TAG_NAMES.get(tag, f"TAG_0x{tag:02X}")
            if tag in (TAG_HOSTNAME, TAG_MODEL, TAG_FIRMWARE, TAG_ID, TAG_PLATFORM, TAG_APP_VERSION, TAG_MQTT_BROKER, TAG_GUID, TAG_UAH_ID, TAG_HW_TYPE):
                val_repr = val.decode("utf-8", errors="replace")
            elif tag == TAG_MAC_IPV4 and len(val) >= 10:
                val_repr = f"{format_mac(val[:6])} / {socket.inet_ntoa(val[6:10])}"
            elif tag == TAG_MAC and len(val) >= 6:
                val_repr = format_mac(val[:6])
            elif tag in (TAG_UPTIME_SECONDS, TAG_PORT, TAG_REVISION) and len(val) >= 4:
                val_repr = struct.unpack("!I", val[:4])[0]
            elif tag in (TAG_ADOPTED, TAG_DEFAULT_CREDS, TAG_SUPPORT_UCP4) and len(val) >= 1:
                val_repr = val[0]
            else:
                val_repr = val.hex()
            res["tlvs"][tag_name] = val_repr
        return res


def build_ua_hub_response(
    mac_str: str,
    ip_str: str,
    model: str = "UA-Hub",
    hostname: str = "UA-Hub",
    firmware: str = "4.3.22+12152",
    device_id: Optional[str] = None,
    adopted: bool = False,
    uptime_seconds: int = 3600,
) -> DiscoveryMessage:
    """Builds a verified Discovery Response for a UniFi Access Hub (UA-Hub).

    Populates all required fields discovered from unifi-access-app reverse-engineering:
    - ID (Tag 33 / 0x21) [REQUIRED by Access CreateDeviceFromDiscoveryMessage]
    - Name (Tag 11 / 0x0B) [REQUIRED]
    - Model (Tag 21 / 0x15) [REQUIRED]
    - Port (Tag 36 / 0x24) [REQUIRED]
    - MAC + IPv4 (Tag 2 / 0x02) [REQUIRED]
    - Adopted status (Tag 23 / 0x17): 0 = unadopted
    - SupportUCP4 (Tag 63 / 0x3F): 1
    """
    mac_bytes = parse_mac(mac_str)
    mac_hex_clean = mac_str.replace(":", "").replace("-", "").lower()
    guid = device_id or f"4a5e238f-4bae-48d5-84d7-{mac_hex_clean}"

    msg = DiscoveryMessage(version=VERSION_V1, cmd=CMD_RESPONSE)
    msg.set_mac_and_ipv4(mac_bytes, ip_str)
    msg.set_bytes(TAG_MAC, mac_bytes)
    msg.set_string(TAG_HOSTNAME, hostname)
    msg.set_string(TAG_MODEL, model)
    msg.set_string(TAG_PLATFORM, "UAH")
    msg.set_string(TAG_FIRMWARE, firmware)
    msg.set_string(TAG_APP_VERSION, firmware)
    msg.set_string(TAG_ID, guid)
    msg.set_string(TAG_GUID, guid)
    msg.set_string(TAG_UAH_ID, guid)
    msg.set_uint8(TAG_ADOPTED, 1 if adopted else 0)
    msg.set_uint32(TAG_UPTIME_SECONDS, uptime_seconds)
    msg.set_int32(TAG_REVISION, 1)
    msg.set_int32(TAG_PORT, 12443)
    msg.set_uint8(TAG_SUPPORT_UCP4, 1)
    msg.set_uint8(TAG_DEFAULT_CREDS, 0)
    return msg
