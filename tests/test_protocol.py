"""Unit tests for the UniFi discovery protocol encoder/decoder."""

import struct
from unifi_access_proxy.protocol import (
    CMD_REQUEST,
    CMD_RESPONSE,
    TAG_ADOPTED,
    TAG_FIRMWARE,
    TAG_HOSTNAME,
    TAG_ID,
    TAG_MAC,
    TAG_MAC_IPV4,
    TAG_MODEL,
    TAG_PORT,
    TAG_SUPPORT_UCP4,
    DiscoveryMessage,
    build_ua_hub_response,
    parse_mac,
)


def test_parse_mac() -> None:
    raw = parse_mac("02:4A:5F:B1:4A:01")
    assert raw == bytes.fromhex("024a5fb14a01")


def test_request_probe_unpack() -> None:
    data = b"\x01\x00\x00\x00"
    msg = DiscoveryMessage.unpack(data)
    assert msg.version == 1
    assert msg.cmd == CMD_REQUEST
    assert msg.is_request is True


def test_ua_hub_response_tlvs() -> None:
    mac = "02:4A:5F:B1:4A:01"
    ip = "10.0.2.92"
    msg = build_ua_hub_response(
        mac_str=mac,
        ip_str=ip,
        model="UA-Hub",
        hostname="Test-UA-Hub",
        firmware="4.3.22+12152",
    )
    wire = msg.pack()
    assert len(wire) > 4
    assert wire[0] == 1
    assert wire[1] == CMD_RESPONSE

    # Unpack from wire
    decoded = DiscoveryMessage.unpack(wire)
    assert decoded.is_response is True
    assert decoded.get_string(TAG_MODEL) == "UA-Hub"
    assert decoded.get_string(TAG_HOSTNAME) == "Test-UA-Hub"
    assert decoded.get_string(TAG_FIRMWARE) == "4.3.22+12152"
    assert decoded.get_uint8(TAG_ADOPTED) == 0
    assert decoded.get_uint8(TAG_SUPPORT_UCP4) == 1

    # Check required tags for UniFi Access CreateDeviceFromDiscoveryMessage
    assert TAG_ID in decoded.tlvs
    assert TAG_MODEL in decoded.tlvs
    assert TAG_HOSTNAME in decoded.tlvs
    assert TAG_PORT in decoded.tlvs
    assert TAG_MAC_IPV4 in decoded.tlvs

    port = struct.unpack("!i", decoded.tlvs[TAG_PORT])[0]
    assert port == 12443

    dec_mac, dec_ip = decoded.get_mac_and_ipv4()
    assert dec_mac.lower() == mac.lower()
    assert dec_ip == ip


if __name__ == "__main__":
    test_parse_mac()
    test_request_probe_unpack()
    test_ua_hub_response_tlvs()
    print("All protocol tests passed!")
