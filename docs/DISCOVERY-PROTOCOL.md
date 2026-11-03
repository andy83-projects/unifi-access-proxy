# UniFi Access Discovery Protocol Reference

## Overview

UniFi Access devices (such as the UniFi Access Hub / `UA-Hub`, `UA-Hub-Lite`, and `UA-Gate`) advertise and discover controllers via the Ubiquiti Discovery Protocol over **UDP port 10001**.

This document captures the reverse-engineering findings conducted on the Ubiquiti Dream Machine Pro (`UDM Pro`, running UniFi OS 5.1.x and `unifi-access-app` 4.3.x).

---

## 1. Network Discovery Flow

1. **Controller Probes:**
   The `unifi-access-app` process on the UDM Pro binds to UDP 10001 and periodically sends broadcast/multicast discovery probes:
   - **Broadcast Destination:** `255.255.255.255:10001`
   - **Multicast Destination:** `233.89.188.1:10001`
   - **Payload:** 4 bytes:
     ```
     \x01\x00\x00\x00   (UBNT Discovery v1 probe)
     ```
     or
     ```
     \x02\x08\x00\x00   (UBNT Discovery v2 probe)
     ```
2. **Device Responses:**
   An Access Hub on the same Layer 2 segment receives the datagram and responds directly (unicast) to the source IP and ephemeral port from which the controller sent the query.

---

## 2. Wire Packet Structure

A discovery response packet uses the standard Ubiquiti TLV (Type-Length-Value) framing:

```
+--------+--------+------------------+-----------------------------+
| Byte 0 | Byte 1 | Bytes 2-3        | Bytes 4..N                  |
| Ver (1)| Cmd (1)| Payload Len (16) | TLV entries                 |
+--------+--------+------------------+-----------------------------+
```

### TLV Field Encoding:
Each TLV entry is packed as:
- **Type (Tag):** 1 byte (uint8)
- **Length:** 2 bytes (uint16 big-endian)
- **Value:** `Length` bytes

---

## 3. Discovered TLV Tags & Access App Validation

From disassembly of `/usr/sbin/unifi-access-app` (specifically the Go package `github.com/Ubiquiti-UID/unifi.lib.go-uum/discovery` and function `unifi-access-be/coms/service/impl/base_device_service/discovery/finder.CreateDeviceFromDiscoveryMessage`), UniFi Access enforces strict field validations:

| Tag (Hex) | Tag (Dec) | Constant / Method | Type | Description & Access Validation |
|---|---|---|---|---|
| `0x01` | 1 | `TAG_MAC` | 6 bytes | Hardware MAC address |
| `0x02` | 2 | `TAG_MAC_IPV4` | 10 bytes | **REQUIRED**: 6 bytes MAC + 4 bytes IPv4. Triggers `NoIP` error if missing. |
| `0x03` | 3 | `TAG_FIRMWARE` | string | Device firmware version (e.g. `4.3.22+12152`) |
| `0x0A` | 10 | `TAG_UPTIME_SECONDS` | uint32 / int32 | Device uptime in seconds |
| `0x0B` | 11 | `TAG_HOSTNAME` | string | **REQUIRED**: Device name. Triggers `NoName` error if missing. |
| `0x0C` | 12 | `TAG_PLATFORM` | string | Hardware platform code (e.g. `UAH`) |
| `0x15` | 21 | `TAG_MODEL` | string | **REQUIRED**: Model name (`UA-Hub`, `UA-Hub-Door`, `UA-Gate`). Triggers `NoModel` error if missing. |
| `0x16` | 22 | `TAG_APP_VERSION` | string | Application version |
| `0x17` | 23 | `TAG_ADOPTED` | uint8 | `0` = unadopted (ready for adoption), `1` = adopted |
| `0x21` | 33 | `TAG_ID` | string | **REQUIRED**: Device UUID/GUID. Triggers `NoId` error if missing. |
| `0x22` | 34 | `TAG_MQTT_BROKER` | string | MQTT broker endpoint (e.g. `tls://10.0.1.1:12812`) |
| `0x23` | 35 | `TAG_REVISION` | int32 | Hardware board revision |
| `0x24` | 36 | `TAG_PORT` | int32 | **REQUIRED**: Management port (typically `12443`). Triggers `NoPort` error if missing. |
| `0x25` | 37 | `TAG_LOCATION_ID` | string | Associated Access location ID |
| `0x26` | 38 | `TAG_CONTROLLER_ID` | string | Controller MAC / unique ID |
| `0x27` | 39 | `TAG_UP_TIMESTAMP` | int64 | Millisecond timestamp of boot |
| `0x28` | 40 | `TAG_UAH_ID` | string | Hub ID used in Access database |
| `0x29` | 41 | `TAG_FIRMWARE_ID` | string | Firmware metadata ID |
| `0x2B` | 43 | `TAG_GUID` | string | Access device GUID |
| `0x2C` | 44 | `TAG_DEFAULT_CREDS`| uint8 | `1` if default credentials are in effect |
| `0x2D` | 45 | `TAG_START_TIME` | int64 | Process start epoch timestamp |
| `0x2E` | 46 | `TAG_HW_TYPE` | string | Hardware type descriptor |
| `0x2F` | 47 | `TAG_BOM_REV` | string | Bill of Materials revision string |
| `0x3F` | 63 | `TAG_SUPPORT_UCP4` | uint8 | `1` indicates device supports UniFi Control Protocol v4 |

---

## 4. Root Cause of Previous Oct 11 Experiment Failure

An earlier experiment (`access-hub-spoof/tools/hub_responder.py`) attempted to announce an emulated hub, but the UDM Pro's UniFi Access interface remained on "No Devices Detected".

### Analysis of the Discrepancy:
1. **Wrong Model Tag:** `hub_responder.py` sent the model name under tag `0x0C` (which is `TAG_PLATFORM`, traditional for UniFi Network switches/APs). UniFi Access requires `TAG_MODEL` (`0x15` / `21`). Result: Access threw `NoModel`.
2. **Missing Device ID:** `hub_responder.py` sent a UUID under tag `0x20`. UniFi Access specifically expects `TAG_ID` (`0x21` / `33`). Result: Access threw `NoId`.
3. **Missing Port:** `hub_responder.py` omitted tag `0x24` (`TAG_PORT`). Result: Access threw `NoPort`.
4. **Access Model GUID Mismatch:** In UniFi Access (`/usr/lib/unifi-access/device_def/device_def.yaml`), the UA-Hub has a predefined GUID family (`4a5e238f-4bae-48d5-84d7-...`).

By supplying all required tags (`TAG_ID`, `TAG_MODEL`, `TAG_HOSTNAME`, `TAG_PORT`, and `TAG_MAC_IPV4`), the response passes `CreateDeviceFromDiscoveryMessage` parsing.
