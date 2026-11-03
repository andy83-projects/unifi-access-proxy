# unifi-access-proxy

> **Software emulator and bridge for UniFi Access (UA-Hub)** to control third-party locks, doors, and gates via Home Assistant.

---

## Overview

`unifi-access-proxy` allows the **UniFi Access** application running on a Ubiquiti Dream Machine (UDM Pro / SE) or Cloud Gateway to discover, adopt, and control third-party access devices without requiring physical Ubiquiti Access Hub hardware.

The primary target is managing:
- **Schlage Z-Wave Smart Deadbolts** (connected through Hubitat and Home Assistant)
- **MyQ Garage Door Controllers** (connected through Home Assistant)

---

## Status: Phase 1 (Discovery Emulator)

- [x] Reverse-engineered UBNT discovery TLV requirements from `unifi-access-app` on the UDM Pro.
- [x] Identified root cause of earlier discovery failures (missing `TAG_ID`, `TAG_MODEL` vs `TAG_PLATFORM`, and `TAG_PORT`).
- [x] Implemented UDP 10001 listener, packet decoder, and emulated UA-Hub responder.
- [x] Built embedded HTTP health check server (`/health`, `/status`) for Kubernetes readiness and metrics.
- [ ] Deploy as K3s workload via FluxCD GitOps.
- [ ] Confirm discovery appearance in UniFi Access controller.

---

## Project Structure

```
unifi-access-proxy/
├── Dockerfile
├── requirements.txt
├── src/
│   └── unifi_access_proxy/
│       ├── __init__.py
│       ├── __main__.py          # Entrypoint CLI
│       ├── device.py            # Device identity & config
│       ├── protocol.py          # UBNT discovery encoder/decoder & TLVs
│       └── server.py            # Async UDP 10001 & HTTP health server
├── tests/
│   └── test_protocol.py
└── docs/
    ├── ARCHITECTURE.md          # Multi-phase architecture roadmap
    └── DISCOVERY-PROTOCOL.md    # Reverse-engineering findings & TLV tags
```

---

## Running Locally

```bash
# Run unit tests
PYTHONPATH=src python3 tests/test_protocol.py

# Run discovery listener in passive observation mode
PYTHONPATH=src python3 -m unifi_access_proxy

# Run in active response mode (answering controller discovery probes)
ENABLE_ACTIVE_RESPONSES=true HUB_ADVERTISED_IP=10.0.2.92 PYTHONPATH=src python3 -m unifi_access_proxy
```

---

## Documentation

- [Architecture & Roadmap](docs/ARCHITECTURE.md)
- [Discovery Protocol Analysis](docs/DISCOVERY-PROTOCOL.md)
