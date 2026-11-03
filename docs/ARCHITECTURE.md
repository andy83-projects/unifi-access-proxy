# UniFi Access Proxy Architecture

## Project Vision

The **UniFi Access Proxy** is a software emulation and bridge layer designed to allow the UniFi Access application on a UniFi Console (such as the UDM Pro) to manage third-party smart locks and gate operators as native UniFi Access Hubs.

### Ultimate Goal
Provide complete access control in UniFi Access for:
1. **Front Door Lock:** Schlage Z-Wave deadbolt (via Hubitat + Home Assistant)
2. **Back Door Lock:** Schlage Z-Wave deadbolt (via Hubitat + Home Assistant)
3. **Garage Door:** MyQ garage door opener (via Home Assistant)

Features targeted include:
- Native door status (DPS / door position sensor)
- Remote lock / unlock actions from the UniFi Access web UI and mobile apps
- Access users, groups, schedules, and permissions
- Access event logs and audit history

---

## Phased Roadmap

```
+-------------------------------------------------------------+
| Phase 1: L2 Discovery Emulation (Current)                   |
| - UDP 10001 listener & responder                           |
| - Verified TLV tags from unifi-access-app                   |
| - Surface device in UDM Pro as "Ready for Adoption"         |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Phase 2: Adoption Handshake & Protocol Session              |
| - Reverse-engineer UCP4 / WSS (:12442) & MQTT (:12812)      |
| - Certificate exchange and authentication                   |
| - Complete adoption into UniFi Access                       |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| Phase 3: Hardware State Bridging (Home Assistant Integration)|
| - Map virtual door locks & DPS to Home Assistant entities   |
| - Bi-directional state sync (lock/unlock commands)          |
| - Event dispatch and audit reporting                        |
+-------------------------------------------------------------+
```

---

## Networking Model in Kubernetes (K3s)

Like the existing camera proxy workloads (`reolink-proxy`) in the homelab:
- The workload runs in the K3s cluster.
- Exposure to the IoT / management network is achieved via a dedicated **MetalLB Layer 2 LoadBalancer Service** assigned an IP from the `reserved` pool (`10.0.2.90-99` with `autoAssign: false`).
- Discovery datagrams arrive on UDP 10001.
- No `hostNetwork: true` or complex CNI overlays (like Multus) are needed.
