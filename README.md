# Botnet / C2 Attack Simulation — Detection & Defense Analysis

> **Academic lab project (KSU – CYB 444).** Built and analyzed entirely inside an **isolated VirtualBox host-only network** using **synthetic, fake data**. This repository documents the project from a **defensive (Blue Team) perspective** — how this class of threat behaves on the network and, more importantly, **how a SOC analyst detects and responds to it**.
>
> ⚠️ No malware, agent code, or C2 server code is published here. This repo is a **detection and analysis** write-up only.

---

## 1. Overview

This project recreates the full lifecycle of a Command-and-Control (C2) botnet in a controlled lab, then analyzes it as a defender would. The goal was to understand attacker behavior well enough to **write detections for it** — the core skill of a SOC analyst.

**My focus in this write-up:** network behavior analysis, Indicators of Compromise (IOCs), MITRE ATT&CK mapping, and SIEM detection logic.

---

## 2. Lab Environment

| Component | Details |
|---|---|
| Attacker / C2 | Kali Linux — `192.168.56.101` |
| Victim | Windows 10 — `192.168.56.102` |
| Network | VirtualBox **Host-Only (fully isolated)** |
| C2 channel | HTTP over port `5000` |
| Data | Synthetic / fake only (no real credentials or PII) |

---

## 3. Attack Lifecycle (defender's view)

| Phase | What happens | Defensive signal |
|---|---|---|
| Delivery | Social-engineering link posing as a free game | URL / download reputation, user-reported phishing |
| Execution | User runs a disguised installer | New process spawning from Downloads, unsigned binary |
| Install | Agent silently deployed | New persistence, unexpected autostart |
| Check-in | Agent registers with the C2 | First outbound connection to unknown host |
| C2 | Agent polls the server **every ~5 seconds** | **Regular, fixed-interval beaconing** |
| Actions | Commands run; files exfiltrated | Outbound POST with file data, data volume spikes |

A sequence diagram of the flow is in [`/docs`](./docs).

---

## 4. Network Indicators (IOCs)

Observed from the C2 traffic logs:

- **Beaconing:** repeated `GET /get_task/<id>` requests at a near-constant ~5s interval — low jitter, machine-like regularity.
- **Result channel:** `POST /send_result` following command execution.
- **Exfiltration:** `POST /upload` carrying file content outbound.
- **Victim → single external host** over a non-standard port (`5000`) with a repeating URI pattern.

> The single strongest tell here is **the rhythm**: human traffic is irregular; beaconing is a metronome.

---

## 5. MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1566 Phishing |
| Execution | T1204 User Execution |
| Command & Control | T1071.001 Application Layer Protocol: Web |
| Command & Control | T1571 Non-Standard Port |
| Exfiltration | T1041 Exfiltration Over C2 Channel |

---

## 6. Detection Logic

### 6.1 Beaconing detection (Splunk SPL — concept)
Group outbound connections by source/destination and look for low variance in the time between connections (the hallmark of a beacon):

```spl
index=proxy OR index=firewall dest_port=5000
| streamstats current=f last(_time) as prev_time by src_ip, dest_ip
| eval delta = _time - prev_time
| stats count, avg(delta) as avg_gap, stdev(delta) as jitter by src_ip, dest_ip
| where count > 20 AND jitter < 2
| sort jitter
```
A high count with **very low jitter** = suspected beacon.

### 6.2 Repeated task-polling URI (KQL — concept)
```kql
NetworkHttpLogs
| where RequestURL has "/get_task/"
| summarize Hits = count(), TimeSpan = max(TimeGenerated) - min(TimeGenerated) by SrcIP, DestIP
| where Hits > 50
```

### 6.3 Outbound file upload to unknown host
Alert on `POST /upload` (or large outbound POST bodies) to a destination with no reputation, especially from a workstation that has never contacted it before.

---

## 7. Defensive Recommendations

- **Network:** block/alert on outbound traffic to unknown hosts on non-standard ports; baseline normal destinations per host.
- **Beacon hunting:** schedule a recurring job that flags low-jitter periodic connections.
- **Endpoint (EDR):** alert on binaries executing from `Downloads`, unsigned installers, and unexpected child processes.
- **Email/Web:** URL filtering and user phishing reporting to cut off delivery.
- **DLP:** monitor and block abnormal outbound data volume.

---

## 8. What I Learned

- How C2 beaconing actually looks in logs, and why **timing analysis** beats signature matching for unknown agents.
- Translating attacker behavior into **SIEM detection rules** and ATT&CK techniques.
- The full detect → investigate → respond loop for a C2 incident.

---

## 9. Team & My Role

_Course project, CYB 444, King Saud University._

**Team members:**
- Rand Alabdulkarim
- Maali Alkhamali
- Noor Al Huraiz
- Reemah Aldosari

**My contribution (Reemah Aldosari):** Designed and built the isolated lab environment — configured the VirtualBox host-only network and the Kali Linux (attacker/C2) and Windows 10 (victim) virtual machines, ensuring full network isolation so the simulation could run safely without any external exposure.

---

## 10. Ethical Notice

This work was performed **only** inside an isolated lab with fabricated data, for educational purposes. Nothing here is intended for, or usable as, an operational tool. No offensive code is included in this repository.
