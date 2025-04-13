<p align="center">
  <img src="assets/handletact_banner.png" alt="HandleTact Banner" width="150"/>
</p>

<h1 align="center">
  🔧 HandleTact v0.1
</h1>

<p align="center">
  <strong>Tactical BLE Handle Dissector & Replay Tool</strong><br>
  Dissect. Decide. Deliver.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.6+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/gatttool-required-orange.svg" alt="gatttool">
  <img src="https://img.shields.io/badge/license-GNU GPL v3.0-green.svg" alt="License">
</p>

---

## 🎯 What is HandleTact?

**HandleTact** is a CLI tool built for BLE attackers, red teamers, and IoT tinkerers.  
It extracts `Write Request` and `Write Command` operations from BLE traffic logs or captures, and **replays them using `gatttool`** — the old-school ninja way.

---

## ✨ Features

- 📦 Parses `.pcap` (Wireshark) or `bt_snoop.log` (Android)
- 🎮 Interactive menu for:
  - Full replay
  - Sequence range
  - Single write
  - Loop mode with delay
- 🎯 One-liner BLE injection via `gatttool`
- 🧠 Colorful UI + ASCII banner
- ✅ Python 3.6+ compatible

---

## 🧰 Requirements

- Python 3.6+
- `gatttool` (from `bluez` suite)
- Python packages:
  - `scapy`
  - `colorama`

### 🛠️ Install

```bash
sudo apt update
sudo apt install python3 python3-pip bluez
pip3 install scapy colorama
```
## 🚀 Usage
### Run with a .pcap file
```bash
sudo python3 handletact.py ble_traffic.pcap -d 0.5
```
### Run with Android bt_snoop.log
```bash
sudo python3 handletact.py bt_snoop.log
```
---
## 🤖 Codename Meaning
HandleTact = Handle + Tactical
A smart, stealthy tool to manipulate BLE characteristic writes with surgical precision.

## 👤 Author
Developed with 🔥 by @souravbaghz <br>
🚘 Automotive Cybersecurity · RF · Reverse Engineering · IoT Pentesting

## ⚠️ Disclaimer
This tool is provided for educational and research purposes only.
Unauthorized use against live devices may violate laws and regulations.

---
<p align="center">
  <strong>🧪 Like it? Star it ⭐️</strong><br>
  Hack smart. Stay sharp.
</p>



