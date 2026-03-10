# Lab Environment Setup Guide

## Overview
Three VMs on VirtualBox/VMware using a Host-Only network (192.168.100.0/24).

## VM Specifications

| VM | OS | RAM | CPU | IP | Role |
|---|---|---|---|---|---|
| Server | Ubuntu 22.04 LTS | 4 GB | 2 vCPUs | 192.168.100.20 | Decision engine + crypto server |
| Client | Ubuntu 22.04 LTS | 2 GB | 2 vCPUs | 192.168.100.30 | Asset scanner + client |
| Attacker | Kali Linux 2024.1 | 2 GB | 2 vCPUs | 192.168.100.10 | Traffic interception |
| Monitor (opt.) | Ubuntu 22.04 + Suricata | 2 GB | 2 vCPUs | 192.168.100.40 | IDS |

## Network Setup (VirtualBox)
1. File → Host Network Manager → Create → 192.168.100.1/24
2. Each VM → Settings → Network → Adapter 1 → Host-Only Adapter
3. Set static IPs per table above in each VM's `/etc/netplan/` config

## Static IP Configuration (Ubuntu)
```yaml
# /etc/netplan/01-netcfg.yaml
network:
  version: 2
  ethernets:
    enp0s3:
      addresses: [192.168.100.20/24]   # change per VM
      gateway4: 192.168.100.1
```
```bash
sudo netplan apply
ping 192.168.100.30  # test connectivity
```

## Server VM Setup
```bash
sudo apt update && sudo apt install -y python3 python3-pip git cmake gcc ninja-build libssl-dev
git clone https://github.com/YOUR_USERNAME/adaptive-crypto-agility.git
cd adaptive-crypto-agility
./scripts/install_liboqs.sh
pip install -r requirements.txt
python server/server.py --host 0.0.0.0 --port 9000
```

## Client VM Setup
```bash
sudo apt install -y python3 python3-pip git
git clone https://github.com/YOUR_USERNAME/adaptive-crypto-agility.git
cd adaptive-crypto-agility
pip install -r requirements.txt
python client/client.py --host 192.168.100.20 --port 9000 --preset high
```

## Attacker VM (Kali Linux)
```bash
sudo apt install -y wireshark tcpdump scapy nmap
# Capture traffic between client and server:
sudo tcpdump -i eth0 host 192.168.100.20 and host 192.168.100.30 -w /tmp/capture.pcap
# Open in Wireshark to verify only encrypted AES-256-GCM frames are visible
```
