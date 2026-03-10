# Adaptive Crypto-Agility Decision System
### Quantum-Resilient Network Security

> **B.E Cybersecurity — Sri Krishna College of Technology, Coimbatore**  
> Academic Year 2025–2026

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![PQC](https://img.shields.io/badge/PQC-ML--KEM--1024%20%7C%20ML--DSA--65-purple)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Status](https://img.shields.io/badge/Status-Research%20Prototype-orange)]()

---

## Overview

This project implements an **Adaptive Crypto-Agility Decision System** that evaluates enterprise cryptographic assets, scores their quantum vulnerability, and dynamically selects the appropriate cryptographic mode:

| Risk Level | Mode Selected | Algorithms Used |
|---|---|---|
| LOW  (QRS ≤ 3.0)    | Classical      | X25519 ECDH + AES-256-GCM |
| MEDIUM (QRS 3.1–6.0) | Hybrid        | X25519 + ML-KEM-1024 + AES-256-GCM |
| HIGH  (QRS 6.1–10.0) | Triple-Hybrid | X25519 + ML-KEM-1024 + Simulated QKD + AES-256-GCM |

The system integrates classical cryptography, NIST post-quantum standards (FIPS 203/204), and simulated Quantum Key Distribution into existing network protocols — addressing the **"Harvest Now, Decrypt Later" (HNDL)** threat model.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   CLIENT MACHINE                        │
│  ┌─────────────────┐    ┌──────────────────────────┐   │
│  │  Asset Scanner  │───▶│  Risk Submission Client  │   │
│  └─────────────────┘    └──────────────────────────┘   │
└─────────────────────────────────┬───────────────────────┘
                                  │ Asset Profile (JSON)
                                  ▼
┌─────────────────────────────────────────────────────────┐
│                  ENTERPRISE SERVER                      │
│  ┌──────────────────┐   ┌─────────────────────────┐    │
│  │  Risk Assessment │──▶│  Crypto-Agility Decision│    │
│  │  Module          │   │  Engine                 │    │
│  └──────────────────┘   └────────────┬────────────┘    │
│                                       │ Mode Selection  │
│                          ┌────────────▼────────────┐   │
│                          │  Cryptographic Comm.    │   │
│                          │  Module (Hybrid KDF)    │   │
│                          └─────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
                                  │
                 ┌────────────────▼────────────────┐
                 │         ATTACKER MACHINE        │
                 │  Wireshark | Scapy | tcpdump    │
                 │  (Sees only AES-256-GCM cipher) │
                 └─────────────────────────────────┘
```

---

## Quick Start

### 1. Clone
```bash
git clone https://github.com/YOUR_USERNAME/adaptive-crypto-agility.git
cd adaptive-crypto-agility
```

### 2. Install LibOQS (Post-Quantum Library)
```bash
chmod +x scripts/install_liboqs.sh
./scripts/install_liboqs.sh
```

### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run Full Demo
```bash
python scripts/run_demo.py
```

---

## Module Guide

| Module | File | Description |
|---|---|---|
| Asset Scanner      | `client/asset_scanner.py`          | Profiles cryptographic assets |
| Risk Engine        | `risk_engine/risk_engine.py`       | Computes QRS quantum risk score |
| Decision Engine    | `risk_engine/decision_engine.py`   | Selects crypto mode |
| Crypto Comm        | `crypto_engine/crypto_comm.py`     | Hybrid key combiner + AES-256-GCM |
| Server             | `server/server.py`                 | Adaptive TLS-simulated server |
| Client             | `client/client.py`                 | Asset-aware secure client |
| Attack Simulation  | `scripts/attack_simulation.py`     | Demonstrates HNDL defense |

---

## Risk Scoring Formula

```
QRS = (0.40 × A_score) + (0.35 × K_score) + (0.25 × S_score)

  A_score — Algorithm vulnerability to Shor's algorithm (0–10)
  K_score — Key strength against Grover's algorithm     (0–10)
  S_score — Data sensitivity / confidentiality horizon  (0–10)
```

---

## Lab Environment

| VM       | OS            | IP              | Role |
|---|---|---|---|
| Server   | Ubuntu 22.04  | 192.168.100.20  | Decision engine + crypto server |
| Client   | Ubuntu 22.04  | 192.168.100.30  | Asset scanner + secure client   |
| Attacker | Kali Linux    | 192.168.100.10  | Traffic interception simulation |

See [`docs/lab_setup.md`](docs/lab_setup.md) for full VM setup guide.

---

## References

1. Rubio García C. et al., *Enhanced Network Security Protocols for the Quantum Era*, IEEE JSAC vol. 43 no. 8, 2025.
2. NIST FIPS 203 — ML-KEM (Kyber)
3. NIST FIPS 204 — ML-DSA (Dilithium)
4. IETF RFC 8446 — TLS 1.3
5. IETF RFC 9370 — Multiple Key Exchanges in IKEv2
6. Open Quantum Safe — https://github.com/open-quantum-safe/liboqs

---

## Team

| Name | Role |
|---|---|
| Muthukumar T    | Risk Assessment Module & System Architecture |
| Priyadharshan V | Cryptographic Engine & PQC Integration       |
| Ram Prabhu K K  | Decision Engine & Attack Simulation          |

**Guide:** Ms. Sugitha Arumugam, Assistant Professor, Sri Krishna College of Technology
