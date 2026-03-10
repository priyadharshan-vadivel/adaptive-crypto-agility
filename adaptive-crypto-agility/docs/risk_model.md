# Quantum Risk Assessment Model

## Formula

```
QRS = (0.40 × A_score) + (0.35 × K_score) + (0.25 × S_score)
```

## Score Definitions

### A_score — Algorithm Vulnerability (Shor's Algorithm)
| Algorithm | A_score | Reason |
|---|---|---|
| RSA | 10 | Fully broken by Shor |
| ECC, ECDH | 9 | Fully broken by Shor |
| AES-128 | 4 | Grover reduces to ~64-bit |
| AES-256 | 2 | Grover reduces to ~128-bit (still secure) |
| ML-KEM (Kyber) | 0 | Quantum-resistant (NIST FIPS 203) |
| ML-DSA (Dilithium) | 0 | Quantum-resistant (NIST FIPS 204) |

### K_score — Key Strength (Grover's Algorithm)
| Key Size | Algorithm | K_score |
|---|---|---|
| < 1024 bits | RSA/DH | 10 (classically broken) |
| 1024–2047 bits | RSA/DH | 9 |
| 2048 bits | RSA/DH | 7 |
| 256 bits | ECC | 7 |
| 128 bits | AES | 6 |
| 256 bits | AES | 2 |
| ML-KEM-1024 | PQ KEM | 0 |

### S_score — Data Sensitivity
| Level | Examples | S_score |
|---|---|---|
| Low | Public data, ephemeral sessions | 2 |
| Medium | Business data, PII, <5 year horizon | 5 |
| High | Government, healthcare, 10+ year horizon | 9 |

## Classification
| QRS Range | Class | Action |
|---|---|---|
| 0.0 – 3.0 | LOW | No immediate action. Classical crypto acceptable. |
| 3.1 – 6.0 | MEDIUM | Migrate within 12–24 months. Deploy Hybrid mode. |
| 6.1 – 10.0 | HIGH | Immediate migration. Deploy Triple-Hybrid mode. |
