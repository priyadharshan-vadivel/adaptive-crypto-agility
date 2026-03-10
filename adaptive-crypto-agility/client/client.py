"""
client.py
=========
Adaptive Crypto-Agility Client.

  1. Scans or accepts a cryptographic asset profile
  2. Sends the profile to the server
  3. Receives mode decision + comm result from server
  4. Displays the full adaptive security outcome

Run:
    python client/client.py [--host 192.168.100.20] [--port 9000] [--preset high]
"""

import sys
import os
import json
import socket
import logging
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from client.asset_scanner import build_manual_profile, SAMPLE_ENTERPRISE_ASSETS

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [CLIENT] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

# Preset asset profiles for easy demo
PRESETS = {
    "low":    {"algorithm": "AES-256", "key_size": 256,  "sensitivity": "low",    "description": "Low-risk symmetric asset"},
    "medium": {"algorithm": "ECC",     "key_size": 256,  "sensitivity": "medium", "description": "Medium-risk ECC key"},
    "high":   {"algorithm": "RSA",     "key_size": 2048, "sensitivity": "high",   "description": "High-risk RSA-2048 cert"},
    "legacy": {"algorithm": "RSA",     "key_size": 1024, "sensitivity": "high",   "description": "Critical legacy RSA-1024"},
}


def _send(conn: socket.socket, data: dict):
    raw = json.dumps(data).encode("utf-8")
    conn.sendall(len(raw).to_bytes(4, "big") + raw)


def _recv(conn: socket.socket) -> dict:
    raw_len = b""
    while len(raw_len) < 4:
        chunk = conn.recv(4 - len(raw_len))
        if not chunk:
            raise ConnectionResetError("Server disconnected")
        raw_len += chunk
    msg_len = int.from_bytes(raw_len, "big")
    raw = b""
    while len(raw) < msg_len:
        chunk = conn.recv(min(4096, msg_len - len(raw)))
        if not chunk:
            raise ConnectionResetError("Server disconnected mid-message")
        raw += chunk
    return json.loads(raw.decode("utf-8"))


def _print_result(response: dict):
    d = response.get("decision", {})
    c = response.get("comm", {})
    risk = d.get("risk", {})
    dec  = d.get("decision", {})
    scores = risk.get("scores", {})

    print("\n" + "=" * 62)
    print("  ADAPTIVE CRYPTO-AGILITY — SERVER RESPONSE")
    print("=" * 62)
    asset = risk.get("asset", {})
    print(f"  Asset       : {asset.get('description', asset.get('algorithm'))}")
    print(f"  Algorithm   : {asset.get('algorithm')}/{asset.get('key_size')}-bit")
    print(f"  Sensitivity : {asset.get('sensitivity', '').upper()}")
    print()
    print(f"  A_score     : {scores.get('algorithm', '?')} (Shor vulnerability)")
    print(f"  K_score     : {scores.get('key_strength', '?')} (Grover vulnerability)")
    print(f"  S_score     : {scores.get('sensitivity', '?')} (Data sensitivity)")
    print(f"  ─────────────────────────────────────────")
    print(f"  QRS         : {scores.get('qrs', '?')} → Risk: {risk.get('risk_class', '?')}")
    print()
    print(f"  Mode        : {dec.get('mode', '?')}")
    print(f"  QR-Safe     : {'YES ✓' if dec.get('quantum_resistant') else 'NO ✗'}")
    print(f"  Algorithms  : {', '.join(dec.get('algorithms', []))}")
    print(f"  Secrets     : {dec.get('secrets_combined', '?')} combined via HKDF-SHA256")
    print()
    print(f"  Rationale   : {dec.get('rationale', '')}")
    print()
    print(f"  Comm status : {'SUCCESS ✓' if c.get('success') else 'FAILED ✗'}")
    print(f"  Key sources : {', '.join(c.get('sources', []))}")
    print(f"  Deriv. time : {c.get('derivation_ms', '?')} ms")
    print(f"  CT sample   : {c.get('encrypted_msg', '')}")
    print("=" * 62)


def run_client(host: str, port: int, profile: dict):
    logger.info("Connecting to server %s:%d", host, port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(15)
            s.connect((host, port))
            logger.info("Connected. Sending asset profile: %s/%d-bit",
                        profile.get("algorithm"), profile.get("key_size"))
            _send(s, {"asset_profile": profile})
            response = _recv(s)

        if response.get("status") == "OK":
            _print_result(response)
        else:
            logger.error("Server error: %s", response.get("message"))

    except ConnectionRefusedError:
        logger.error("Cannot connect to %s:%d — is the server running?", host, port)
    except Exception as e:
        logger.error("Client error: %s", e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adaptive Crypto-Agility Client")
    parser.add_argument("--host",    default="127.0.0.1", help="Server IP")
    parser.add_argument("--port",    type=int, default=9000)
    parser.add_argument("--preset",  choices=list(PRESETS.keys()),
                        default="high", help="Use a preset asset profile")
    parser.add_argument("--algo",    help="Override algorithm (e.g. RSA, ECC, AES-256)")
    parser.add_argument("--keysize", type=int, help="Override key size in bits")
    parser.add_argument("--sens",    choices=["low", "medium", "high"],
                        help="Override sensitivity level")
    args = parser.parse_args()

    # Build profile
    profile = dict(PRESETS[args.preset])
    if args.algo:    profile["algorithm"]   = args.algo.upper()
    if args.keysize: profile["key_size"]    = args.keysize
    if args.sens:    profile["sensitivity"] = args.sens

    print(f"\n[*] Profile: {profile['algorithm']}/{profile['key_size']}-bit | Sensitivity: {profile['sensitivity']}")
    run_client(args.host, args.port, profile)
