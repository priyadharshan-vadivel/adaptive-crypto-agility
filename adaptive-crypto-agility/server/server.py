"""
server.py
=========
Adaptive Crypto-Agility Server.

Listens for client connections. On each connection:
  1. Receives JSON asset profile from the client
  2. Evaluates quantum risk (risk_engine)
  3. Selects crypto mode (decision_engine)
  4. Executes the selected cryptographic handshake (crypto_comm)
  5. Exchanges a test encrypted message
  6. Returns the full decision result to the client

Run:
    python server/server.py [--host 0.0.0.0] [--port 9000]
"""

import sys
import os
import json
import socket
import logging
import argparse
import threading
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from risk_engine.decision_engine import decide_from_dict
from crypto_engine.crypto_comm import run_secure_communication

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [SERVER] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

LOG_FILE = os.path.join(os.path.dirname(__file__), "..", "logs", "server.log")


def _log_to_file(entry: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")


def _send(conn: socket.socket, data: dict):
    raw = json.dumps(data).encode("utf-8")
    # Prefix with 4-byte length
    conn.sendall(len(raw).to_bytes(4, "big") + raw)


def _recv(conn: socket.socket) -> dict:
    # Read 4-byte length prefix
    raw_len = b""
    while len(raw_len) < 4:
        chunk = conn.recv(4 - len(raw_len))
        if not chunk:
            raise ConnectionResetError("Client disconnected")
        raw_len += chunk
    msg_len = int.from_bytes(raw_len, "big")
    raw = b""
    while len(raw) < msg_len:
        chunk = conn.recv(min(4096, msg_len - len(raw)))
        if not chunk:
            raise ConnectionResetError("Client disconnected mid-message")
        raw += chunk
    return json.loads(raw.decode("utf-8"))


def handle_client(conn: socket.socket, addr: tuple):
    """Handle one client connection."""
    logger.info("Connection from %s:%d", *addr)
    try:
        # Step 1: Receive asset profile
        msg = _recv(conn)
        profile = msg.get("asset_profile", {})
        logger.info("Asset profile received: %s/%d-bit / %s",
                    profile.get("algorithm", "?"),
                    profile.get("key_size", 0),
                    profile.get("sensitivity", "?"))

        # Step 2: Evaluate risk + decide mode
        decision = decide_from_dict(profile)

        # Step 3: Execute crypto handshake
        comm_result = run_secure_communication(
            decision.mode,
            payload=f"Server→Client: session established [{decision.mode}]"
        )

        # Step 4: Build response
        response = {
            "status":      "OK",
            "timestamp":   datetime.utcnow().isoformat(),
            "decision":    decision.to_dict(),
            "comm": {
                "mode":            comm_result.mode,
                "sources":         comm_result.session_key.sources,
                "derivation_ms":   round(comm_result.session_key.derivation_time_ms, 3),
                "ciphertext_len":  len(comm_result.ciphertext),
                "success":         comm_result.success,
                "encrypted_msg":   comm_result.ciphertext.hex()[:64] + "...",
            },
        }

        _send(conn, response)

        # Log
        log_entry = {
            "ts":        datetime.utcnow().isoformat(),
            "client":    f"{addr[0]}:{addr[1]}",
            "algorithm": profile.get("algorithm"),
            "key_size":  profile.get("key_size"),
            "qrs":       decision.qrs,
            "risk":      decision.risk_class,
            "mode":      decision.mode,
        }
        _log_to_file(log_entry)
        logger.info(
            "Handled: QRS=%.2f | Risk=%s | Mode=%s | Comm=%s",
            decision.qrs, decision.risk_class, decision.mode,
            "✓" if comm_result.success else "✗",
        )

    except Exception as e:
        logger.error("Error handling client %s: %s", addr, e)
        try:
            _send(conn, {"status": "ERROR", "message": str(e)})
        except Exception:
            pass
    finally:
        conn.close()


def run_server(host: str = "0.0.0.0", port: int = 9000):
    """Start the adaptive crypto server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(10)
        logger.info("Adaptive Crypto-Agility Server listening on %s:%d", host, port)
        logger.info("Press Ctrl+C to stop.")

        while True:
            try:
                conn, addr = srv.accept()
                t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
                t.start()
            except KeyboardInterrupt:
                logger.info("Server shutting down.")
                break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Adaptive Crypto-Agility Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    args = parser.parse_args()
    run_server(args.host, args.port)
