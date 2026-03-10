"""
benchmark.py
============
Performance Benchmarking

Measures execution time for each cryptographic mode across multiple runs
and produces a summary table — useful for the Experimental Results section
of the academic report.

Run:
    python scripts/benchmark.py
"""

import sys
import os
import time
import statistics

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from crypto_engine.hybrid_combiner import run_secure_communication

MODES = ["CLASSICAL", "HYBRID", "TRIPLE_HYBRID"]
RUNS = 10
MESSAGE = "Benchmark payload — fixed length for fair comparison."


def benchmark_mode(mode: str, runs: int = RUNS) -> dict:
    times = []
    for _ in range(runs):
        t0 = time.monotonic()
        result = run_secure_communication(mode, MESSAGE)
        elapsed = (time.monotonic() - t0) * 1000
        assert result["success"], f"Crypto failure in {mode}"
        times.append(elapsed)
    return {
        "mode": mode,
        "runs": runs,
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "stdev_ms": statistics.stdev(times) if runs > 1 else 0.0,
        "min_ms": min(times),
        "max_ms": max(times),
    }


def main():
    print("\n" + "=" * 65)
    print("  PERFORMANCE BENCHMARK")
    print("  Adaptive Crypto-Agility Decision System")
    print(f"  Runs per mode: {RUNS}")
    print("=" * 65)

    results = []
    for mode in MODES:
        print(f"  Benchmarking {mode}...", end=" ", flush=True)
        r = benchmark_mode(mode, RUNS)
        results.append(r)
        print(f"done  ({r['mean_ms']:.2f} ms avg)")

    print("\n")
    print(f"  {'Mode':<15} {'Mean (ms)':>10} {'Median':>10} {'StdDev':>10} {'Min':>8} {'Max':>8}")
    print(f"  {'-'*15} {'-'*10} {'-'*10} {'-'*10} {'-'*8} {'-'*8}")
    for r in results:
        print(f"  {r['mode']:<15} {r['mean_ms']:>10.3f} {r['median_ms']:>10.3f} "
              f"{r['stdev_ms']:>10.3f} {r['min_ms']:>8.3f} {r['max_ms']:>8.3f}")

    print()
    print("  Note: Times include key exchange, HKDF derivation, and AES-256-GCM")
    print("  encryption/decryption. Network round-trip NOT included (local sim).")
    print("  In real TLS 1.3: QKD adds ~48 ms handshake overhead (Rubio García 2025).")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
