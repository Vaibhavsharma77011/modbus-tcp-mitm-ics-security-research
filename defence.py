#!/usr/bin/env python3
"""
Modbus TCP Anomaly Detector — Defense Script
Monitors Modbus traffic and detects MITM/spoofing attacks.
Run this on the Factory IO machine or network tap.
"""
import socket
import threading
import struct
import os
import sys
import time
from datetime import datetime
from collections import deque

if os.geteuid() != 0:
    print("[-] Root required. Run with sudo.")
    sys.exit(1)

# ─── CONFIG ───────────────────────────────────────────
LISTEN_IP       = "0.0.0.0"
LISTEN_PORT     = 503
FORWARD_IP      = "127.0.0.1"   # Actual Factory IO (if chaining)
FORWARD_PORT    = 5030

ALERT_THRESHOLD = 3             # Consecutive suspicious packets before alert
LOG_FILE        = "anomaly_log.txt"
# ──────────────────────────────────────────────────────

# State tracking
sensor_history   = deque(maxlen=10)   # Last 10 sensor values
alert_count      = 0
packet_count     = 0
spoof_detected   = False


def log(msg: str, level: str = "INFO"):
    """Log to console and file"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def analyze_fc2_response(data: bytes) -> dict:
    """
    Analyze FC=2 response for anomalies.
    Returns dict with analysis results.
    """
    result = {
        "is_fc2"      : False,
        "sensor_value": None,
        "suspicious"  : False,
        "reason"      : ""
    }

    if len(data) < 10:
        return result

    try:
        fc = data[7]
        if fc != 2:
            return result

        result["is_fc2"] = True
        sensor_byte = data[9]
        result["sensor_value"] = sensor_byte

        # Rule 1: Unexpected 0xFF value
        # Normal discrete input = 0x00 or 0x01 only
        if sensor_byte not in [0x00, 0x01]:
            result["suspicious"] = True
            result["reason"] = f"Abnormal sensor byte: 0x{sensor_byte:02X} (expected 0x00 or 0x01)"
            return result

        # Rule 2: Rapid 0→1 transitions (sensor value flipping too fast)
        sensor_history.append(sensor_byte)
        if len(sensor_history) >= 4:
            transitions = sum(
                1 for i in range(1, len(sensor_history))
                if sensor_history[i] != sensor_history[i-1]
            )
            if transitions >= 3:
                result["suspicious"] = True
                result["reason"] = f"Rapid sensor transitions detected: {list(sensor_history)}"
                return result

        # Rule 3: Sensor stuck at 1 for too long
        # (Real sensor should sometimes read 0 when box passes)
        if len(sensor_history) >= 8 and all(v == 1 for v in sensor_history):
            result["suspicious"] = True
            result["reason"] = "Sensor stuck at 1 — possible spoofing!"
            return result

    except Exception as e:
        log(f"Analysis error: {e}", "ERROR")

    return result


def process_packet(data: bytes, src_addr) -> None:
    """Process and analyze each packet"""
    global alert_count, packet_count, spoof_detected

    packet_count += 1

    if len(data) < 8:
        return

    fc = data[7]
    analysis = analyze_fc2_response(data)

    if analysis["is_fc2"]:
        sv = analysis["sensor_value"]
        log(f"FC=2 Response | Sensor={sv} | From={src_addr}")

        if analysis["suspicious"]:
            alert_count += 1
            log(f"⚠️  ANOMALY DETECTED! Reason: {analysis['reason']}", "ALERT")
            log(f"⚠️  Raw packet: {data.hex()}", "ALERT")

            if alert_count >= ALERT_THRESHOLD and not spoof_detected:
                spoof_detected = True
                log("🚨 MITM ATTACK CONFIRMED! Sensor spoofing in progress!", "CRITICAL")
                log(f"🚨 Suspicious source: {src_addr}", "CRITICAL")
                log("🚨 Action: Block traffic from this IP!", "CRITICAL")
        else:
            alert_count = 0   # Reset on clean packet


def monitor_connection(conn: socket.socket, addr) -> None:
    """Monitor incoming Modbus traffic"""
    log(f"Connection from {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            process_packet(data, addr)
    except Exception as e:
        log(f"Connection error: {e}", "ERROR")
    finally:
        conn.close()
        log(f"Connection closed: {addr}")


def print_stats():
    """Print stats every 30 seconds"""
    while True:
        time.sleep(30)
        log(f"--- STATS | Packets: {packet_count} | Alerts: {alert_count} | MITM: {spoof_detected} ---")


def main():
    log("=" * 60)
    log("  Modbus TCP Anomaly Detector — DEFENSE MODE")
    log(f"  Listening on {LISTEN_IP}:{LISTEN_PORT}")
    log(f"  Log file: {LOG_FILE}")
    log("=" * 60)

    # Stats thread
    stats_thread = threading.Thread(target=print_stats, daemon=True)
    stats_thread.start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_IP, LISTEN_PORT))
    server.listen(5)

    log(f"Monitoring started. Waiting for Modbus connections...")

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(
                target=monitor_connection,
                args=(conn, addr),
                daemon=True
            )
            t.start()
        except KeyboardInterrupt:
            log("Monitoring stopped by user.")
            break

    server.close()


if __name__ == "__main__":
    main()
