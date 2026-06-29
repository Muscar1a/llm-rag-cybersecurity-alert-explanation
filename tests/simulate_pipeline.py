"""
Simulate the realtime Suricata+Zeek pipeline using tests/suricata_alerts.json.

Injects synthetic alerts into Redis without needing pcap or live Suricata/Zeek.
Consumer processes them and pushes results to alerts:results for Streamlit dashboard.

Usage:
    python tests/simulate_pipeline.py
    python tests/simulate_pipeline.py --delay 1.5 --limit 20
    python tests/simulate_pipeline.py --tactic Reconnaissance --delay 2.0
"""

import argparse
import json
import time
from pathlib import Path

import redis

REDIS_HOST = "localhost"
REDIS_PORT = 6379
SURICATA_QUEUE = "suricata:alerts:raw"
FLOW_TTL = 600  # seconds

INPUT = Path(__file__).parent / "suricata_alerts.json"


def _network_to_zeek_flow(network: dict) -> dict:
    return {
        "id.orig_h": network.get("src_ip", ""),
        "id.resp_h": network.get("dest_ip", ""),
        "id.resp_p": network.get("dest_port", 0),
        "proto": network.get("proto", ""),
        "conn_state": network.get("conn_state", ""),
        "history": network.get("history", ""),
        "duration": network.get("duration_s", 0),
        "orig_bytes": network.get("orig_bytes", 0),
        "resp_bytes": network.get("resp_bytes", 0),
        "orig_pkts": network.get("orig_pkts", 0),
        "resp_pkts": network.get("resp_pkts", 0),
        "service": network.get("service", ""),
    }


def _flow_key(event: dict) -> str:
    proto = str(event.get("proto", "tcp")).lower()
    return (
        f"zeek:flow:{proto}"
        f":{event.get('src_ip', '')}"
        f":{event.get('src_port', 0)}"
        f":{event.get('dest_ip', '')}"
        f":{event.get('dest_port', 0)}"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds between alerts (default: 0.5)")
    parser.add_argument("--limit", type=int, default=0, help="Max alerts to inject (0 = all)")
    parser.add_argument("--tactic", type=str, default="", help="Filter by ground truth tactic")
    parser.add_argument("--redis-host", type=str, default=REDIS_HOST)
    parser.add_argument("--redis-port", type=int, default=REDIS_PORT)
    args = parser.parse_args()

    r = redis.Redis(host=args.redis_host, port=args.redis_port, db=0)
    try:
        r.ping()
    except redis.ConnectionError:
        print(f"ERROR: Cannot connect to Redis at {args.redis_host}:{args.redis_port}")
        print("Make sure Redis is running: docker compose up -d redis")
        return

    data = json.loads(INPUT.read_text(encoding="utf-8"))

    if args.tactic:
        data = [d for d in data if d.get("_ground_truth", {}).get("label_tactic") == args.tactic]
        print(f"Filtered to tactic '{args.tactic}': {len(data)} alerts")

    if args.limit and len(data) > args.limit:
        data = data[:args.limit]

    queue_len = r.llen(SURICATA_QUEUE)
    if queue_len > 0:
        print(f"Warning: {SURICATA_QUEUE} already has {queue_len} pending items.")

    print(f"Injecting {len(data)} alerts into Redis (delay={args.delay}s)...")
    print("Start consumer in another terminal:")
    print("  $env:REDIS_HOST='localhost'; $env:API_URL='http://localhost:8000/analyze'; python -m src.realtime.consumer")
    print()

    for i, row in enumerate(data):
        event = row["suricata_event"]
        network = row["network"]
        tactic = row.get("_ground_truth", {}).get("label_tactic", "?")

        zeek_flow = _network_to_zeek_flow(network)
        key = _flow_key(event)
        r.setex(key, FLOW_TTL, json.dumps(zeek_flow))

        r.rpush(SURICATA_QUEUE, json.dumps(event))

        sig = event.get("alert", {}).get("signature", "?")
        dst = f"{event.get('dest_ip','?')}:{event.get('dest_port','?')}"
        print(f"[{i+1:>3}/{len(data)}] {tactic:<25} | {dst:<25} | {sig[:60]}")

        if args.delay > 0 and i < len(data) - 1:
            time.sleep(args.delay)

    print(f"\nDone. {len(data)} alerts queued in Redis.")
    print(f"Results will appear in alerts:results as consumer processes them.")
    print(f"Check count: docker exec redis redis-cli LLEN alerts:results")


if __name__ == "__main__":
    main()
