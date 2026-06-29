import json
from pathlib import Path

from src.realtime.alert_builder import build_combined_alert

INPUT = Path(__file__).parent / "suricata_alerts.json"
OUTPUT = Path(__file__).parent / "alerts.json"


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


def main():
    data = json.loads(INPUT.read_text(encoding="utf-8"))
    results = []

    for row in data:
        zeek_flow = _network_to_zeek_flow(row["network"])
        alert_text = build_combined_alert(row["suricata_event"], zeek_flow)

        results.append({
            "id": row["id"],
            "alert_text": alert_text,
            "network": row["network"],
            "_ground_truth": row["_ground_truth"],
        })

    OUTPUT.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Done. {len(results)} combined alerts written to {OUTPUT}")
    print(f"\nSample (id=0):\n{results[0]['alert_text']}")
    print(f"\nSample (id=30):\n{results[30]['alert_text']}")


if __name__ == "__main__":
    main()
