"""
Generate data/demo.pcap from uwf-zeekdata24 CSV data.

Requires: pip install scapy
Output: data/demo.pcap  (for Suricata + Zeek pcap replay demo)

Usage:
    python tests/generate_pcap.py
"""
import csv
import random
import time
from pathlib import Path

try:
    from scapy.all import Ether, IP, TCP, UDP, wrpcap
except ImportError:
    raise SystemExit("Install scapy first:  pip install scapy")

INPUT_DIR = Path("data/test_data/uwf-zeekdata24")
OUTPUT = Path("data/demo.pcap")

# (tactic, ports_to_target, flows_to_generate)
TACTIC_CONFIG = [
    ("Reconnaissance",   [22, 21, 25, 80, 110, 111, 139, 443, 445], 4),
    ("Credential_Access", [4848, 22],                                 4),
    ("Initial_Access",   [445, 80],                                   3),
    ("Defense_Evasion",  [445, 139],                                  3),
    ("Exfiltration",     [445],                                       3),
    ("Benign",           [80, 443, 53],                               3),
]

MAC_A = "de:ad:be:ef:00:01"
MAC_B = "de:ad:be:ef:00:02"

random.seed(42)


def _to_int(v, default=0):
    try:
        return int(float(v or default))
    except (ValueError, TypeError):
        return default


def load_ip_pairs(tactic: str, n: int) -> list[tuple[str, str]]:
    path = INPUT_DIR / tactic
    csvs = list(path.glob("*.csv")) if path.is_dir() else []
    pairs = []
    if csvs:
        with open(csvs[0], encoding="utf-8") as f:
            for row in csv.DictReader(f):
                src = (row.get("src_ip_zeek") or "").strip()
                dst = (row.get("dest_ip_zeek") or "").strip()
                if src and dst and src != dst:
                    pairs.append((src, dst))
                if len(pairs) >= n * 4:
                    break
    if not pairs:
        pairs = [("10.0.0.50", "192.168.1.100")]
    return random.sample(pairs, min(n, len(pairs)))


def make_tcp_syn(src_ip: str, dst_ip: str, dport: int, ts: float) -> list:
    sport = random.randint(10000, 60000)
    pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src=src_ip, dst=dst_ip) / \
          TCP(sport=sport, dport=dport, flags="S", seq=random.randint(1000, 99999))
    pkt.time = ts
    return [pkt]


def make_tcp_flow(src_ip: str, dst_ip: str, dport: int, ts: float) -> list:
    sport = random.randint(10000, 60000)
    isn_a = random.randint(1000, 99999)
    isn_b = random.randint(1000, 99999)
    pkts = [
        Ether(src=MAC_A, dst=MAC_B) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="S",  seq=isn_a),
        Ether(src=MAC_B, dst=MAC_A) / IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=sport, flags="SA", seq=isn_b, ack=isn_a + 1),
        Ether(src=MAC_A, dst=MAC_B) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="A",  seq=isn_a + 1, ack=isn_b + 1),
        Ether(src=MAC_A, dst=MAC_B) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=dport, flags="FA", seq=isn_a + 1, ack=isn_b + 1),
    ]
    for i, p in enumerate(pkts):
        p.time = ts + i * 0.002
    return pkts


def make_udp_pkt(src_ip: str, dst_ip: str, dport: int, ts: float) -> list:
    sport = random.randint(10000, 60000)
    pkt = Ether(src=MAC_A, dst=MAC_B) / IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport)
    pkt.time = ts
    return [pkt]


def main():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    all_pkts = []
    ts = time.time() - 3600.0
    counts = {}

    for tactic, ports, n_flows in TACTIC_CONFIG:
        pairs = load_ip_pairs(tactic, n_flows)
        for i, (src_ip, dst_ip) in enumerate(pairs):
            dport = ports[i % len(ports)]

            if tactic == "Reconnaissance":
                # Sweep all configured ports → triggers port sweep rule
                for p in ports:
                    all_pkts.extend(make_tcp_syn(src_ip, dst_ip, p, ts))
                    ts += 0.03
            elif dport == 53:
                all_pkts.extend(make_udp_pkt(src_ip, dst_ip, dport, ts))
                ts += 0.05
            else:
                all_pkts.extend(make_tcp_flow(src_ip, dst_ip, dport, ts))
                ts += 0.2

            counts[tactic] = counts.get(tactic, 0) + 1

    all_pkts.sort(key=lambda p: p.time)
    wrpcap(str(OUTPUT), all_pkts)

    print(f"Written {len(all_pkts)} packets ({sum(counts.values())} flows) → {OUTPUT}")
    print(f"File size: {OUTPUT.stat().st_size / 1024:.1f} KB\n")
    print("Flows per tactic:")
    for tactic, _, _ in TACTIC_CONFIG:
        if tactic in counts:
            print(f"  {tactic:<30} {counts[tactic]}")


if __name__ == "__main__":
    main()
