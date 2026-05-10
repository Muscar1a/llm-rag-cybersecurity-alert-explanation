import argparse
import csv
import json
import sys
from datetime import datetime

PROTO = {6: "TCP", 17: "UDP", 1: "ICMP", 0: "Unknown"}

SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
}

WIN_OS = {
    65535: "Windows", 64240: "Windows 10/11",
    29200: "Linux", 5840: "Linux (older)", 14600: "Linux",
    32768: "macOS", 8192: "non-standard/custom stack",
}

def get_float(row, col, default=0.0):
    try:
        v = float(row.get(col, default))
        return v if v == v else default  # NaN check (simpler)
    except (ValueError, TypeError):
        return default

def get_int(row, col, default=0):
    return int(get_float(row, col, default))




def build_alert_text(row: dict) -> str:
    parts = []
    
    dst_port = get_int(row, "Dst Port")
    proto_num = int(get_float(row, "Protocol"))
    proto = PROTO.get(proto_num, f"proto-{proto_num}")
    service = SERVICES.get(dst_port)
    port_str = f"port {dst_port}/{service}" if service else f"port {dst_port}"
    parts.append(f"{proto} flow on {port_str}")
    
    fwd_pkts = get_int(row, "Tot Fwd Pkts")
    bwd_pkts = get_int(row, "Tot Bwd Pkts")
    fwd_bytes = get_float(row, "TotLen Fwd Pkts")
    bwd_bytes = get_float(row, "TotLen Bwd Pkts")
    total_pkts = fwd_pkts + bwd_pkts
    ratio = round(bwd_bytes / fwd_bytes, 2) if fwd_bytes > 0 else None
    
    parts.append(
        f"Volume: {total_pkts} packets total "
        f"({fwd_pkts} forward / {bwd_pkts} backward), "
        f"{int(fwd_bytes + bwd_bytes)} bytes total "
        f"({int(fwd_bytes)} B sent, {int(bwd_bytes)} B received)."
    )
    
    if ratio is not None:
        direction = (
            "heavily server-dominant" if ratio > 5 else
            "server-dominant" if ratio > 2 else
            "balanced" if ratio > 0.5 else
            "client-dominant"
        )
        parts.append(f"Byte ratio received/sent: {ratio}x ({direction}).")
 
    
    dur_us = get_float(row, "Flow Duration")
    dur_s = dur_us / 1e6
    dur_str = (
        f"{round(dur_s * 1000, 1)} ms" if dur_s < 1
        else f"{round(dur_s, 2)} s" if dur_s < 60
        else f"{round(dur_s / 60, 1)} min"
    )
    parts.append(f"Duration: {dur_str}.")
    
    iat_mean_us = get_float(row, "Flow IAT Mean")
    iat_std_us = get_float(row, "Flow IAT Std")
    iat_max_us = get_float(row, "Flow IAT Max")
    fwd_iat_max_us = get_float(row, "Fwd IAT Max")
    fwd_iat_mean_us = get_float(row, "Fwd IAT Mean")
    
    if iat_mean_us > 0:
        iat_parts = [
            f"mean {round(iat_mean_us / 1000, 1)} ms",
            f"std {round(iat_std_us / 1000, 1)} ms",
            f"max {round(iat_max_us / 1000, 1)} ms",
        ]
        parts.append(f"Inter-arrival time (IAT): {', '.join(iat_parts)}.")
 
    if fwd_iat_max_us > 0:
        parts.append(
            f"Forward IAT: mean {round(fwd_iat_mean_us / 1000, 1)} ms, "
            f"max {round(fwd_iat_max_us / 1000, 1)} ms."
        )
        
    
    fwd_max = get_float(row, "Fwd Pkt Len Max")
    fwd_min = get_float(row, "Fwd Pkt Len Min")
    fwd_std = get_float(row, "Fwd Pkt Len Std")
    bwd_max = get_float(row, "Bwd Pkt Len Max")
    bwd_min = get_float(row, "Bwd Pkt Len Min")
    bwd_std = get_float(row, "Bwd Pkt Len Std")
    
    parts.append(
        f"Forward packet sizes: min {int(fwd_min)} B, max {int(fwd_max)} B, "
        f"std {round(fwd_std, 1)} B. "
        f"Backward packet sizes: min {int(bwd_min)} B, max {int(bwd_max)} B, "
        f"std {round(bwd_std, 1)} B."
    )
    
    flag_map = [
        ("SYN Flag Cnt", "SYN"), ("ACK Flag Cnt", "ACK"),
        ("PSH Flag Cnt", "PSH"), ("FIN Flag Cnt", "FIN"),
        ("RST Flag Cnt", "RST"), ("URG Flag Cnt", "URG"),
        ("ECE Flag Cnt", "ECE"), ("CWE Flag Count", "CWE"),
    ]
    flags_set = [
        f"{name}x{get_int(row, col)}"
        for col, name in flag_map
        if get_int(row, col) > 0
    ]
    if flags_set:
        parts.append(f"TCP flags: {', '.join(flags_set)}.")
    else:
        parts.append("TCP flags: none set.")
        
    init_fwd_win = get_int(row, "Init Fwd Win Byts")
    init_bwd_win = get_int(row, "Init Bwd Win Byts")
    seg_min = get_int(row, "Fwd Seg Size Min")
    
    win_parts = []
    if init_fwd_win > 0:
        os_guess = WIN_OS.get(init_fwd_win, "unknown OS")
        win_parts.append(f"client init window {init_fwd_win} B ({os_guess})")
    if init_bwd_win > 0:
        win_parts.append(f"server init window {init_bwd_win} B")
    if win_parts:
        parts.append(f"TCP window: {'; '.join(win_parts)}.")
 
    if seg_min > 0:
        parts.append(f"Minimum forward segment size: {seg_min} B.")
 
    return " ".join(parts)


def build_metadata(row: dict) -> dict:
    dst_port = get_int(row, "Dst Port")
    proto_num = int(get_float(row, "Protocol"))
    
    
    return {
        "dst_port":    dst_port,
        "service":     SERVICES.get(dst_port), 
        "protocol":    PROTO.get(proto_num, f"proto-{proto_num}"),
        "duration_s":  round(get_float(row, "Flow Duration") / 1e6, 6),
        "total_pkts":  get_int(row, "Tot Fwd Pkts") + get_int(row, "Tot Bwd Pkts"),
        "total_bytes": int(get_float(row, "TotLen Fwd Pkts") + get_float(row, "TotLen Bwd Pkts")),
        "init_fwd_win": get_int(row, "Init Fwd Win Byts"),
    }
    
    
def process_row(row: dict) -> dict:
    return {
        "text": build_alert_text(row),
        "metadata": build_metadata(row),
    }


if __name__ == "__main__":
    try:
        import pandas as _pd, os as _os, sys as _sys

        _csv_path = _os.path.join("E:/Uni/BigProject/data/raw/cse-cic-ids2018", "combined_shorten.csv")
        if not _os.path.exists(_csv_path):
            print("Test CSV not found:", _csv_path)
            _sys.exit(1)

        _df = _pd.read_csv(_csv_path, low_memory=False)

        print("Running quick alert tests on first 3 rows of combined_shorten.csv using process_row()")
        for idx, _r in _df.head(3).iterrows():
            row_dict = _r.to_dict()
            result = process_row(row_dict)
            print("\n--- Record", idx, "---")
            print(result.get("text"))

    except Exception as _e:
        print("Error during test run:", _e)
