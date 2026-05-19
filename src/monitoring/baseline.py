import json
import numpy as np
import pandas as pd
from pathlib import Path

EXCLUDE_COLS = {
    "Dst Port", "Src Port", "Protocol", "Label", 
    "Timestamp", "Flow ID", "Src IP", "Dst IP"
}

MIN_SAMPLES = 30

def _compute_stats(values: np.ndarray) -> dict:
    values = values[np.isfinite(values)]
    if len(values) == 0:
        return None
    median = float(np.median(values))
    mad = float(np.median(np.abs(values - median)))
    return {
        "median": median,
        "mad": mad,
        "p95": float(np.percentile(values, 95)),
        "p99": float(np.percentile(values, 99)),
        "n": int(len(values)),
    }
    
    
def _weighted_avg_stats(stats_list: list) -> dict:
    total_n = sum(s["n"] for s in stats_list)
    def wavg(key):
        return sum(s[key] * s["n"] for s in stats_list) / total_n
    return {
        "median": wavg("median"),
        "mad":    wavg("mad"),
        "p95":    wavg("p95"),
        "p99":    wavg("p99"),
        "n":      total_n,
    }


def _modified_z(value: float, stats: dict) -> float:
    if stats["mad"] == 0:
        return 0.0
    return 0.6745 * (value - stats["median"]) / stats["mad"]


class PortBaseline:
    def __init__(self, data: dict):
        self._data = data
    
    @classmethod
    def from_dataframe(cls, df: pd.DataFrame) -> "PortBaseline":
        numeric_cols = [
            c for c in df.select_dtypes(include="number").columns
            if c not in EXCLUDE_COLS
        ]

        data: dict = {}

        def _valid_stats(grp, col):
            vals = grp[col].dropna().values
            if len(vals) < MIN_SAMPLES:
                return None
            s = _compute_stats(vals)
            if s is None or s["p99"] == 0:
                return None
            return s

        for (proto, port), grp in df.groupby(["Protocol", "Dst Port"]):
            if len(grp) < MIN_SAMPLES:
                continue
            pk, ptk = str(int(proto)), str(int(port))
            port_stats = {col: s for col in numeric_cols if (s := _valid_stats(grp, col))}
            if port_stats:
                data.setdefault(pk, {})[ptk] = port_stats

        for proto, grp in df.groupby("Protocol"):
            if len(grp) < MIN_SAMPLES:
                continue
            pk = str(int(proto))
            fallback_stats = {col: s for col in numeric_cols if (s := _valid_stats(grp, col))}
            if fallback_stats:
                data.setdefault(pk, {})["_fallback"] = fallback_stats

        return cls(data)

    @classmethod
    def from_csv(cls, csv_path: str, label_col: str="Label", benign_label: str="Benign") -> "PortBaseline":
        df = pd.read_csv(csv_path, low_memory=False)
        df = df[df[label_col].str.strip() == benign_label]
        return cls.from_dataframe(df)
    
    @classmethod
    def merge(cls, baselines: list) -> "PortBaseline":
        merged: dict = {}
        all_protos = set(pk for b in baselines for pk in b._data)
        for proto in all_protos:
            merged[proto] = {}
            all_ports = set(pt for b in baselines for pt in b._data.get(proto, {}))
            for port in all_ports:
                all_features = set(
                    f for b in baselines
                    for f in b._data.get(proto, {}).get(port, {})
                )
                port_stats = {}
                for feature in all_features:
                    parts = [
                        b._data[proto][port][feature]
                        for b in baselines
                        if feature in b._data.get(proto, {}).get(port, {})
                    ]
                    if parts:
                        port_stats[feature] = _weighted_avg_stats(parts)
                if port_stats:
                    merged[proto][port] = port_stats
        return cls(merged)

    @classmethod
    def from_json(cls, path: str) -> "PortBaseline":
        with open(path) as f:
            return cls(json.load(f))
        
    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self._data, f, indent=2)
            
    def _lookup(self, proto: int, port: int, feature: str) -> dict | None:
        proto_data = self._data.get(str(proto), {})
        stats = proto_data.get(str(port), {}).get(feature)
        if stats:
            return stats
        return proto_data.get("_fallback", {}).get(feature)
    
    def annotate(self, proto: int, port: int, feature: str, value: float) -> str | None:
        stats = self._lookup(proto, port, feature)
        if stats is None:
            return None
        z = _modified_z(value, stats)
        if value > stats["p99"]:
            return f"{value} (>p99, z={z:.1f})"
        if value > stats["p95"]:
            return f"{value} (>p95, z={z:.1f})"
        if z < -2.5:
            return f"{value} (unusually low, z={z:.1f})"
        return None
        