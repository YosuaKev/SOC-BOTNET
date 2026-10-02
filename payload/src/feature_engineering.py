#!/usr/bin/env python3
import numpy as np
import pandas as pd


def number(value, default=0.0):
    try:
        if value is None:
            return default
        value = float(value)
        return value if np.isfinite(value) else default
    except (TypeError, ValueError):
        return default


def nonnegative(value):
    return max(number(value), 0.0)


def safe_divide(numerator, denominator):
    numerator = number(numerator)
    denominator = number(denominator)
    if denominator <= 0:
        return 0.0
    result = numerator / denominator
    return result if np.isfinite(result) else 0.0


def port_category(value):
    try:
        port = int(float(value))
    except (TypeError, ValueError):
        return "unknown"
    if 0 <= port <= 1023:
        return "well_known"
    if 1024 <= port <= 49151:
        return "registered"
    if 49152 <= port <= 65535:
        return "ephemeral"
    return "unknown"


def clean_category(value):
    if value is None:
        return "unknown"
    value = str(value).strip()
    return value if value else "unknown"


def build_features(record, active_features, numeric_features, categorical_features):
    duration_missing = int(record.get("duration") is None)
    orig_bytes_missing = int(record.get("orig_bytes") is None)
    resp_bytes_missing = int(record.get("resp_bytes") is None)

    duration = nonnegative(record.get("duration"))
    orig_bytes = nonnegative(record.get("orig_bytes"))
    resp_bytes = nonnegative(record.get("resp_bytes"))
    orig_pkts = nonnegative(record.get("orig_pkts"))
    resp_pkts = nonnegative(record.get("resp_pkts"))
    orig_ip_bytes = nonnegative(record.get("orig_ip_bytes"))
    resp_ip_bytes = nonnegative(record.get("resp_ip_bytes"))
    src_port = number(record.get("id.orig_p"))
    dst_port = number(record.get("id.resp_p"))
    dst_port_numeric = min(max(dst_port, 0.0), 65535.0)

    total_pkts = orig_pkts + resp_pkts
    total_bytes = orig_bytes + resp_bytes
    total_ip_bytes = orig_ip_bytes + resp_ip_bytes

    packet_ratio = safe_divide(orig_pkts, resp_pkts)
    byte_ratio = safe_divide(orig_bytes, resp_bytes)
    ip_byte_ratio = safe_divide(orig_ip_bytes, resp_ip_bytes)

    orig_bytes_per_pkt = safe_divide(orig_bytes, orig_pkts)
    resp_bytes_per_pkt = safe_divide(resp_bytes, resp_pkts)
    total_bytes_per_pkt = safe_divide(total_bytes, total_pkts)

    packets_per_sec = safe_divide(total_pkts, duration)
    bytes_per_sec = safe_divide(total_bytes, duration)
    orig_packets_per_sec = safe_divide(orig_pkts, duration)
    resp_packets_per_sec = safe_divide(resp_pkts, duration)

    packet_difference = orig_pkts - resp_pkts
    byte_difference = orig_bytes - resp_bytes

    proto = clean_category(record.get("proto")).lower()
    conn_state = clean_category(record.get("conn_state"))
    history = clean_category(record.get("history"))

    features = {
        "duration": duration,
        "dst_port": dst_port_numeric,
        "orig_bytes": orig_bytes,
        "resp_bytes": resp_bytes,
        "orig_pkts": orig_pkts,
        "resp_pkts": resp_pkts,
        "orig_ip_bytes": orig_ip_bytes,
        "resp_ip_bytes": resp_ip_bytes,
        "total_pkts": total_pkts,
        "total_bytes": total_bytes,
        "total_ip_bytes": total_ip_bytes,
        "packet_ratio": packet_ratio,
        "byte_ratio": byte_ratio,
        "ip_byte_ratio": ip_byte_ratio,
        "orig_bytes_per_pkt": orig_bytes_per_pkt,
        "resp_bytes_per_pkt": resp_bytes_per_pkt,
        "total_bytes_per_pkt": total_bytes_per_pkt,
        "packets_per_sec": packets_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "orig_packets_per_sec": orig_packets_per_sec,
        "resp_packets_per_sec": resp_packets_per_sec,
        "packet_difference": packet_difference,
        "byte_difference": byte_difference,
        "duration_missing": duration_missing,
        "orig_bytes_missing": orig_bytes_missing,
        "resp_bytes_missing": resp_bytes_missing,
        "log1p_duration": np.log1p(duration),
        "log1p_orig_bytes": np.log1p(orig_bytes),
        "log1p_resp_bytes": np.log1p(resp_bytes),
        "log1p_orig_pkts": np.log1p(orig_pkts),
        "log1p_resp_pkts": np.log1p(resp_pkts),
        "log1p_total_bytes": np.log1p(total_bytes),
        "log1p_total_pkts": np.log1p(total_pkts),
        "log1p_total_ip_bytes": np.log1p(total_ip_bytes),
        "log1p_packets_per_sec": np.log1p(max(packets_per_sec, 0.0)),
        "log1p_bytes_per_sec": np.log1p(max(bytes_per_sec, 0.0)),
        "proto": proto,
        "conn_state": conn_state,
        "history": history,
        "src_port_category": port_category(src_port),
        "dst_port_category": port_category(dst_port),
    }

    missing = [f for f in active_features if f not in features]
    if missing:
        raise RuntimeError(f"Missing engineered features: {missing}")

    df = pd.DataFrame([{f: features[f] for f in active_features}])

    for column in numeric_features:
        df[column] = (
            pd.to_numeric(df[column], errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0.0)
            .astype(np.float32)
        )

    for column in categorical_features:
        df[column] = df[column].astype("string").fillna("unknown")

    return df
