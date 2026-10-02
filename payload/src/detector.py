#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from feature_engineering import build_features

BASE_DIR = Path("/opt/zeek-botnet-detector")
MODEL_FILE = BASE_DIR / "models" / "rf_official_bro_final_pipeline.joblib"
CONFIG_FILE = BASE_DIR / "models" / "zeek_official_active_feature_config.pkl"
DETECTION_LOG = BASE_DIR / "logs" / "detections.jsonl"
ALERT_LOG = BASE_DIR / "logs" / "botnet_alerts.jsonl"
THRESHOLD = 0.50
POLL_INTERVAL = 0.25


def safe_int(value, default=-1):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_ignore_service(value):
    value = str(value).strip()
    if value.startswith("["):
        end = value.find("]")
        if end < 0 or end + 1 >= len(value) or value[end + 1] != ":":
            raise ValueError(f"invalid ignored service: {value}")
        host = value[1:end]
        port_text = value[end + 2 :]
    else:
        if ":" not in value:
            raise ValueError(f"ignored service must be HOST:PORT: {value}")
        host, port_text = value.rsplit(":", 1)
    port = int(port_text)
    if not host or not 0 <= port <= 65535:
        raise ValueError(f"invalid ignored service: {value}")
    return host, port


parser = argparse.ArgumentParser()
parser.add_argument("--conn-log", required=True, help="Path to Zeek JSON conn.log")
parser.add_argument("--from-start", action="store_true", help="Process existing log contents too")
parser.add_argument(
    "--ignore-service",
    action="append",
    default=[],
    metavar="HOST:PORT",
    help="Skip ML inference and all ML logging when either Zeek endpoint exactly matches HOST:PORT. Repeatable.",
)
args = parser.parse_args()
CONN_LOG = Path(args.conn_log)
try:
    IGNORED_SERVICES = {parse_ignore_service(value) for value in args.ignore_service}
except (ValueError, TypeError) as exc:
    parser.error(str(exc))

model = joblib.load(MODEL_FILE)
config = joblib.load(CONFIG_FILE)
ACTIVE_FEATURES = list(config["active_feature_columns"])
NUMERIC_FEATURES = list(config["active_numeric_features"])
CATEGORICAL_FEATURES = list(config["active_categorical_features"])
assert len(ACTIVE_FEATURES) == 40
preprocessor = model.named_steps["preprocessor"]
assert len(preprocessor.get_feature_names_out()) == 433
classes = np.asarray(model.classes_)
pos = np.where(classes == 1)[0]
if len(pos) != 1:
    raise RuntimeError(f"Unexpected model classes: {classes}")
POSITIVE_INDEX = int(pos[0])

DETECTION_LOG.parent.mkdir(parents=True, exist_ok=True)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def write_json_line(path, data):
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()


def is_ignored_connection(record):
    if not IGNORED_SERVICES:
        return False
    orig = (str(record.get("id.orig_h") or ""), safe_int(record.get("id.orig_p")))
    resp = (str(record.get("id.resp_h") or ""), safe_int(record.get("id.resp_p")))
    return orig in IGNORED_SERVICES or resp in IGNORED_SERVICES


def predict_connection(record):
    X = build_features(
        record=record,
        active_features=ACTIVE_FEATURES,
        numeric_features=NUMERIC_FEATURES,
        categorical_features=CATEGORICAL_FEATURES,
    )
    if list(X.columns) != ACTIVE_FEATURES:
        raise RuntimeError("Feature order mismatch")
    probability = float(model.predict_proba(X)[0][POSITIVE_INDEX])
    prediction = "BOTNET" if probability >= THRESHOLD else "NORMAL"
    return {
        "processed_at_utc": utc_now(),
        "zeek_ts": record.get("ts"),
        "uid": record.get("uid"),
        "src_ip": record.get("id.orig_h"),
        "src_port": record.get("id.orig_p"),
        "dst_ip": record.get("id.resp_h"),
        "dst_port": record.get("id.resp_p"),
        "proto": record.get("proto"),
        "service": record.get("service"),
        "conn_state": record.get("conn_state"),
        "history": record.get("history"),
        "duration": record.get("duration"),
        "orig_bytes": record.get("orig_bytes"),
        "resp_bytes": record.get("resp_bytes"),
        "orig_pkts": record.get("orig_pkts"),
        "resp_pkts": record.get("resp_pkts"),
        "botnet_probability": round(probability, 8),
        "threshold": THRESHOLD,
        "prediction": prediction,
        "detector_mode": "shadow",
    }


def process_line(line):
    line = line.strip()
    if not line:
        return
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        print("[JSON ERROR]", exc, file=sys.stderr, flush=True)
        return

    # Known infrastructure services (for example the configured Elasticsearch
    # endpoint) are excluded before ML inference. They are not written to
    # detections.jsonl and can never enter botnet_alerts.jsonl.
    if is_ignored_connection(record):
        return

    try:
        result = predict_connection(record)
    except Exception as exc:
        print("[PREDICTION ERROR]", repr(exc), file=sys.stderr, flush=True)
        return

    write_json_line(DETECTION_LOG, result)

    if result["prediction"] == "BOTNET":
        write_json_line(ALERT_LOG, result)
        source = f"{result['src_ip']}:{result['src_port']}"
        destination = f"{result['dst_ip']}:{result['dst_port']}"
        print(
            "[BOTNET]",
            source,
            "->",
            destination,
            result["proto"],
            f"P={result['botnet_probability']:.6f}",
            flush=True,
        )


def follow_conn_log(path, from_start=False):
    handle = None
    current_inode = None
    first_open = True
    waiting_printed = False

    while True:
        if not path.exists():
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
                handle = None
                current_inode = None
            if not waiting_printed:
                print("[WAIT] conn.log not available:", path, flush=True)
                waiting_printed = True
            time.sleep(1.0)
            continue

        waiting_printed = False
        try:
            stat = path.stat()
        except OSError:
            time.sleep(POLL_INTERVAL)
            continue

        if handle is None or current_inode != stat.st_ino:
            rotated = handle is not None and current_inode != stat.st_ino
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
            handle = path.open("r", encoding="utf-8", errors="replace")
            current_inode = os.fstat(handle.fileno()).st_ino
            if first_open and not from_start:
                handle.seek(0, os.SEEK_END)
            first_open = False
            print("[OPEN]", path, "inode=", current_inode, "rotated=" + str(rotated), flush=True)

        line = handle.readline()
        if line:
            process_line(line)
            continue

        try:
            if path.stat().st_size < handle.tell():
                handle.close()
                handle = None
                current_inode = None
                continue
        except OSError:
            pass
        time.sleep(POLL_INTERVAL)


print("=" * 80)
print("ZEEK BOTNET DETECTOR - SHADOW MODE")
print("=" * 80)
print("Raw model features     :", len(ACTIVE_FEATURES))
print("Encoded model features :", len(preprocessor.get_feature_names_out()))
print("Threshold              :", THRESHOLD)
print("Watching               :", CONN_LOG)
print("Ignored services       :", ", ".join(f"{h}:{p}" for h, p in sorted(IGNORED_SERVICES)) or "none")
print("Ignored traffic logging: DISABLED (not written to detections/alerts)")
print("Console output         : BOTNET only")
print("Traffic blocking       : DISABLED")
print("=" * 80)

try:
    follow_conn_log(CONN_LOG, from_start=args.from_start)
except KeyboardInterrupt:
    print("Detector stopped.")
