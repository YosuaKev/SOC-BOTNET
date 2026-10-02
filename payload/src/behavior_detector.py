#!/usr/bin/env python3
import argparse
import ipaddress
import json
import math
import os
import statistics
import time
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

POLL_INTERVAL = 0.25
LOGIN_KEYWORDS = (
    "/login",
    "login.php",
    "/signin",
    "/sign-in",
    "/auth",
    "/authenticate",
    "/session",
    "/user/login",
    "wp-login.php",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def write_json_line(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n")
        handle.flush()


def clean_uri(uri):
    if not uri:
        return "/"
    return str(uri).split("?", 1)[0]


def is_login_endpoint(uri):
    uri = clean_uri(uri).lower()
    return any(keyword in uri for keyword in LOGIN_KEYWORDS)


def valid_unicast_ip(value):
    try:
        ip = ipaddress.ip_address(str(value))
        return not (ip.is_multicast or ip.is_unspecified)
    except ValueError:
        return False


def safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def safe_float(value, default=None):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def parse_ignore_service(value):
    """Parse HOST:PORT (IPv4/hostname) or [IPv6]:PORT."""
    value = str(value).strip()
    if not value:
        raise ValueError("empty service")
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
    if not host or not (0 <= port <= 65535):
        raise ValueError(f"invalid ignored service: {value}")
    return host, port


class IgnoreServices:
    def __init__(self, values):
        self.services = set()
        for value in values or []:
            self.services.add(parse_ignore_service(value))

    def matches_record(self, record):
        if not self.services:
            return False
        orig_h = str(record.get("id.orig_h") or "")
        resp_h = str(record.get("id.resp_h") or "")
        orig_p = safe_int(record.get("id.orig_p"), -1)
        resp_p = safe_int(record.get("id.resp_p"), -1)
        return (orig_h, orig_p) in self.services or (resp_h, resp_p) in self.services

    def display(self):
        return [f"{host}:{port}" for host, port in sorted(self.services)]


class Tailer:
    def __init__(self, path, label):
        self.path = Path(path)
        self.label = label
        self.handle = None
        self.inode = None
        self.waiting_printed = False
        self.first_open = True

    def close(self):
        if self.handle is not None:
            try:
                self.handle.close()
            except Exception:
                pass
        self.handle = None
        self.inode = None

    def read_available(self):
        lines = []
        if not self.path.exists():
            self.close()
            if not self.waiting_printed:
                print(f"[WAIT] {self.label} not available: {self.path}", flush=True)
                self.waiting_printed = True
            return lines

        self.waiting_printed = False
        try:
            stat = self.path.stat()
        except OSError:
            return lines

        if self.handle is None or self.inode != stat.st_ino:
            rotated = self.handle is not None and self.inode != stat.st_ino
            self.close()
            self.handle = self.path.open("r", encoding="utf-8", errors="replace")
            self.inode = os.fstat(self.handle.fileno()).st_ino
            if self.first_open:
                self.handle.seek(0, os.SEEK_END)
                self.first_open = False
            print("[OPEN]", self.path, "inode=", self.inode, "rotated=" + str(rotated), flush=True)

        while True:
            pos = self.handle.tell()
            line = self.handle.readline()
            if not line:
                self.handle.seek(pos)
                break
            lines.append(line)

        try:
            if self.path.stat().st_size < self.handle.tell():
                self.close()
        except OSError:
            self.close()

        return lines


class BehaviorDetector:
    def __init__(
        self,
        window,
        http_threshold,
        ssh_threshold,
        port_threshold,
        host_threshold,
        flood_window,
        flood_threshold,
        beacon_window,
        beacon_min_connections,
        beacon_min_interval,
        beacon_max_interval,
        beacon_max_cv,
        cooldown,
        alert_log,
        ignored_services=None,
    ):
        self.window = window
        self.http_threshold = http_threshold
        self.ssh_threshold = ssh_threshold
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold
        self.flood_window = flood_window
        self.flood_threshold = flood_threshold
        self.beacon_window = beacon_window
        self.beacon_min_connections = beacon_min_connections
        self.beacon_min_interval = beacon_min_interval
        self.beacon_max_interval = beacon_max_interval
        self.beacon_max_cv = beacon_max_cv
        self.cooldown = cooldown
        self.alert_log = Path(alert_log)
        self.ignored_services = ignored_services or IgnoreServices([])

        self.http_events = defaultdict(deque)
        self.ssh_events = defaultdict(deque)
        self.port_events = defaultdict(deque)
        self.host_events = defaultdict(deque)
        self.flood_events = defaultdict(deque)
        self.beacon_events = defaultdict(deque)
        self.last_alert = {}

    @staticmethod
    def _expire(queue, cutoff):
        while queue and queue[0][0] < cutoff:
            queue.popleft()

    def can_alert(self, alert_type, key, ts):
        cooldown_key = (alert_type,) + tuple(key)
        previous = self.last_alert.get(cooldown_key, 0.0)
        if ts - previous < self.cooldown:
            return False
        self.last_alert[cooldown_key] = ts
        return True

    def emit(self, alert, console_parts):
        alert.setdefault("detection_method", "behavioral_heuristic")
        alert.setdefault("mode", "shadow")
        write_json_line(self.alert_log, alert)
        print(*console_parts, flush=True)

    def process_http(self, record):
        if self.ignored_services.matches_record(record):
            return

        method = str(record.get("method") or "").upper()
        if method != "POST":
            return
        uri = clean_uri(record.get("uri"))
        if not is_login_endpoint(uri):
            return

        src_ip = record.get("id.orig_h")
        src_port = record.get("id.orig_p")
        dst_ip = record.get("id.resp_h")
        dst_port = record.get("id.resp_p")
        if not src_ip or not dst_ip:
            return

        ts = safe_float(record.get("ts"), time.time())
        if ts is None:
            ts = time.time()
        dst_port = safe_int(dst_port, 0)

        key = (str(src_ip), str(dst_ip), dst_port, uri)
        queue = self.http_events[key]
        queue.append((ts, src_port))
        self._expire(queue, ts - self.window)

        attempts = len(queue)
        if attempts < self.http_threshold:
            return
        if not self.can_alert("HTTP_BRUTE_FORCE", key, ts):
            return

        unique_source_ports = len({port for _, port in queue if port is not None})
        alert = {
            "processed_at_utc": utc_now(),
            "event_ts": ts,
            "alert_type": "HTTP_BRUTE_FORCE",
            "category": "brute_force",
            "severity": "HIGH",
            "src_ip": str(src_ip),
            "src_port": safe_int(src_port, 0),
            "dst_ip": str(dst_ip),
            "dst_port": dst_port,
            "protocol": "tcp",
            "method": method,
            "uri": uri,
            "attempts_in_window": attempts,
            "unique_source_ports": unique_source_ports,
            "window_seconds": self.window,
            "threshold": self.http_threshold,
            "reason": f"{attempts} POST requests to authentication endpoint {uri} within {self.window} seconds",
            "detection_source": "zeek_http_behavior",
        }
        self.emit(
            alert,
            [
                "[HTTP_BRUTE_FORCE]",
                f"{src_ip} -> {dst_ip}:{dst_port}",
                f"URI={uri}",
                f"ATTEMPTS={attempts}",
                f"WINDOW={self.window}s",
            ],
        )

    def process_conn(self, record):
        if self.ignored_services.matches_record(record):
            return

        proto = str(record.get("proto") or "").lower()
        if proto not in {"tcp", "udp"}:
            return

        src_ip = record.get("id.orig_h")
        src_port = safe_int(record.get("id.orig_p"), 0)
        dst_ip = record.get("id.resp_h")
        dst_port = safe_int(record.get("id.resp_p"), -1)
        if not src_ip or not dst_ip or dst_port < 0:
            return
        if not valid_unicast_ip(src_ip) or not valid_unicast_ip(dst_ip):
            return

        ts = safe_float(record.get("ts"), None)
        if ts is None or not 0 <= dst_port <= 65535:
            return

        src_ip = str(src_ip)
        dst_ip = str(dst_ip)
        conn_state = str(record.get("conn_state") or "-")

        self._process_ssh(ts, src_ip, src_port, dst_ip, dst_port, proto, conn_state)
        self._process_port_scan(ts, src_ip, src_port, dst_ip, dst_port, proto)
        self._process_host_scan(ts, src_ip, src_port, dst_ip, dst_port, proto)
        self._process_flood(ts, src_ip, src_port, dst_ip, dst_port, proto, conn_state)
        self._process_beacon(ts, src_ip, src_port, dst_ip, dst_port, proto)

    def _process_ssh(self, ts, src_ip, src_port, dst_ip, dst_port, proto, conn_state):
        if proto != "tcp" or dst_port != 22:
            return
        key = (src_ip, dst_ip, dst_port)
        queue = self.ssh_events[key]
        queue.append((ts, src_port, conn_state))
        self._expire(queue, ts - self.window)
        attempts = len(queue)
        if attempts < self.ssh_threshold:
            return
        if not self.can_alert("SSH_BRUTE_FORCE", key, ts):
            return

        state_counts = dict(Counter(state for _, _, state in queue))
        alert = {
            "processed_at_utc": utc_now(),
            "event_ts": ts,
            "alert_type": "SSH_BRUTE_FORCE",
            "category": "brute_force",
            "severity": "HIGH",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": 22,
            "protocol": "tcp",
            "attempts_in_window": attempts,
            "unique_source_ports": len({p for _, p, _ in queue}),
            "conn_state_counts": state_counts,
            "window_seconds": self.window,
            "threshold": self.ssh_threshold,
            "reason": f"{attempts} SSH connection attempts to {dst_ip}:22 within {self.window} seconds",
            "detection_source": "zeek_conn_behavior",
        }
        self.emit(
            alert,
            ["[SSH_BRUTE_FORCE]", f"{src_ip} -> {dst_ip}:22", f"ATTEMPTS={attempts}", f"WINDOW={self.window}s"],
        )

    def _process_port_scan(self, ts, src_ip, src_port, dst_ip, dst_port, proto):
        key = (src_ip, dst_ip, proto)
        queue = self.port_events[key]
        queue.append((ts, dst_port))
        self._expire(queue, ts - self.window)
        unique_ports = sorted({port for _, port in queue})
        if len(unique_ports) < self.port_threshold:
            return
        if not self.can_alert("PORT_SCAN", key, ts):
            return

        alert = {
            "processed_at_utc": utc_now(),
            "event_ts": ts,
            "alert_type": "PORT_SCAN",
            "category": "scan",
            "severity": "HIGH",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": proto,
            "unique_destination_ports": len(unique_ports),
            "destination_ports": unique_ports,
            "window_seconds": self.window,
            "threshold": self.port_threshold,
            "reason": f"{src_ip} contacted {len(unique_ports)} unique {proto.upper()} ports on {dst_ip} within {self.window} seconds",
            "detection_source": "zeek_conn_behavior",
        }
        self.emit(
            alert,
            ["[PORT_SCAN]", f"{src_ip} -> {dst_ip}", f"PROTO={proto}", f"UNIQUE_PORTS={len(unique_ports)}", f"WINDOW={self.window}s"],
        )

    def _process_host_scan(self, ts, src_ip, src_port, dst_ip, dst_port, proto):
        # Same source probing the same service/port across many destination hosts.
        key = (src_ip, dst_port, proto)
        queue = self.host_events[key]
        queue.append((ts, dst_ip))
        self._expire(queue, ts - self.window)
        unique_hosts = sorted({host for _, host in queue})
        if len(unique_hosts) < self.host_threshold:
            return
        if not self.can_alert("HOST_SCAN", key, ts):
            return

        alert = {
            "processed_at_utc": utc_now(),
            "event_ts": ts,
            "alert_type": "HOST_SCAN",
            "category": "scan",
            "severity": "HIGH",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": proto,
            "unique_destination_hosts": len(unique_hosts),
            "destination_hosts": unique_hosts,
            "window_seconds": self.window,
            "threshold": self.host_threshold,
            "reason": f"{src_ip} contacted {len(unique_hosts)} destination hosts on {proto.upper()}/{dst_port} within {self.window} seconds",
            "detection_source": "zeek_conn_behavior",
        }
        self.emit(
            alert,
            ["[HOST_SCAN]", f"SRC={src_ip}", f"PORT={dst_port}/{proto}", f"UNIQUE_HOSTS={len(unique_hosts)}", f"WINDOW={self.window}s"],
        )

    def _process_flood(self, ts, src_ip, src_port, dst_ip, dst_port, proto, conn_state):
        key = (src_ip, dst_ip, dst_port, proto)
        queue = self.flood_events[key]
        queue.append((ts, src_port, conn_state))
        self._expire(queue, ts - self.flood_window)
        count = len(queue)
        if count < self.flood_threshold:
            return
        if not self.can_alert("CONNECTION_FLOOD", key, ts):
            return

        state_counts = dict(Counter(state for _, _, state in queue))
        alert = {
            "processed_at_utc": utc_now(),
            "event_ts": ts,
            "alert_type": "CONNECTION_FLOOD",
            "category": "flood",
            "severity": "HIGH",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": proto,
            "connections_in_window": count,
            "unique_source_ports": len({p for _, p, _ in queue}),
            "conn_state_counts": state_counts,
            "window_seconds": self.flood_window,
            "threshold": self.flood_threshold,
            "reason": f"{count} connections from {src_ip} to {dst_ip}:{dst_port}/{proto} within {self.flood_window} seconds",
            "detection_source": "zeek_conn_behavior",
        }
        self.emit(
            alert,
            ["[CONNECTION_FLOOD]", f"{src_ip} -> {dst_ip}:{dst_port}", f"PROTO={proto}", f"CONNECTIONS={count}", f"WINDOW={self.flood_window}s"],
        )

    def _process_beacon(self, ts, src_ip, src_port, dst_ip, dst_port, proto):
        key = (src_ip, dst_ip, dst_port, proto)
        queue = self.beacon_events[key]
        queue.append((ts, src_port))
        self._expire(queue, ts - self.beacon_window)
        if len(queue) < self.beacon_min_connections:
            return

        timestamps = [item[0] for item in queue]
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
        if len(intervals) < self.beacon_min_connections - 1:
            return

        mean_interval = statistics.mean(intervals)
        if not self.beacon_min_interval <= mean_interval <= self.beacon_max_interval:
            return
        std_interval = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
        cv = std_interval / mean_interval if mean_interval > 0 else math.inf
        if cv > self.beacon_max_cv:
            return
        if not self.can_alert("BEACONING", key, ts):
            return

        alert = {
            "processed_at_utc": utc_now(),
            "event_ts": ts,
            "alert_type": "BEACONING",
            "category": "beacon",
            "severity": "MEDIUM",
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": proto,
            "connections_observed": len(queue),
            "observation_window_seconds": self.beacon_window,
            "mean_interval_seconds": round(mean_interval, 6),
            "interval_stddev_seconds": round(std_interval, 6),
            "interval_cv": round(cv, 6),
            "min_interval_seconds": round(min(intervals), 6),
            "max_interval_seconds": round(max(intervals), 6),
            "beacon_min_connections": self.beacon_min_connections,
            "beacon_max_cv": self.beacon_max_cv,
            "reason": f"Periodic connections to {dst_ip}:{dst_port}/{proto}: mean interval {mean_interval:.2f}s, CV {cv:.3f}",
            "detection_source": "zeek_conn_behavior",
        }
        self.emit(
            alert,
            ["[BEACONING]", f"{src_ip} -> {dst_ip}:{dst_port}", f"PROTO={proto}", f"N={len(queue)}", f"MEAN={mean_interval:.2f}s", f"CV={cv:.3f}"],
        )


def decode_json(line):
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def positive_int(value):
    value = int(value)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return value


def positive_float(value):
    value = float(value)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return value


def cv_float(value):
    value = float(value)
    if not 0 < value <= 1:
        raise argparse.ArgumentTypeError("must be > 0 and <= 1")
    return value


def main():
    parser = argparse.ArgumentParser(description="Zeek real-time behavior detector")
    parser.add_argument("--http-log", required=True)
    parser.add_argument("--conn-log", required=True)
    parser.add_argument("--alert-log", default="/opt/zeek-botnet-detector/logs/behavior_alerts.jsonl")
    parser.add_argument("--window", type=positive_int, default=60)
    parser.add_argument("--http-threshold", type=positive_int, default=20)
    parser.add_argument("--ssh-threshold", type=positive_int, default=10)
    parser.add_argument("--port-threshold", type=positive_int, default=15)
    parser.add_argument("--host-threshold", type=positive_int, default=15)
    parser.add_argument("--flood-window", type=positive_int, default=10)
    parser.add_argument("--flood-threshold", type=positive_int, default=100)
    parser.add_argument("--beacon-window", type=positive_int, default=600)
    parser.add_argument("--beacon-min-connections", type=positive_int, default=6)
    parser.add_argument("--beacon-min-interval", type=positive_float, default=5.0)
    parser.add_argument("--beacon-max-interval", type=positive_float, default=300.0)
    parser.add_argument("--beacon-max-cv", type=cv_float, default=0.15)
    parser.add_argument("--cooldown", type=positive_int, default=60)
    parser.add_argument("--ignore-service", action="append", default=[], metavar="HOST:PORT")
    args = parser.parse_args()

    if args.beacon_min_interval >= args.beacon_max_interval:
        parser.error("--beacon-min-interval must be lower than --beacon-max-interval")

    try:
        ignored_services = IgnoreServices(args.ignore_service)
    except (ValueError, TypeError) as exc:
        parser.error(str(exc))

    print("=" * 80)
    print("ZEEK BEHAVIOR DETECTOR")
    print("=" * 80)
    print("Mode                 : SHADOW")
    print("HTTP log             :", args.http_log)
    print("Connection log       :", args.conn_log)
    print("Alert log            :", args.alert_log)
    print("General window       :", args.window, "seconds")
    print("HTTP brute threshold :", args.http_threshold, "POST requests")
    print("SSH brute threshold  :", args.ssh_threshold, "connections to TCP/22")
    print("Port scan threshold  :", args.port_threshold, "unique ports")
    print("Host scan threshold  :", args.host_threshold, "unique hosts on same port")
    print("Flood threshold      :", args.flood_threshold, "connections /", args.flood_window, "seconds")
    print("Beacon rule          :", args.beacon_min_connections, "connections, interval", f"{args.beacon_min_interval}-{args.beacon_max_interval}s", "CV <=", args.beacon_max_cv)
    print("Beacon window        :", args.beacon_window, "seconds")
    print("Cooldown             :", args.cooldown, "seconds")
    print("Ignored services     :", ", ".join(ignored_services.display()) or "none")
    print("Alert types          : HTTP_BRUTE_FORCE, SSH_BRUTE_FORCE, PORT_SCAN, HOST_SCAN, CONNECTION_FLOOD, BEACONING")
    print("=" * 80)

    detector = BehaviorDetector(
        window=args.window,
        http_threshold=args.http_threshold,
        ssh_threshold=args.ssh_threshold,
        port_threshold=args.port_threshold,
        host_threshold=args.host_threshold,
        flood_window=args.flood_window,
        flood_threshold=args.flood_threshold,
        beacon_window=args.beacon_window,
        beacon_min_connections=args.beacon_min_connections,
        beacon_min_interval=args.beacon_min_interval,
        beacon_max_interval=args.beacon_max_interval,
        beacon_max_cv=args.beacon_max_cv,
        cooldown=args.cooldown,
        alert_log=args.alert_log,
        ignored_services=ignored_services,
    )
    http_tailer = Tailer(args.http_log, "http.log")
    conn_tailer = Tailer(args.conn_log, "conn.log")

    try:
        while True:
            did_work = False
            for line in http_tailer.read_available():
                did_work = True
                record = decode_json(line)
                if record is not None:
                    detector.process_http(record)
            for line in conn_tailer.read_available():
                did_work = True
                record = decode_json(line)
                if record is not None:
                    detector.process_conn(record)
            if not did_work:
                time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("Behavior detector stopped.")


if __name__ == "__main__":
    main()
