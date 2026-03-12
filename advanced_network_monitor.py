import argparse
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque, DefaultDict, Dict, Tuple
import pyshark
@dataclass
class MonitorConfig:
    interface: str
    summary_interval: float = 5.0
    window_seconds: float = 10.0
    packet_rate_threshold: int = 100
    syn_flood_threshold: int = 50
    dns_request_threshold: int = 40
    port_scan_threshold: int = 20
    alerts_log_path: str = "alerts.log"
    summary_log_path: str = "traffic_summary.txt"
@dataclass
class TrafficStats:
    total_packets: int = 0
    protocol_counts: DefaultDict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    packets_per_ip: DefaultDict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    packets_timestamps_per_ip: Dict[str, Deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    syn_timestamps_per_ip: Dict[str, Deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    dns_timestamps_per_ip: Dict[str, Deque[float]] = field(
        default_factory=lambda: defaultdict(deque)
    )
    port_scan_ports_per_ip: Dict[str, Dict[str, Deque[float]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(deque))
    )
    alerts_count: int = 0
    last_alert_time_per_ip: Dict[Tuple[str, str], float] = field(
        default_factory=dict
    )
def get_ip_address(packet) -> str:
    try:
        if hasattr(packet, "ip") and hasattr(packet.ip, "src"):
            return packet.ip.src
        if hasattr(packet, "ipv6") and hasattr(packet.ipv6, "src"):
            return packet.ipv6.src
    except AttributeError:
        # If any attribute is missing, fall through to "unknown".
        pass
    return "unknown"


def get_protocol_name(packet) -> str:
    # Check for DNS first, then ICMP, then TCP, then UDP.
    if hasattr(packet, "dns"):
        return "DNS"
    if hasattr(packet, "icmp"):
        return "ICMP"
    if hasattr(packet, "tcp"):
        return "TCP"
    if hasattr(packet, "udp"):
        return "UDP"
    return "OTHER"


def is_tcp_syn(packet) -> bool:
    if not hasattr(packet, "tcp"):
        return False

    tcp_layer = packet.tcp
    try:
        # pyshark exposes individual flag fields like 'flags_syn', 'flags_ack'.
        syn_flag = getattr(tcp_layer, "flags_syn", None)
        ack_flag = getattr(tcp_layer, "flags_ack", None)
        return syn_flag == "1" and ack_flag == "0"
    except AttributeError:
        return False


def current_timestamp(packet) -> float:
    ts = getattr(packet, "sniff_timestamp", None)
    if ts is not None:
        try:
            return float(ts)
        except (TypeError, ValueError):
            pass
    return time.time()


def prune_old_timestamps(deque_obj: Deque[float], now: float, window_seconds: float):
    cutoff = now - window_seconds
    while deque_obj and deque_obj[0] < cutoff:
        deque_obj.popleft()


def log_alert(config: MonitorConfig, stats: TrafficStats, ip: str, reason: str):
    now = time.time()
    key = (ip, reason)

    last_time = stats.last_alert_time_per_ip.get(key)
    if last_time is not None and (now - last_time) < 30:
        # Cooldown not yet expired for this (IP, reason); skip logging.
        return

    # Record the time of this alert and update global count.
    stats.last_alert_time_per_ip[key] = now
    stats.alerts_count += 1

    timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    line = f"[{timestamp_str}] IP={ip} Reason={reason}\n"

    try:
        with open(config.alerts_log_path, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass
def print_live_summary(stats: TrafficStats):
    print("-" * 60)
    print(f"Total packets captured: {stats.total_packets}")

    # Show protocol counts.
    print("Protocol counts:")
    for proto, count in sorted(stats.protocol_counts.items()):
        print(f"  {proto}: {count}")

    # Find top 5 IP senders by packet count.
    print("Top IP senders:")
    sorted_ips = sorted(
        stats.packets_per_ip.items(), key=lambda kv: kv[1], reverse=True
    )
    for ip, count in sorted_ips[:5]:
        print(f"  {ip}: {count} packets")

    print(f"Alerts triggered so far: {stats.alerts_count}")
    print("-" * 60)
def write_final_summary(config: MonitorConfig, stats: TrafficStats):
    try:
        with open(config.summary_log_path, "w", encoding="utf-8") as f:
            f.write("Advanced Network Monitor - Traffic Summary\n")
            f.write("=" * 60 + "\n\n")

            f.write(f"Total packets captured: {stats.total_packets}\n\n")

            f.write("Protocol counts:\n")
            for proto, count in sorted(stats.protocol_counts.items()):
                f.write(f"  {proto}: {count}\n")
            f.write("\n")

            f.write("Packets per IP (top 20):\n")
            sorted_ips = sorted(
                stats.packets_per_ip.items(),
                key=lambda kv: kv[1],
                reverse=True,
            )
            for ip, count in sorted_ips[:20]:
                f.write(f"  {ip}: {count} packets\n")
            f.write("\n")

            f.write(f"Total alerts triggered: {stats.alerts_count}\n")
    except OSError:
        pass
def process_packet(packet, config: MonitorConfig, stats: TrafficStats) -> None:
    stats.total_packets += 1

    if not hasattr(packet, "ip"):
        return
    try:
        src_ip = packet.ip.src
    except AttributeError:
        return
    proto = get_protocol_name(packet)
    stats.packets_per_ip[src_ip] += 1
    stats.protocol_counts[proto] += 1
    now = current_timestamp(packet)
    ip_deque = stats.packets_timestamps_per_ip[src_ip]
    ip_deque.append(now)
    prune_old_timestamps(ip_deque, now, config.window_seconds)
    if len(ip_deque) == config.packet_rate_threshold + 1:
        alert_msg = (
            f"[ALERT] High packet rate from {src_ip} - "
            f"{len(ip_deque)} packets in {config.window_seconds:.0f} seconds"
        )
        print(alert_msg)
        log_alert(config, stats, src_ip, alert_msg)
    if proto == "TCP" and is_tcp_syn(packet):
        syn_deque = stats.syn_timestamps_per_ip[src_ip]
        syn_deque.append(now)
        prune_old_timestamps(syn_deque, now, config.window_seconds)
        if len(syn_deque) == config.syn_flood_threshold + 1:
            alert_msg = (
                f"[ALERT] Possible SYN Flood from {src_ip} - "
                f"{len(syn_deque)} SYN packets in "
                f"{config.window_seconds:.0f} seconds"
            )
            print(alert_msg)
            log_alert(config, stats, src_ip, alert_msg)
    if proto == "TCP":
        dst_port = None
        try:
            if hasattr(packet, "tcp"):
                tcp_layer = packet.tcp
                dst_port = getattr(tcp_layer, "dstport", None)
        except AttributeError:
            dst_port = None
        if dst_port is not None:
            ports_dict = stats.port_scan_ports_per_ip[src_ip]
            for port, dq in list(ports_dict.items()):
                prune_old_timestamps(dq, now, config.window_seconds)
                if not dq:
                    del ports_dict[port]
            port_deque = ports_dict.setdefault(dst_port, deque())
            port_deque.append(now)
            prune_old_timestamps(port_deque, now, config.window_seconds)
            unique_ports = len(ports_dict)
            if unique_ports == config.port_scan_threshold + 1:
                alert_msg = (
                    f"[ALERT] Possible Port Scan from {src_ip} - "
                    f"{unique_ports} ports scanned"
                )
                print(alert_msg)
                log_alert(config, stats, src_ip, alert_msg)
    if proto == "DNS":
        dns_deque = stats.dns_timestamps_per_ip[src_ip]
        dns_deque.append(now)
        prune_old_timestamps(dns_deque, now, config.window_seconds)
        if len(dns_deque) > config.dns_request_threshold:
            reason = (
                f"High DNS request volume: {len(dns_deque)} DNS packets "
                f"in {config.window_seconds:.0f}s"
            )
            log_alert(config, stats, src_ip, reason)
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Advanced real-time network monitor using PyShark.\n"
            "Tracks traffic statistics and detects simple suspicious patterns."
        )
    )

    parser.add_argument(
        "--iface",
        required=True,
        help="Network interface to listen on (e.g., en0 on macOS, eth0 on Linux).",
    )
    parser.add_argument(
        "--summary-interval",
        type=float,
        default=5.0,
        help="Seconds between on-screen statistics summaries (default: 5).",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=10.0,
        help="Sliding time window in seconds used for alert checks (default: 10).",
    )
    parser.add_argument(
        "--packet-threshold",
        type=int,
        default=100,
        help=(
            "Packet rate threshold: alert if an IP sends more than this many "
            "packets within the time window (default: 100)."
        ),
    )
    parser.add_argument(
        "--syn-threshold",
        type=int,
        default=50,
        help=(
            "SYN flood threshold: alert if an IP sends more than this many "
            "TCP SYN packets within the time window (default: 50)."
        ),
    )
    parser.add_argument(
        "--dns-threshold",
        type=int,
        default=40,
        help=(
            "DNS request threshold: alert if an IP sends more than this many "
            "DNS packets within the time window (default: 40)."
        ),
    )
    parser.add_argument(
        "--port-scan-threshold",
        type=int,
        default=20,
        help=(
            "Port scan threshold: alert if an IP connects to more than this many "
            "different destination ports within the time window (default: 20)."
        ),
    )
    return parser.parse_args()
def main() -> None:
    args = parse_args()

    config = MonitorConfig(
        interface=args.iface,
        summary_interval=args.summary_interval,
        window_seconds=args.window,
        packet_rate_threshold=args.packet_threshold,
        syn_flood_threshold=args.syn_threshold,
        dns_request_threshold=args.dns_threshold,
        port_scan_threshold=args.port_scan_threshold,
    )
    stats = TrafficStats()
    print(
        f"Starting advanced network monitor on interface '{config.interface}'.\n"
        f"Summary interval: {config.summary_interval}s, "
        f"window: {config.window_seconds}s.\n"
        "Press Ctrl+C to stop.\n"
    )
    try:
        with open(config.alerts_log_path, "w", encoding="utf-8") as f:
            f.write("Advanced Network Monitor - Alerts Log\n")
            f.write("=" * 60 + "\n")
    except OSError:
        pass
    capture = pyshark.LiveCapture(interface=config.interface)
    last_summary_time = time.time()
    try:
        for packet in capture.sniff_continuously():
            process_packet(packet, config, stats)
            now = time.time()
            if now - last_summary_time >= config.summary_interval:
                print_live_summary(stats)
                last_summary_time = now
    except KeyboardInterrupt:
        print("\nStopping advanced network monitor...")
    finally:
        try:
            capture.close()
        except Exception:
            pass
        write_final_summary(config, stats)
        print(f"Final summary written to '{config.summary_log_path}'.")
        print(f"Alerts (if any) stored in '{config.alerts_log_path}'.")
if __name__ == "__main__":
    main()
