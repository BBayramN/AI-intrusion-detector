import pyshark
import csv
import os
from statistics import mean, stdev
from django.conf import settings

# Define feature names
FIELDNAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

def capture_model_features(output_file="captured_traffic_features.csv", packet_count=100):
    output_path = os.path.join(settings.BASE_DIR, "data", output_file)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Create or initialize CSV file
    if not os.path.exists(output_path):
        with open(output_path, mode="w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()

    # Start capturing traffic
    capture = pyshark.LiveCapture(interface="eth0")
    flows = {}

    for packet in capture.sniff_continuously(packet_count=packet_count):
        try:
            src_ip = getattr(packet.ip, "src", None)
            dst_ip = getattr(packet.ip, "dst", None)
            src_port = getattr(packet[packet.transport_layer], "srcport", None)
            dst_port = getattr(packet[packet.transport_layer], "dstport", None)
            length = int(packet.length)
            timestamp = float(packet.sniff_timestamp)

            flow_key = (src_ip, dst_ip, src_port, dst_port)

            if flow_key not in flows:
                flows[flow_key] = {
                    "timestamps": [],
                    "fwd_lengths": [], "bwd_lengths": [],
                    "syn_flags": 0, "ack_flags": 0, "fin_flags": 0,
                    "rst_flags": 0, "psh_flags": 0, "urg_flags": 0, "ece_flags": 0
                }

            flow = flows[flow_key]
            flow["timestamps"].append(timestamp)

            # Packet direction
            if src_ip == flow_key[0]:
                flow["fwd_lengths"].append(length)
            else:
                flow["bwd_lengths"].append(length)

            # Extract TCP Flags
            if packet.transport_layer == "TCP":
                flags = packet.tcp.flags_str
                if "SYN" in flags: flow["syn_flags"] += 1
                if "ACK" in flags: flow["ack_flags"] += 1
                if "FIN" in flags: flow["fin_flags"] += 1
                if "RST" in flags: flow["rst_flags"] += 1
                if "PSH" in flags: flow["psh_flags"] += 1
                if "URG" in flags: flow["urg_flags"] += 1
                if "ECE" in flags: flow["ece_flags"] += 1

        except AttributeError:
            continue

    # Process flows into features and write to CSV
    with open(output_path, mode="a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)

        for flow_key, stats in flows.items():
            iat = [stats["timestamps"][i] - stats["timestamps"][i - 1] for i in range(1, len(stats["timestamps"]))]

            row = {
                "Destination Port": flow_key[3],
                "Flow Duration": sum(iat) if iat else None,
                "Total Fwd Packets": len(stats["fwd_lengths"]),
                "Total Backward Packets": len(stats["bwd_lengths"]),
                "Total Length of Fwd Packets": sum(stats["fwd_lengths"]),
                "Total Length of Bwd Packets": sum(stats["bwd_lengths"]),
                "Fwd Packet Length Max": max(stats["fwd_lengths"], default=None),
                "Fwd Packet Length Min": min(stats["fwd_lengths"], default=None),
                "Fwd Packet Length Mean": mean(stats["fwd_lengths"]) if stats["fwd_lengths"] else None,
                "Fwd Packet Length Std": stdev(stats["fwd_lengths"]) if len(stats["fwd_lengths"]) > 1 else None,
                "SYN Flag Count": stats["syn_flags"],
                "ACK Flag Count": stats["ack_flags"],
                "FIN Flag Count": stats["fin_flags"],
                "RST Flag Count": stats["rst_flags"],
                "PSH Flag Count": stats["psh_flags"],
                "URG Flag Count": stats["urg_flags"],
                "ECE Flag Count": stats["ece_flags"],
                "Flow IAT Mean": mean(iat) if iat else None,
                "Flow IAT Std": stdev(iat) if len(iat) > 1 else None,
                "Flow IAT Max": max(iat) if iat else None,
                "Flow IAT Min": min(iat) if iat else None,
            }

            # Write row with only relevant data
            writer.writerow(row)
