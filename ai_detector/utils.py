import pyshark
import csv
import os
from statistics import mean, stdev
from django.conf import settings


# Define the column headers
FIELDNAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "SYN Flag Count", "ACK Flag Count", "FIN Flag Count", "RST Flag Count",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s"
]


def calculate_iat_values(timestamps):
    """Calculate inter-arrival time metrics."""
    if len(timestamps) < 2:
        return {"mean": 0, "std": 0, "max": 0, "min": 0, "total": 0}
    iat = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))]
    return {
        "mean": mean(iat),
        "std": stdev(iat) if len(iat) > 1 else 0,
        "max": max(iat),
        "min": min(iat),
        "total": sum(iat)
    }


def capture_model_features(output_file="captured_traffic_features.csv", packet_count=300):
    """
    Capture live traffic, extract features, and save them to a CSV file.
    """
    output_path = os.path.join(settings.BASE_DIR, "data", output_file)

    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Initialize CSV file with headers if it doesn't exist
    if not os.path.exists(output_path):
        with open(output_path, mode='w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
            writer.writeheader()

    capture = pyshark.LiveCapture(interface='eth0')
    flows = {}

    for packet in capture.sniff_continuously(packet_count=packet_count):
        try:
            src_ip = getattr(packet.ip, 'src', None)
            dst_ip = getattr(packet.ip, 'dst', None)
            src_port = getattr(packet[packet.transport_layer], 'srcport', None)
            dst_port = getattr(packet[packet.transport_layer], 'dstport', None)
            length = int(packet.length)
            timestamp = float(packet.sniff_timestamp)
            flow_key = (src_ip, dst_ip, src_port, dst_port)

            if flow_key not in flows:
                flows[flow_key] = {
                    "timestamps": [], "fwd_lengths": [], "bwd_lengths": [],
                    "syn_flags": 0, "ack_flags": 0, "fin_flags": 0, "rst_flags": 0
                }

            flow = flows[flow_key]
            flow["timestamps"].append(timestamp)

            if src_ip == flow_key[0]:  # Forward direction
                flow["fwd_lengths"].append(length)
            else:  # Backward direction
                flow["bwd_lengths"].append(length)

            # Extract TCP flags
            if packet.transport_layer == "TCP":
                flags = packet.tcp.flags_str
                if "SYN" in flags: flow["syn_flags"] += 1
                if "ACK" in flags: flow["ack_flags"] += 1
                if "FIN" in flags: flow["fin_flags"] += 1
                if "RST" in flags: flow["rst_flags"] += 1

        except AttributeError:
            continue

    # Write processed flows to CSV
    features = []
    for flow_key, stats in flows.items():
        iat = calculate_iat_values(stats["timestamps"])
        total_fwd_length = sum(stats["fwd_lengths"])
        total_bwd_length = sum(stats["bwd_lengths"])

        features.append({
            "Destination Port": flow_key[3] or 0,
            "Flow Duration": iat["total"],
            "Total Fwd Packets": len(stats["fwd_lengths"]),
            "Total Backward Packets": len(stats["bwd_lengths"]),
            "Total Length of Fwd Packets": total_fwd_length,
            "Total Length of Bwd Packets": total_bwd_length,
            "Fwd Packet Length Max": max(stats["fwd_lengths"], default=0),
            "Fwd Packet Length Min": min(stats["fwd_lengths"], default=0),
            "Flow IAT Mean": iat["mean"],
            "SYN Flag Count": stats["syn_flags"],
            "ACK Flag Count": stats["ack_flags"]
        })

    # Write to CSV
    with open(output_path, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writerows(features)
    print(f"Captured {len(features)} flows and written to {output_path}")
