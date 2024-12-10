import pyshark
import csv
import os
from statistics import mean, stdev

def capture_model_features(output_file='model_input_data.csv'):
    # Define the feature columns
    fieldnames = [
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




    # Initialize CSV file
    if not os.path.exists(output_file):
        with open(output_file, mode='w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

    # Start capturing packets
    capture = pyshark.LiveCapture(interface='eth0')
    flows = {}

    for packet in capture.sniff_continuously(packet_count=500):  # Adjust packet_count as needed
        try:
            src_ip = getattr(packet.ip, 'src', None)
            dst_ip = getattr(packet.ip, 'dst', None)
            src_port = getattr(packet[packet.transport_layer], 'srcport', None)
            dst_port = getattr(packet[packet.transport_layer], 'dstport', None)
            flow_key = (src_ip, dst_ip, src_port, dst_port)

            if flow_key not in flows:
                flows[flow_key] = {
                    "timestamps": [],
                    "fwd_lengths": [],
                    "bwd_lengths": [],
                    "syn_flags": 0,
                    "ack_flags": 0,
                    "fin_flags": 0,
                    "rst_flags": 0,
                    "psh_flags": 0,
                    "urg_flags": 0,
                    "ece_flags": 0,
                }

            flow = flows[flow_key]
            flow["timestamps"].append(float(packet.sniff_timestamp))
            packet_length = int(packet.length)

            if src_ip == packet.ip.src:
                flow["fwd_lengths"].append(packet_length)
            else:
                flow["bwd_lengths"].append(packet_length)

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

    # Process flows into features
    features = []
    for flow_key, stats in flows.items():
        flow_duration = max(stats["timestamps"]) - min(stats["timestamps"]) if len(stats["timestamps"]) > 1 else 0
        total_fwd_packets = len(stats["fwd_lengths"])
        total_bwd_packets = len(stats["bwd_lengths"])
        total_fwd_length = sum(stats["fwd_lengths"])
        total_bwd_length = sum(stats["bwd_lengths"])

        features.append({
            "Destination Port": flow_key[3],
            "Flow Duration": flow_duration,
            "Total Fwd Packets": total_fwd_packets,
            "Total Backward Packets": total_bwd_packets,
            "Total Length of Fwd Packets": total_fwd_length,
            "Total Length of Bwd Packets": total_bwd_length,
            "Fwd Packet Length Max": max(stats["fwd_lengths"], default=0),
            "Fwd Packet Length Min": min(stats["fwd_lengths"], default=0),
            "Fwd Packet Length Mean": mean(stats["fwd_lengths"]) if stats["fwd_lengths"] else 0,
            "Fwd Packet Length Std": stdev(stats["fwd_lengths"]) if len(stats["fwd_lengths"]) > 1 else 0,
            "Bwd Packet Length Max": max(stats["bwd_lengths"], default=0),
            "Bwd Packet Length Min": min(stats["bwd_lengths"], default=0),
            "Bwd Packet Length Mean": mean(stats["bwd_lengths"]) if stats["bwd_lengths"] else 0,
            "Bwd Packet Length Std": stdev(stats["bwd_lengths"]) if len(stats["bwd_lengths"]) > 1 else 0,
            "Flow Bytes/s": (total_fwd_length + total_bwd_length) / flow_duration if flow_duration > 0 else 0,
            "Flow Packets/s": (total_fwd_packets + total_bwd_packets) / flow_duration if flow_duration > 0 else 0,
            "SYN Flag Count": stats["syn_flags"],
            "ACK Flag Count": stats["ack_flags"],
            "FIN Flag Count": stats["fin_flags"],
            "RST Flag Count": stats["rst_flags"],
            "PSH Flag Count": stats["psh_flags"],
            "URG Flag Count": stats["urg_flags"],
            "ECE Flag Count": stats["ece_flags"],
            # Add other features as needed
        })

    for feature in features:
        if len(feature) != len(fieldnames):
            print(f"Row length mismatch: {feature}")
            
    # Write features to CSV
    # Open the file in append mode with quoting enabled
    with open(output_file, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_MINIMAL)
        writer.writerows(features)

    print(f"Captured {len(features)} flows written to {output_file}")
