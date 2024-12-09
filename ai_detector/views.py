from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import pprint
import pyshark
import csv
from django.http import JsonResponse
from datetime import datetime
import os

def capture_traffic(request):
    # File to save extracted features
    output_file = 'traffic_features.csv'
    fieldnames = [
        "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets",
        "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
        "Flow Bytes/s", "Flow Packets/s", "SYN Flag Count", "ACK Flag Count"
    ]

    # Initialize CSV file if not already created
    if not os.path.exists(output_file):
        with open(output_file, mode='w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

    try:
        # Initialize PyShark to capture packets on the primary interface
        capture = pyshark.LiveCapture(interface='lo')  # Replace 'eth0' with your active network interface

        # Capture up to 100 packets (adjust count as needed)
        flows = {}
        for packet in capture.sniff_continuously(packet_count=100):
            try:
                # Extract flow key
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                src_port = getattr(packet[packet.transport_layer], 'srcport', None)
                dst_port = getattr(packet[packet.transport_layer], 'dstport', None)
                flow_key = (src_ip, dst_ip, src_port, dst_port)

                # Initialize flow if not already present
                if flow_key not in flows:
                    flows[flow_key] = {
                        "timestamps": [],
                        "fwd_lengths": [],
                        "bwd_lengths": [],
                        "fwd_count": 0,
                        "bwd_count": 0,
                        "syn_flags": 0,
                        "ack_flags": 0,
                    }

                # Update flow stats
                flows[flow_key]["timestamps"].append(float(packet.sniff_timestamp))
                if packet.transport_layer == "TCP":
                    if "SYN" in packet.tcp.flags_str:
                        flows[flow_key]["syn_flags"] += 1
                    if "ACK" in packet.tcp.flags_str:
                        flows[flow_key]["ack_flags"] += 1

                # Direction-specific lengths
                if src_ip == packet.ip.src:
                    flows[flow_key]["fwd_lengths"].append(int(packet.length))
                    flows[flow_key]["fwd_count"] += 1
                else:
                    flows[flow_key]["bwd_lengths"].append(int(packet.length))
                    flows[flow_key]["bwd_count"] += 1

            except AttributeError:
                continue

        # Compute flow features
        features = []
        for flow_key, stats in flows.items():
            flow_duration = max(stats["timestamps"]) - min(stats["timestamps"]) if len(stats["timestamps"]) > 1 else 0
            total_fwd_packets = stats["fwd_count"]
            total_bwd_packets = stats["bwd_count"]
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
                "Fwd Packet Length Mean": (sum(stats["fwd_lengths"]) / len(stats["fwd_lengths"])) if stats["fwd_lengths"] else 0,
                "Fwd Packet Length Std": 0,  # Placeholder (add calculation if needed)
                "Bwd Packet Length Max": max(stats["bwd_lengths"], default=0),
                "Bwd Packet Length Min": min(stats["bwd_lengths"], default=0),
                "Bwd Packet Length Mean": (sum(stats["bwd_lengths"]) / len(stats["bwd_lengths"])) if stats["bwd_lengths"] else 0,
                "Bwd Packet Length Std": 0,  # Placeholder (add calculation if needed)
                "Flow Bytes/s": total_fwd_length / flow_duration if flow_duration > 0 else 0,
                "Flow Packets/s": (total_fwd_packets + total_bwd_packets) / flow_duration if flow_duration > 0 else 0,
                "SYN Flag Count": stats["syn_flags"],
                "ACK Flag Count": stats["ack_flags"],
            })

        # Save features to CSV
        with open(output_file, mode='a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writerows(features)

        return JsonResponse({'status': 'success', 'message': 'Captured traffic saved to CSV.'})

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})






# @csrf_exempt
# def hello(request):
#     if request.method == "POST":
#         pp = pprint.PrettyPrinter(indent=4)
#         pp.pprint(request.META)
#     return HttpResponse("SSH key test...")


# import pickle
# from django.http import JsonResponse
# from .utils import extract_model_features, preprocess_features

# # Load the trained AI model
# with open('webattack_detection_rf_model.pkl', 'rb') as model_file:
#     ai_model = pickle.load(model_file)
# @csrf_exempt

from django.shortcuts import redirect

def home(request):
    return redirect('capture_traffic')

