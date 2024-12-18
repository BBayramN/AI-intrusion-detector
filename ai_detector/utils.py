import pyshark
import csv
import os
import numpy as np
from statistics import mean, stdev
from django.conf import settings
import pandas as pd
import logging

# Setup logging
logger = logging.getLogger(__name__)


# Define all expected feature names (67 columns)
FIELDNAMES = [
    # Port and Flow Characteristics
    "Destination Port", "Flow Duration", 
    
    # Packet Counts
    "Total Fwd Packets", "Total Backward Packets",
    
    # Packet Lengths
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", 
    "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", 
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
    
    # Flow Rates
    "Flow Bytes/s", "Flow Packets/s", 
    
    # Inter-Arrival Times (IAT)
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", 
    "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", 
    "Bwd IAT Max", "Bwd IAT Min",
    
    # Flags and Headers
    "Fwd PSH Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", 
    
    # Packet Size Statistics
    "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    
    # TCP Flags
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", 
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", 
    "ECE Flag Count", 
    
    # Ratio and Averages
    "Down/Up Ratio", "Average Packet Size", 
    "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    
    # Subflow Metrics
    "Subflow Fwd Packets", "Subflow Fwd Bytes", 
    "Subflow Bwd Packets", "Subflow Bwd Bytes",
    
    # Window and Initialization Metrics
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", 
    "act_data_pkt_fwd", "min_seg_size_forward",
    
    # Active and Idle Times
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

def calculate_feature_columns(flows):
    """
    Calculate comprehensive network flow features.
    
    Args:
        flows (dict): Dictionary of network flow statistics
    
    Returns:
        list: Calculated feature values for each flow
    """
    results = []
    
    for flow_key, stats in flows.items():
        # Ensure minimum data requirements
        if not stats['timestamps'] or len(stats['timestamps']) < 2:
            continue
        
        # Calculate Inter-Arrival Times (IAT)
        iat = [stats['timestamps'][i] - stats['timestamps'][i-1] 
               for i in range(1, len(stats['timestamps']))]
        
        # Separate forward and backward packets
        fwd_lengths = stats['fwd_lengths']
        bwd_lengths = stats['bwd_lengths']
        
        # Comprehensive feature calculation
        flow_features = {
            # Basic Flow Characteristics
            "Destination Port": flow_key[3],
            "Flow Duration": stats['timestamps'][-1] - stats['timestamps'][0],
            
            # Packet Counts
            "Total Fwd Packets": len(fwd_lengths),
            "Total Backward Packets": len(bwd_lengths),
            
            # Packet Length Metrics
            "Total Length of Fwd Packets": sum(fwd_lengths) if fwd_lengths else 0,
            "Total Length of Bwd Packets": sum(bwd_lengths) if bwd_lengths else 0,
            
            # Forward Packet Length Statistics
            "Fwd Packet Length Max": max(fwd_lengths) if fwd_lengths else 0,
            "Fwd Packet Length Min": min(fwd_lengths) if fwd_lengths else 0,
            "Fwd Packet Length Mean": np.mean(fwd_lengths) if fwd_lengths else 0,
            "Fwd Packet Length Std": np.std(fwd_lengths) if len(fwd_lengths) > 1 else 0,
            
            # Backward Packet Length Statistics
            "Bwd Packet Length Max": max(bwd_lengths) if bwd_lengths else 0,
            "Bwd Packet Length Min": min(bwd_lengths) if bwd_lengths else 0,
            "Bwd Packet Length Mean": np.mean(bwd_lengths) if bwd_lengths else 0,
            "Bwd Packet Length Std": np.std(bwd_lengths) if len(bwd_lengths) > 1 else 0,
            
            # Flow Rates
            "Flow Bytes/s": (sum(fwd_lengths) + sum(bwd_lengths)) / (stats['timestamps'][-1] - stats['timestamps'][0]) if stats['timestamps'] else 0,
            "Flow Packets/s": len(stats['timestamps']) / (stats['timestamps'][-1] - stats['timestamps'][0]) if stats['timestamps'] else 0,
            
            # Inter-Arrival Time (IAT) Metrics
            "Flow IAT Mean": np.mean(iat) if iat else 0,
            "Flow IAT Std": np.std(iat) if len(iat) > 1 else 0,
            "Flow IAT Max": max(iat) if iat else 0,
            "Flow IAT Min": min(iat) if iat else 0,
            
            # TCP Flag Counts
            "SYN Flag Count": stats.get('syn_flags', 0),
            "ACK Flag Count": stats.get('ack_flags', 0),
            "FIN Flag Count": stats.get('fin_flags', 0),
            "RST Flag Count": stats.get('rst_flags', 0),
            "PSH Flag Count": stats.get('psh_flags', 0),
            "URG Flag Count": stats.get('urg_flags', 0),
            "ECE Flag Count": stats.get('ece_flags', 0)
        }
        
        # Fill remaining columns with default values
        for field in FIELDNAMES:
            if field not in flow_features:
                flow_features[field] = None
        
        results.append(flow_features)
    
    return results

def capture_model_features(
    output_file="/app/data/network_features.csv", 
    # output_excel_file="/app/data/network_features.xlsx",
    interface="eth0", 
    packet_count=100,
    bpf_filter="tcp port 80 or tcp port 443"
):
    """
    Capture network traffic features and save to CSV and Excel.
    
    Args:
        output_file (str): Path to output CSV file
        output_excel_file (str): Path to output Excel file
        interface (str): Network interface to capture traffic
        packet_count (int): Number of packets to capture
    """
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    try:
    # Start capturing traffic
        capture = pyshark.LiveCapture(interface=interface)
        flows = {}
    
    # Capture packets
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

            except AttributeError as e:
                logger.warning(f"AttributeError encountered: {e}")
                continue
        
        # Calculate features
        features = calculate_feature_columns(flows)
        
        if features:
            # Save to CSV
            df = pd.DataFrame(features)
            df.to_csv(output_file, index=False)
            
            # Save to Excel
            # df.to_excel(output_excel_file, index=False)
            
            logger.info(f"Network features saved to {output_file}")
        else:
            logger.info("No network features captured.")
    
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")


# # Example usage
# if __name__ == "__main__":
#     capture_network_features()