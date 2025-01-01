import logging
import os
import time
from subprocess import run, PIPE

logger = logging.getLogger('ai_detector')

def capture_model_features(interface="any", packet_count=10000):
    pcap_dir = "/app/data/captures"
    pcap_file = f"{pcap_dir}/capture_{packet_count}.pcap"
    os.makedirs(pcap_dir, exist_ok=True)
    bpf_filter = "tcp port 80 or tcp port 443"
    
    # Use subprocess.run instead of os.system for better control
    tshark_cmd = [
        "tshark",
        "-i", interface,
        "-f", bpf_filter,
        "-c", str(packet_count),
        "-w", pcap_file,
        "-F", "pcap"
    ]
    
    logger.info(f"Running tshark command: {' '.join(tshark_cmd)}")
    
    try:
        result = run(tshark_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            logger.info(f"Captured {packet_count} packets on {interface}, saved to {pcap_file}")
            
            # Wait a short time to ensure the file is fully written
            time.sleep(1)
            
            # Verify the file exists and has content
            if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
                return convert_pcap_csv(packet_count)
            else:
                logger.error("PCAP file is empty or doesn't exist after capture")
                return False
        else:
            logger.error(f"Failed to capture packets with tshark. Error: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Exception during packet capture: {e}")
        return False

def convert_pcap_csv(packet_count):
    csv_dir = "/app/data/csv"
    os.makedirs(csv_dir, exist_ok=True)
    csv_file = f"{csv_dir}/capture_{packet_count}.csv"
    nftl_config = "/app/ntlflowlyzer_config"
    
    # Use subprocess.run for better error handling
    flow_cmd = ["ntlflowlyzer", "-c", nftl_config]
    
    try:
        result = run(flow_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            # Wait a short time to ensure the file is fully written
            time.sleep(1)
            
            if os.path.isfile(csv_file):
                file_size = os.path.getsize(csv_file)
                logger.info(f"CSV file generated at {csv_file} with size {file_size} bytes")
                return True
            else:
                logger.warning(f"No error reported, but {csv_file} not found.")
                return False
        else:
            logger.error(f"Flow conversion failed. Error: {result.stderr}")
            return False
    except FileNotFoundError as e:
        logger.error(f"Could not find the flow tool executable. Error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error running flow tool: {e}")
        return False