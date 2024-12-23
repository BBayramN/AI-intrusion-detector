import logging
import os



logger = logging.getLogger('ai_detector')

def capture_model_features(interface="eth0", packet_count=500, bpf_filter="tcp port 80 or tcp port 443"):
    pcap_dir = "/app/data/captures"
    pcap_file = f"{pcap_dir}/capture_{packet_count}.pcap"
    os.makedirs(pcap_dir, exist_ok=True)
    tshark_cmd = f"tshark -i {interface} -c {packet_count}  -w {pcap_file} -F pcap" # -F change pcapng to pcap
    # -f {bpf_filter}
    
    logger.info(f"Running tshark command: {tshark_cmd}")

    ret = os.system(tshark_cmd)
    if ret == 0:
        logger.info(f"Captured {packet_count} packets on {interface}, saved to {pcap_file}")
    else:
        logger.error(f"Failed to capture packets with tshark. Return code: {ret}")


    # Step 2: Convert the .pcap to CSV using new Python flow library
    csv_dir = "/app/data/csv"
    os.makedirs(csv_dir, exist_ok=True)
    csv_file = f"{csv_dir}/capture_{packet_count}.csv"

    nftl_config = "/app/ntlflowlyzer_config"
    flow_cmd = f"ntlflowlyzer -c {nftl_config}"


    logger.info(f"Converting {pcap_file} to {csv_file} with new flow library: {' '.join(flow_cmd)}")

    try:
        result = os.system(flow_cmd)
        if result.returncode == 0:
            if os.path.isfile(csv_file):
                logger.info(f"CSV file generated at {csv_file}")
            else:
                logger.warning(f"No error reported, but {csv_file} not found. The tool might store CSV differently.")
        else:
            logger.error(f"Flow conversion failed (exit code {result.returncode}). Stderr:\n{result.stderr}")
    except FileNotFoundError as e:
        logger.error(f"Could not find the flow tool executable. Check if it's installed. Error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error running flow tool: {e}")