from django.http import JsonResponse
import pyshark
import csv
import os

def capture_traffic(request):

    # Test file writing
    # with open(output_file, mode='a', newline='') as f:
    #     writer = csv.DictWriter(f, fieldnames=fieldnames)
    #     writer.writerow({
    #         "Source IP": "192.168.1.1",
    #         "Destination IP": "192.168.1.2",
    #         "Source Port": "5000",
    #         "Destination Port": "443",
    #         "Timestamp": "1696484737.123456",
    #         "Packet Length": "1500"
    #     })

    output_file = '/app/flow_data.csv'
    fieldnames = ["Source IP", "Destination IP", "Source Port", "Destination Port", "Timestamp", "Packet Length"]

    # Initialize CSV if it doesn't exist
    if not os.path.exists(output_file):
        with open(output_file, mode='w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

    try:
        capture = pyshark.LiveCapture(interface='eth0')  # Replace 'eth0' with your active interface
        flows = []

        # Capture packets
        for packet in capture.sniff_continuously(packet_count=100):  # Adjust packet_count as needed
            try:
                src_ip = getattr(packet.ip, 'src', None)
                dst_ip = getattr(packet.ip, 'dst', None)
                src_port = getattr(packet[packet.transport_layer], 'srcport', None)
                dst_port = getattr(packet[packet.transport_layer], 'dstport', None)
                timestamp = packet.sniff_timestamp
                packet_length = int(packet.length)

                if src_ip and dst_ip and src_port and dst_port:
                    flows.append({
                        "Source IP": src_ip,
                        "Destination IP": dst_ip,
                        "Source Port": src_port,
                        "Destination Port": dst_port,
                        "Timestamp": timestamp,
                        "Packet Length": packet_length
                    })

            except AttributeError:
                # Skip packets missing required attributes
                continue

        # Write flows to CSV
        with open(output_file, mode='a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writerows(flows)

        return JsonResponse({'status': 'success', 'message': f'{len(flows)} flows captured and saved to CSV.'})

    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})
