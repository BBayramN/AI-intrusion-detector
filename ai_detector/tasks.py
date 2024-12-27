# networkapp/tasks.py

from celery import shared_task, chain
from .utils import capture_model_features,convert_pcap_csv
from .model_process import model_input
import subprocess

@shared_task(bind=True)
def capture_model_features_task(self, packet_count=10000):
    """
    Celery task to run the feature extraction function asynchronously.
    """
    try:
        capture_model_features(packet_count=packet_count)
        return {"status": "success", "message": f"Traffic captured"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    


# @shared_task(bind=True)
# def convert_pcap_to_csv_task(self, pcap_file):
#     """
#     Celery task to run the feature extraction function asynchronously.
#     """
#     try:
#         convert_pcap_csv()
#         return {"status": "success", "message": f"Pcap converted to csv"}
#     except Exception as e:
#         return {"status": "error", "message": str(e)}


# @shared_task(bind=True)
# def model_input_task(self):

#     try:
#         model_input()
#         return {"status": "success", "message": f"Model processed"}
#     except Exception as e:
#         return {"status": "error", "message": str(e)}


# @shared_task(bind=True)
# def chained_attack_detection_task(self):
#     """
#     Chain tasks to capture traffic, convert PCAP to CSV, and predict attacks.
#     """
#     packet_count=10000
#     bpf_filter="tcp port 80 or tcp port 443"
#     try:
#         # Chain tasks
#         task_chain = chain(
#             capture_model_features_task.s(packet_count=packet_count, bpf_filter=bpf_filter),
#             convert_pcap_to_csv_task.s(),
#             model_input_task.s()
#         )
#         result = task_chain.apply_async()
#         return result.get(timeout=120)
#     except Exception as e:
#         # logger.error(f"Error in chained attack detection process: {e}")
#         return {"status": "error", "message": str(e)}