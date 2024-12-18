# networkapp/tasks.py

from celery import shared_task
from .utils import capture_model_features

@shared_task(bind=True)
def capture_model_features_task(self, packet_count=300, 
                                output_file="/app/data/captured_traffic_features.csv",
                                bpf_filter="tcp port 80 or tcp port 443"):
    """
    Celery task to run the feature extraction function asynchronously.
    """
    try:
        capture_model_features(output_file=output_file, 
                               packet_count=packet_count,
                               bpf_filter=bpf_filter)
        return {"status": "success", "message": f"Captured traffic written to {output_file}"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
