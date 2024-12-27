# networkapp/tasks.py

from celery import shared_task
from .utils import capture_model_features
from .model_process import model_input

@shared_task(bind=True)
def capture_model_features_task(self, packet_count=10000,bpf_filter="tcp port 80 or tcp port 443"):
    """
    Celery task to run the feature extraction function asynchronously.
    """
    try:
        capture_model_features(packet_count=packet_count,
                               bpf_filter=bpf_filter)
        return {"status": "success", "message": f"Traffic captured"}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    
@shared_task(bind=True)
def model_input_task(self):

    try:
        model_input()
        return {"status": "success", "message": f"Model processed"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

