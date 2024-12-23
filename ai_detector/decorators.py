# networkapp/decorators.py
from functools import wraps
from .tasks import capture_model_features_task

def trigger_network_capture(packet_count=300, bpf_filter="tcp port 80 or tcp port 443"):
    """
    Decorator to trigger network capture with specified parameters.
    
    Args:
        packet_count (int): Number of packets to capture.
        output_file (str): File path to save the captured traffic features.
        bpf_filter (str): BPF filter to apply during packet capture.
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Enqueue the network capture task with specified parameters
            capture_model_features_task.delay(
                packet_count=packet_count,
                bpf_filter=bpf_filter
            )
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
