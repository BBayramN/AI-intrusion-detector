# networkapp/decorators.py
from functools import wraps
from .tasks import capture_model_features_task

def trigger_network_capture(packet_count=300, output_file='/app/data/captured_traffic_features.csv'):
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # Enqueue the network capture task
            capture_model_features_task.delay(packet_count=packet_count,output_file=output_file)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
