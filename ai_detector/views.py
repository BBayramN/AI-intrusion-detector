from django.http import JsonResponse

from celery.result import AsyncResult

def task_status(request, task_id):
    result = AsyncResult(task_id)
    return JsonResponse({'task_id': task_id, 'status': result.status})


from django.http import JsonResponse
from .tasks import capture_model_features_task

def capture_data_view(request):
    """
    API endpoint to trigger traffic capture using Celery.
    """
    task = capture_model_features_task.delay(packet_count=500,
                                             output_file="/app/data/captured_traffic_features.csv",
                                             bpf_filter="tcp port 80 or tcp port 443")
    return JsonResponse({"status": "success", "task_id": task.id, "message": "Traffic capture started."})
