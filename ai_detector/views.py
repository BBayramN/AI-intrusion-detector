from django.http import JsonResponse


# from .tasks import capture_model_features_task
# from django.http import JsonResponse

# def capture_data(request):
#     task = capture_model_features_task.delay()  # Run the task asynchronously
#     return JsonResponse({'status': 'success', 'task_id': task.id})


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
    task = capture_model_features_task.delay(packet_count=500)
    return JsonResponse({"status": "success", "task_id": task.id, "message": "Traffic capture started."})
