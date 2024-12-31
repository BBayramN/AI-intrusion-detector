from django.http import JsonResponse

from celery.result import AsyncResult
from .model_process import model_input

def task_status(request, task_id):
    result = AsyncResult(task_id)
    return JsonResponse({'task_id': task_id, 'status': result.status})


from django.http import JsonResponse


# def capture_data_view(request):
#     """
#     API endpoint to trigger traffic capture using Celery.
#     """
#     task = capture_model_features_task.delay(packet_count=10000,
#                                              output_file="/app/data/captured_traffic_features.csv",
#                                              bpf_filter="tcp port 80 or tcp port 443")
#     return JsonResponse({"status": "success", "task_id": task.id, "message": "Traffic capture started."})


#from .tasks import chained_attack_detection_task



def predict(request):

    # res = model_input_task.delay()
    # res = model_input(request,'C:/Users/Bayram/Desktop/gazi/cicgit/capture_500.csv')
    try:
        result = model_input()
        return JsonResponse(result,safe=False) # Wait for the result and print it
    except Exception as e:
        return JsonResponse("No prediction",safe=False)
        
    
