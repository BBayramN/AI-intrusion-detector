from django.http import JsonResponse
import pyshark
from .utils import capture_model_features

from django.http import JsonResponse

def capture_data(request):
    try:
        capture_model_features('/app/data/model_input_data.csv')  # Use absolute path for Docker compatibility
        return JsonResponse({'status': 'success', 'message': 'Traffic data captured successfully!'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})