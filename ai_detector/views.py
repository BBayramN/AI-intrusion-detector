from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
import pprint

@csrf_exempt
def hello(request):
    if request.method == "POST":
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(request.META)
    return HttpResponse("SSH key test...")


# import pickle
# from django.http import JsonResponse
# from .utils import extract_model_features, preprocess_features

# # Load the trained AI model
# with open('webattack_detection_rf_model.pkl', 'rb') as model_file:
#     ai_model = pickle.load(model_file)
# @csrf_exempt
def test_request(request):
#     """Test request against the trained model."""
#     # Step 1: Extract features
    
#     if request.method == "POST":

#         raw_features = extract_model_features(request)

#         # Step 2: Preprocess features
#         processed_features = preprocess_features(raw_features)

#         # Step 3: Predict using the model
#         prediction = ai_model.predict([processed_features])  # Ensure input is a 2D array

#         # Step 4: Return response
#         if prediction[0] == 1:  # Assuming 1 = Attack, 0 = Normal
#             return JsonResponse({'message': 'Attack detected!'}, status=403)
    return JsonResponse({'message': 'Normal request'})
