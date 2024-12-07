import pickle
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


# Load your AI model (ensure the path to your model is correct)
with open('webattack_detection_rf_model.pkl', 'rb') as model_file:
    ai_model = pickle.load(model_file)


class AIDetectionMiddleware:
    """Middleware to integrate AI model for detecting brute force or web attacks."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Apply AI model only to the admin login endpoint
        if request.path == '/admin/login/':
            # Extract features for the model
            features = self.extract_features(request)
            print(features)

            # Predict using the AI model
            prediction = ai_model.predict([features])
            print("pred",prediction)
            # If the model detects an attack (assuming 1 = attack, 0 = normal)
            if prediction[0] == 1:
                # return JsonResponse(
                #     {'error': 'Suspicious activity detected, request blocked.'},
                #     status=403
                # )
                print("ATTACKKKK")

        response = self.get_response(request)
        return response

    def extract_features(self, request):
        """Extract features from the request for the AI model."""
        # Replace with your actual feature extraction logic
        # Example features (simplified for demonstration)
        features = {
            'Average Packet Size': len(request.body),
            'Flow Bytes/s': len(request.body),  # Simplification
            'Max Packet Length': len(request.body),  # Simplification
            'Fwd Packet Length Mean': len(request.body),
            'Fwd IAT Min': 0,  # Replace with actual calculation
            'Total Length of Fwd Packets': len(request.body),
            'Flow IAT Mean': 0,  # Replace with actual calculation
            'Fwd Packet Length Max': len(request.body),
            'Fwd IAT Std': 0,  # Replace with actual calculation
            'Fwd Header Length': len(request.headers)
        }
        # Return features in the same order as expected by your model
        return [
            features['Average Packet Size'],
            features['Flow Bytes/s'],
            features['Max Packet Length'],
            features['Fwd Packet Length Mean'],
            features['Fwd IAT Min'],
            features['Total Length of Fwd Packets'],
            features['Flow IAT Mean'],
            features['Fwd Packet Length Max'],
            features['Fwd IAT Std'],
            features['Fwd Header Length']
        ]
