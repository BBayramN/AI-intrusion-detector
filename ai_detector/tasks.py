from celery import shared_task

@shared_task
def capture_model_features_task(output_file = '/app/data/model_input_data.csv'):
    from .utils import capture_model_features  # Import your function
    capture_model_features(output_file)
    return f"Data captured and saved to {output_file}"
