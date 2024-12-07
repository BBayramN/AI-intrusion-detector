from datetime import datetime

def extract_model_features(request):
    """Extract and calculate features for the model."""
    # Start capturing time
    start_time = datetime.now()

    # Extract simple features from request
    total_fwd_packets = 1  # Assuming 1 request = 1 packet (simplified for now)
    total_length_fwd_packets = len(request.body)

    # Calculate features
    features = {
        'Average Packet Size': total_length_fwd_packets / total_fwd_packets,
        'Flow Bytes/s': total_length_fwd_packets / 1,  # Assuming 1 second for simplicity
        'Max Packet Length': len(request.body),  # Assuming body size for now
        'Fwd Packet Length Mean': len(request.body),  # Average length (only one packet here)
        'Fwd IAT Min': 0,  # Need timestamps for multiple packets
        'Total Length of Fwd Packets': total_length_fwd_packets,
        'Flow IAT Mean': 0,  # Placeholder
        'Fwd Packet Length Max': len(request.body),
        'Fwd IAT Std': 0,  # Placeholder
        'Fwd Header Length': len(request.headers),  # Simplified header length
    }

    # Calculate flow duration
    end_time = datetime.now()
    flow_duration = (end_time - start_time).total_seconds()
    features['Flow Bytes/s'] = total_length_fwd_packets / flow_duration if flow_duration > 0 else 0

    return features


def preprocess_features(features):
    """Convert features into a list in the correct order for the model."""
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
        features['Fwd Header Length'],
    ]
