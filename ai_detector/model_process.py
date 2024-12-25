import pandas as pd
import joblib
from ai_intrusion_detector.settings import AI_MODEL,AI_SCALER

scaler = joblib.load(AI_SCALER)
model = joblib.load(AI_MODEL)

def model_input(request):
    file = '/app/data/csv/capture_500.csv'
    df = pd.read_csv(file)

    dataset_1 = [
       'Fwd IAT Min', 'Flow IAT Min', 'Init_Win_bytes_backward',
       'Init_Win_bytes_forward', 'Flow Duration', 'Bwd Packets/s',
       'Destination Port', 'Flow Packets/s', 'Fwd IAT Total', 'Flow IAT Max',
       'Fwd Packets/s', 'Flow IAT Mean', 'Fwd IAT Max', 'Flow IAT Std',
       'Flow Bytes/s', 'min_seg_size_forward', 'Fwd IAT Mean',
       'Fwd Packet Length Mean', 'Fwd IAT Std', 'Bwd IAT Min', 'Down/Up Ratio',
       'Total Backward Packets', 'Max Packet Length', 'Fwd Packet Length Min',
       'Bwd Packet Length Mean', 'Fwd Packet Length Max', 'Bwd IAT Mean',
       'Bwd Packet Length Std', 'Bwd IAT Total', 'Bwd IAT Std', 'Bwd IAT Max',
       'Bwd Packet Length Max', 'Packet Length Std', 'Active Mean',
       'Packet Length Variance', 'Total Length of Fwd Packets',
       'Total Length of Bwd Packets', 'Fwd Header Length',
       'Fwd Packet Length Std', 'act_data_pkt_fwd', 'Packet Length Mean',
       'Bwd Header Length', 'Total Fwd Packets'
    ]

    col_list = [
    'dst_port',
    'duration',
    'fwd_packets_count',
    'bwd_packets_count',
    'fwd_total_payload_bytes',
    'bwd_total_payload_bytes',
    'fwd_payload_bytes_max',
    'fwd_payload_bytes_min',
    'fwd_payload_bytes_mean',
    'fwd_payload_bytes_std',
    'bwd_payload_bytes_max',
    'bwd_payload_bytes_min',
    'bwd_payload_bytes_mean',
    'bwd_payload_bytes_std',
    'bytes_rate',
    'packets_rate',
    'packets_IAT_mean',
    'packet_IAT_std',
    'packet_IAT_max',
    'packet_IAT_min',
    'fwd_packets_IAT_total',
    'fwd_packets_IAT_mean',
    'fwd_packets_IAT_std',
    'fwd_packets_IAT_max',
    'fwd_packets_IAT_min',
    'bwd_packets_IAT_min',
    'bwd_packets_IAT_mean',
    'bwd_packets_IAT_std',
    'bwd_packets_IAT_max',
    'fwd_psh_flag_counts',
    'fwd_total_header_bytes',
    'bwd_total_header_bytes',
    'fwd_packets_rate',
    'bwd_packets_rate',
    'payload_bytes_min',
    'payload_bytes_max',
    'payload_bytes_mean',
    'payload_bytes_std',
    'payload_bytes_variance',
    'fin_flag_counts',
    'syn_flag_counts',
    'rst_flag_counts',
    'psh_flag_counts',
    'ack_flag_counts',
    'urg_flag_counts',
    'ece_flag_counts',
    'down_up_rate',
    'segment_size_mean',
    'fwd_segment_size_mean',
    'bwd_segment_size_mean',
    'subflow_fwd_packets',
    'subflow_fwd_bytes',
    'subflow_bwd_packets',
    'subflow_bwd_bytes',
    'fwd_init_win_bytes',
    'bwd_init_win_bytes',
    'active_mean',
    'active_std',
    'active_max',
    'active_min',
    'idle_mean',
    'idle_std',
    'idle_max',
    'idle_min',
    'fwd_segment_size_min'
]

    new_df = df[col_list]
    new_df['act_data_pkt_fwd'] = new_df['fwd_packets_count']

    name_mapping = {   
    'fwd_packets_IAT_min': 'Fwd IAT Min',
    'packet_IAT_min': 'Flow IAT Min',
    'bwd_init_win_bytes': 'Init_Win_bytes_backward',
    'fwd_init_win_bytes': 'Init_Win_bytes_forward',
    'duration': 'Flow Duration',
    'bwd_packets_rate': 'Bwd Packets/s',
    'dst_port': 'Destination Port',
    'packets_rate': 'Flow Packets/s',
    'fwd_packets_IAT_total': 'Fwd IAT Total',
    'packet_IAT_max': 'Flow IAT Max',
    'fwd_packets_rate': 'Fwd Packets/s',
    'packets_IAT_mean': 'Flow IAT Mean',
    'fwd_packets_IAT_max': 'Fwd IAT Max',
    'packet_IAT_std': 'Flow IAT Std',
    'bytes_rate': 'Flow Bytes/s',
    'fwd_segment_size_min': 'min_seg_size_forward',
    'fwd_packets_IAT_mean': 'Fwd IAT Mean',
    'fwd_payload_bytes_mean': 'Fwd Packet Length Mean',
    'fwd_packets_IAT_std': 'Fwd IAT Std',
    'bwd_packets_IAT_min': 'Bwd IAT Min',
    'down_up_rate': 'Down/Up Ratio',
    'bwd_packets_count': 'Total Backward Packets',
    'payload_bytes_max': 'Max Packet Length',
    'fwd_payload_bytes_min': 'Fwd Packet Length Min',
    'bwd_payload_bytes_mean': 'Bwd Packet Length Mean',
    'fwd_payload_bytes_max': 'Fwd Packet Length Max',
    'bwd_packets_IAT_mean': 'Bwd IAT Mean',
    'bwd_payload_bytes_std': 'Bwd Packet Length Std',
    'bwd_packets_IAT_std': 'Bwd IAT Std',
    'bwd_packets_IAT_max': 'Bwd IAT Max',
    'bwd_payload_bytes_max': 'Bwd Packet Length Max',
    'payload_bytes_std': 'Packet Length Std',
    'active_mean': 'Active Mean',
    'payload_bytes_variance': 'Packet Length Variance',
    'fwd_total_payload_bytes': 'Total Length of Fwd Packets',
    'bwd_total_payload_bytes': 'Total Length of Bwd Packets',
    'fwd_total_header_bytes': 'Fwd Header Length',
    'fwd_payload_bytes_std': 'Fwd Packet Length Std',
    'payload_bytes_mean': 'Packet Length Mean',
    'bwd_total_header_bytes': 'Bwd Header Length',
    'fwd_packets_count': 'Total Fwd Packets'

}

    mapped_dataset2 = new_df.rename(columns=name_mapping)
    dataset2_aligned = mapped_dataset2.reindex(columns=dataset_1, fill_value=0)

    X_test_filtered_scaled = scaler.transform(dataset2_aligned)
    pred = model.predict(X_test_filtered_scaled)

    pred_list = pred.tolist()
    return pred_list