import pandas as pd
import joblib
from ai_intrusion_detector.settings import AI_MODEL,AI_SCALER, AI_PCA

scaler = joblib.load(AI_SCALER)
pca = joblib.load(AI_PCA)
model = joblib.load(AI_MODEL)

def model_input():
    file = '/app/data/csv/capture_10000.csv'
    df = pd.read_csv(file)


    dataset_1 = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max',
    'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
    'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd Header Length',
    'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
    'Idle Std', 'Idle Max', 'Idle Min'
]

    col_list = col_list = ['fwd_packets_IAT_min', 'packet_IAT_min', 'bwd_init_win_bytes', 'fwd_init_win_bytes', 'duration', 'bwd_packets_rate', 'dst_port', 'packets_rate', 'fwd_packets_IAT_total', 'packet_IAT_max', 'fwd_packets_rate', 'packets_IAT_mean', 'fwd_packets_IAT_max', 'packet_IAT_std', 'bytes_rate', 'fwd_segment_size_min', 'fwd_packets_IAT_mean', 'fwd_payload_bytes_mean', 'fwd_packets_IAT_std', 'bwd_packets_IAT_min', 'down_up_rate', 'bwd_packets_count', 'payload_bytes_max', 'fwd_payload_bytes_min', 'bwd_payload_bytes_mean', 'fwd_payload_bytes_max', 'bwd_packets_IAT_mean', 'bwd_payload_bytes_std', 'bwd_packets_IAT_std', 'bwd_packets_IAT_max', 'bwd_payload_bytes_max', 'payload_bytes_std', 'active_mean', 'payload_bytes_variance', 'fwd_total_payload_bytes', 'bwd_total_payload_bytes', 'fwd_total_header_bytes', 'fwd_payload_bytes_std', 'payload_bytes_mean', 'bwd_total_header_bytes', 'fwd_packets_count', 'fwd_psh_flag_counts', 'fin_flag_counts', 'syn_flag_counts', 'rst_flag_counts', 'psh_flag_counts', 'ack_flag_counts', 'urg_flag_counts', 'ece_flag_counts', 'payload_bytes_min', 'bwd_packets_IAT_total', 'segment_size_mean', 'fwd_segment_size_mean', 'bwd_segment_size_mean', 'subflow_fwd_packets', 'subflow_fwd_bytes', 'subflow_bwd_packets', 'subflow_bwd_bytes', 'active_std', 'active_max', 'active_min', 'idle_mean', 'idle_std', 'idle_max', 'idle_min']

    new_df = df[col_list]
    new_df['act_data_pkt_fwd'] = new_df['fwd_packets_count']

    name_mapping = {   
    # Existing 41 entries:
    'fwd_packets_IAT_min':      'Fwd IAT Min',
    'packet_IAT_min':           'Flow IAT Min',
    'bwd_init_win_bytes':       'Init_Win_bytes_backward',
    'fwd_init_win_bytes':       'Init_Win_bytes_forward',
    'duration':                 'Flow Duration',
    'bwd_packets_rate':         'Bwd Packets/s',
    'dst_port':                 'Destination Port',
    'packets_rate':             'Flow Packets/s',
    'fwd_packets_IAT_total':    'Fwd IAT Total',
    'packet_IAT_max':           'Flow IAT Max',
    'fwd_packets_rate':         'Fwd Packets/s',
    'packets_IAT_mean':         'Flow IAT Mean',
    'fwd_packets_IAT_max':      'Fwd IAT Max',
    'packet_IAT_std':           'Flow IAT Std',
    'bytes_rate':               'Flow Bytes/s',
    'fwd_segment_size_min':     'min_seg_size_forward',
    'fwd_packets_IAT_mean':     'Fwd IAT Mean',
    'fwd_payload_bytes_mean':   'Fwd Packet Length Mean',
    'fwd_packets_IAT_std':      'Fwd IAT Std',
    'bwd_packets_IAT_min':      'Bwd IAT Min',
    'down_up_rate':             'Down/Up Ratio',
    'bwd_packets_count':        'Total Backward Packets',
    'payload_bytes_max':        'Max Packet Length',
    'fwd_payload_bytes_min':    'Fwd Packet Length Min',
    'bwd_payload_bytes_mean':   'Bwd Packet Length Mean',
    'fwd_payload_bytes_max':    'Fwd Packet Length Max',
    'bwd_packets_IAT_mean':     'Bwd IAT Mean',
    'bwd_payload_bytes_std':    'Bwd Packet Length Std',
    'bwd_packets_IAT_std':      'Bwd IAT Std',
    'bwd_packets_IAT_max':      'Bwd IAT Max',
    'bwd_payload_bytes_max':    'Bwd Packet Length Max',
    'payload_bytes_std':        'Packet Length Std',
    'active_mean':              'Active Mean',
    'payload_bytes_variance':   'Packet Length Variance',
    'fwd_total_payload_bytes':  'Total Length of Fwd Packets',
    'bwd_total_payload_bytes':  'Total Length of Bwd Packets',
    'fwd_total_header_bytes':   'Fwd Header Length',
    'fwd_payload_bytes_std':    'Fwd Packet Length Std',
    'payload_bytes_mean':       'Packet Length Mean',
    'bwd_total_header_bytes':   'Bwd Header Length',
    'fwd_packets_count':        'Total Fwd Packets',

    # Newly added to reach 67 total requirements:

    # Flags
    'fwd_psh_flag_counts':      'Fwd PSH Flags',
    'fin_flag_counts':          'FIN Flag Count',
    'syn_flag_counts':          'SYN Flag Count',
    'rst_flag_counts':          'RST Flag Count',
    'psh_flag_counts':          'PSH Flag Count',
    'ack_flag_counts':          'ACK Flag Count',
    'urg_flag_counts':          'URG Flag Count',
    'ece_flag_counts':          'ECE Flag Count',

    # Min Packet Length (we have payload_bytes_max but also need min)
    'payload_bytes_min':        'Min Packet Length',

    # Bwd IAT Total
    'bwd_packets_IAT_total':      'Bwd IAT Total',

    # Average Packet Size / Segments
    'segment_size_mean':        'Average Packet Size',
    'fwd_segment_size_mean':    'Avg Fwd Segment Size',
    'bwd_segment_size_mean':    'Avg Bwd Segment Size',

    # Subflows
    'subflow_fwd_packets':      'Subflow Fwd Packets',
    'subflow_fwd_bytes':        'Subflow Fwd Bytes',
    'subflow_bwd_packets':      'Subflow Bwd Packets',
    'subflow_bwd_bytes':        'Subflow Bwd Bytes',

    # “act_data_pkt_fwd” placeholder
    'act_data_pkt_fwd':         'act_data_pkt_fwd',

    # Active / Idle stats
    'active_std':               'Active Std',
    'active_max':               'Active Max',
    'active_min':               'Active Min',
    'idle_mean':                'Idle Mean',
    'idle_std':                 'Idle Std',
    'idle_max':                 'Idle Max',
    'idle_min':                 'Idle Min'
}


    mapped_dataset2 = new_df.rename(columns=name_mapping)
    dataset2_aligned = mapped_dataset2.reindex(columns=dataset_1, fill_value=0)

    X_test_filtered_scaled = scaler.transform(dataset2_aligned)
    X_test_pca = pca.transform(X_test_filtered_scaled)
    pred = model.predict(X_test_pca)


    pred_list = pred.tolist()
    return pred_list