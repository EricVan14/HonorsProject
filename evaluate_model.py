import sys
import pandas as pd
import joblib
import numpy as np

def load_data(csv_file_path):
    # Load the features from the created CSV, excluding IP addresses for the feature set
    data = pd.read_csv(csv_file_path)
    IPs = data[['Src_IP', 'Dst_IP']]
    X = data[['StDev_pkts_length', 'Max_payload', 'Avg_pkts_length', 'Min_pkts_length']]
    return X, IPs

def preprocess_data(X, scaler_path):
    # Scaling the data
    scaler = joblib.load(scaler_path)
    X_scaled = scaler.transform(X)
    return X_scaled

def evaluate_model(model_path, scaler_path, X, IPs):
    # Load the model and predict Tor likelihood
    model = joblib.load(model_path)
    X_processed = preprocess_data(X, scaler_path)
    y_pred_proba = model.predict_proba(X_processed)[:, 1]  # Get confidence scores for the positive class
    
    # Filter for high-confidence Tor predictions
    tor_ips = IPs[y_pred_proba > 0.5]  # Example threshold, adjust based on your model
    tor_ips['Confidence'] = y_pred_proba[y_pred_proba > 0.5]
    
    # Return unique Tor IPs with average confidence
    unique_tor_ips = tor_ips.groupby(['Src_IP', 'Dst_IP']).Confidence.mean().reset_index()
    return unique_tor_ips

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python evaluate_model.py <model_path> <scaler_path> <csv_file_path>")
        sys.exit(1)
    
    model_path = sys.argv[1]
    scaler_path = sys.argv[2]
    csv_file_path = sys.argv[3]

    X, IPs = load_data(csv_file_path)
    tor_ips = evaluate_model(model_path, scaler_path, X, IPs)
    print(tor_ips.to_json(orient="records"))
