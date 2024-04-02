import sys
import pandas as pd
import joblib
from sklearn.metrics import accuracy_score

def load_data(csv_file_path):
    """
    Load the features and labels from the CSV file.
    """
    data = pd.read_csv(csv_file_path)
    # Correcting the selection of multiple columns
    X = data[['StDev_pkts_length', 'Max_payload', 'Avg_pkts_length', 'Min_pkts_length']]
    y = data['Label']
    return X, y

def preprocess_data(X, scaler_path):
    """
    Apply preprocessing to the data (e.g., scaling).
    """
    scaler = joblib.load(scaler_path)
    X_scaled = scaler.transform(X)
    return X_scaled

def evaluate_model(model_path, scaler_path, X, y):
    """
    Load the model, predict labels, and evaluate accuracy.
    """
    model = joblib.load(model_path)
    X_processed = preprocess_data(X, scaler_path)
    y_pred = model.predict(X_processed)
    accuracy = accuracy_score(y, y_pred)
    return accuracy

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python evaluate_model.py <model_path> <scaler_path> <csv_file_path>")
        sys.exit(1)
    
    model_path = sys.argv[1]
    scaler_path = sys.argv[2]
    csv_file_path = sys.argv[3]

    X, y = load_data(csv_file_path)
    accuracy = evaluate_model(model_path, scaler_path, X, y)
    print(accuracy)
