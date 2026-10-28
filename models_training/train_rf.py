import os
import glob

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


# Path where CIC-IDS2017 CSV files are stored
DATASET_DIR = "cicids2017"

# Output model path
MODEL_PATH = "models_training/model.pkl"


def normalize_column_name(column_name: str) -> str:
    """
    Converts column names such as:
        'Total Fwd Packets'
    into:
        'total_fwd_packets'
    """
    return (
        str(column_name)
        .strip()
        .lower()
        .replace("/", "_per_")
        .replace(" ", "_")
        .replace("-", "_")
    )


def load_and_preprocess_data(data_dir: str):
    csv_files = glob.glob(os.path.join(data_dir, "*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in directory: {os.path.abspath(data_dir)}"
        )

    dfs = []

    print(f"[*] Found {len(csv_files)} CSV files. Loading data...")

    for file_path in csv_files:
        print(f" -> Reading {os.path.basename(file_path)}...")

        df = pd.read_csv(file_path, low_memory=False)

        # Normalize CSV column names before applying the mapping
        df.columns = [
            normalize_column_name(column)
            for column in df.columns
        ]

        dfs.append(df)

    combined_df = pd.concat(dfs, ignore_index=True)

    print(f"[*] Combined dataset shape: {combined_df.shape}")

    # Handle missing 'source_port'
    if "source_port" not in combined_df.columns:
        print("[!] Source Port column missing. Using 0 instead.")
        combined_df["source_port"] = 0

    # Handle missing 'protocol' column in CIC-IDS2017 CSVs
    if "protocol" not in combined_df.columns:
        print("[!] Protocol column missing in CSV dataset. Inferring/Defaulting to TCP (6)...")
        # If TCP flag counts are present and non-zero, assign 6 (TCP), else 17 (UDP)
        if "syn_flag_count" in combined_df.columns or "ack_flag_count" in combined_df.columns:
            combined_df["protocol"] = 6
        else:
            combined_df["protocol"] = 6

    feature_mapping = {
        "source_port": "src_port",
        "destination_port": "dst_port",
        "protocol": "protocol",
        "flow_duration": "flow_duration",
        "total_fwd_packets": "total_packets_fwd",
        "total_backward_packets": "total_packets_bwd",
        "total_length_of_fwd_packets": "bytes_fwd",
        "total_length_of_bwd_packets": "bytes_bwd",
        "packet_length_mean": "packet_length_mean",
        "packet_length_std": "packet_length_std",
        "flow_bytes_per_s": "bytes_per_second",
        "flow_packets_per_s": "packets_per_second",
        "label": "label",
    }

    required_columns = list(feature_mapping.keys())

    missing_columns = [
        column
        for column in required_columns
        if column not in combined_df.columns
    ]

    if missing_columns:
        print("\n[!] Missing required columns:")
        for column in missing_columns:
            print(f"    - {column}")

        raise ValueError(
            "\nThe dataset does not contain all required CIC-IDS2017 columns."
        )

    # Keep only required columns
    df_filtered = combined_df[required_columns].copy()

    # Rename columns to model's internal feature names
    df_filtered.rename(columns=feature_mapping, inplace=True)

    # Convert feature columns to numeric values
    numeric_columns = [
        "src_port",
        "dst_port",
        "protocol",
        "flow_duration",
        "total_packets_fwd",
        "total_packets_bwd",
        "bytes_fwd",
        "bytes_bwd",
        "packet_length_mean",
        "packet_length_std",
        "bytes_per_second",
        "packets_per_second",
    ]

    for column in numeric_columns:
        df_filtered[column] = pd.to_numeric(
            df_filtered[column],
            errors="coerce"
        )

    # Calculate aggregate metrics
    df_filtered["total_packets"] = (
        df_filtered["total_packets_fwd"]
        + df_filtered["total_packets_bwd"]
    )

    df_filtered["total_bytes"] = (
        df_filtered["bytes_fwd"]
        + df_filtered["bytes_bwd"]
    )

    # Features expected by inference.py
    features = [
        "src_port",
        "dst_port",
        "protocol",
        "flow_duration",
        "total_packets",
        "total_bytes",
        "packet_length_mean",
        "packet_length_std",
        "bytes_per_second",
        "packets_per_second",
    ]

    X = df_filtered[features].copy()
    y = df_filtered["label"].copy()

    # Replace infinity values with NaN and fill with 0
    print("[*] Cleaning NaN and Infinity values...")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(0)

    # Convert labels to integer classes
    def map_label(label):
        label = str(label).strip().upper()

        if "BENIGN" in label:
            return 0
        elif "DDOS" in label or "DOS" in label:
            return 1
        elif "PORTSCAN" in label or "PORT SCAN" in label:
            return 2
        elif "BOT" in label:
            return 3
        else:
            return 4

    y = y.apply(map_label)

    print(f"[*] Final feature shape: {X.shape}")
    print("[*] Label distribution:")
    print(y.value_counts().sort_index())

    return X, y


def train():
    X, y = load_and_preprocess_data(DATASET_DIR)

    if len(X) > 500_000:
        print("[*] Dataset contains more than 500,000 records.")
        print("[*] Downsampling for efficient Random Forest training...")

        X, _, y, _ = train_test_split(
            X,
            y,
            train_size=500_000,
            stratify=y,
            random_state=42,
        )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    print(f"[*] Training samples: {len(X_train)}")
    print(f"[*] Testing samples: {len(X_test)}")

    print("[*] Training Random Forest Classifier...")

    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )

    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)

    print("\n[+] Classification Report:")
    print(
        classification_report(
            y_test,
            y_pred,
            zero_division=0
        )
    )

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(rf, MODEL_PATH)

    print(f"[+] Model successfully saved to: {MODEL_PATH}")


if __name__ == "__main__":
    train()