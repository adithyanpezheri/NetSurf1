import argparse
import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import load_model
from autoencoder import build_autoencoder
from datetime import datetime

def preprocess_dataset(csv_path, drop_cols=None, label_col=None, for_supervised=False):
    print(f"[+] Loading dataset: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)

    # Drop repeated header rows (common in CICFlowMeter output)
    if 'Dst Port' in df.columns:
        df = df[df['Dst Port'] != 'Dst Port']

    # Drop unnecessary columns
    if drop_cols:
        df.drop(columns=drop_cols, inplace=True, errors='ignore')

    # Handle labels if supervised
    if for_supervised and label_col:
        y = df[label_col].apply(lambda x: 1 if x == 'BENIGN' else 0)
        df.drop(columns=[label_col], inplace=True)
    else:
        y = None

    # Convert all to numeric (non-numeric entries -> NaN), drop bad rows
    df = df.apply(pd.to_numeric, errors='coerce')
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Sanity check
    if df.empty:
        raise ValueError("Dataset is empty after cleaning. Check for repeated headers or malformed rows.")

    scaler = StandardScaler()
    X = scaler.fit_transform(df)

    return X, y, scaler

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--features', required=True, help='Path to features CSV')
    parser.add_argument('--model', required=True, choices=['autoencoder', 'svm', 'isoforest', 'rf'], help='Model to train')
    parser.add_argument('--labels', help='Optional label CSV for supervised training')
    parser.add_argument('--label_column', default='Label', help='Column name for class labels')
    parser.add_argument('--drop_cols', default='Flow ID, Source IP, Destination IP, Timestamp, Label', help='Comma-separated column names to drop')
    parser.add_argument('--save_scaler', action='store_true', help='Optionally save the scaler for later use')
    parser.add_argument('--output_dir', default='models', help='Directory to save trained models')
    args = parser.parse_args()

    drop_cols = [col.strip() for col in args.drop_cols.split(',')]
    for_supervised = args.model == 'rf'

    X, y, scaler = preprocess_dataset(args.features, drop_cols=drop_cols, label_col=args.label_column, for_supervised=for_supervised)

    os.makedirs(args.output_dir, exist_ok=True)

    if args.save_scaler:
        joblib.dump(scaler, os.path.join(args.output_dir, "scaler.pkl"))
        print("[+] Scaler saved.")

    if args.model == 'autoencoder':
        model = build_autoencoder(X.shape[1])
        model.model.fit(X, X, epochs=10, batch_size=32, verbose=1)
        model.model.save(os.path.join(args.output_dir, "cic_autoencoder.h5"))

        print("[+] Autoencoder model saved as cic_autoencoder.h5")

    elif args.model == 'svm':
        model = OneClassSVM(kernel='rbf', nu=0.05)
        model.fit(X)
        joblib.dump(model, os.path.join(args.output_dir, "cic_ocsvm.pkl"))
        print("[+] One-Class SVM model saved as cic_ocsvm.pkl")

    elif args.model == 'isoforest':
        model = IsolationForest(n_estimators=100, contamination=0.05)
        model.fit(X)
        joblib.dump(model, os.path.join(args.output_dir, "cic_isoforest.pkl"))
        print("[+] Isolation Forest model saved as cic_isoforest.pkl")

    elif args.model == 'rf':
        if y is None:
            raise ValueError("Supervised model requires labels.")
        model = RandomForestClassifier(n_estimators=100)
        model.fit(X, y)
        joblib.dump(model, os.path.join(args.output_dir, "cic_rf.pkl"))
        print("[+] Random Forest model saved as cic_rf.pkl")
