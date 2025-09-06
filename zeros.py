import os
import socket
import subprocess
import logging
import psutil
import json
import pickle
import time
import nmap
import numpy as np
from datetime import datetime
from tqdm import tqdm
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import hashlib
import random
import string
import pydot
import yara
import volatility3
from volatility3.framework import contexts, symbols
from volatility3.plugins.windows import pslist, memmap
from main import preprocess_dataset
from autoencoder import build_autoencoder
import pandas as pd
from oneclass_svm import  train_model
import joblib
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, LSTM, RepeatVector, TimeDistributed, Dense
from collections import Counter
from volatility3.framework import symbols
import numpy as np
import matplotlib.pyplot as plt
from sklearn.feature_selection import VarianceThreshold



def build_lstm_autoencoder(seq_len, n_features):
    inputs = Input(shape=(seq_len, n_features))
    encoded = LSTM(64, activation='relu')(inputs)
    repeated = RepeatVector(seq_len)(encoded)
    decoded = LSTM(64, return_sequences=True)(repeated)
    outputs = TimeDistributed(Dense(n_features))(decoded)

    model = Model(inputs, outputs)
    model.compile(optimizer='adam', loss='mse')
    return model



from autoencoder import build_autoencoder, load_model as load_ae_model
from oneclass_svm import load_model as load_svm_model

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("NetSurf")

class NetSurf:
    def __init__(self):
        self.results_dir = "netsurf_results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.ml_models = {}
        self.advanced_analysis = {
            'process': False,
            'memory': False,
            'dataflow': False,
            'taint': False,
            'fuzzing': False,
            'hashing': False
        }
        self.model_anomaly_counts = {}

    def display_banner(self):
        banner = r"""
NN   NN   EEEEEEE   TTTTTTT    SSSSSS   UU   UU   RRRRRR    FFFFFFF         111         OOOOO  
NNN  NN   EE           TT     SS        UU   UU   RR   RR   FF             1111        O     O 
NN N NN   EEEEEE       TT      SSSSSS   UU   UU   RRRRRR    FFFFFF          111         O     O 
NN  NNN   EE           TT          SS   UU   UU   RR   RR   FF              111   ...   O     O 
NN   NN   EEEEEEE      TT     SSSSSS     UUUUU    RR   RR   FF           1111111  ...    OOOOO  

  NetSurf - Zero-Day Detection Framework
  By: Adithyan P
        """
        print(banner)

    def configure_advanced_features(self):
        print("\nConfigure Advanced Analysis Features:")
        print("[1] Process Analysis")
        print("[2] Memory Analysis")
        print("[3] Data Flow Analysis")
        print("[4] Taint Analysis")
        print("[5] Enhanced Fuzzing")
        print("[6] Hashing")
        print("[7] Done")
        
        while True:
            choice = input("\nSelect feature to toggle (7 to finish): ")
            if choice == '1':
                self.advanced_analysis['process'] = not self.advanced_analysis['process']
                print(f"Process Analysis: {'Enabled' if self.advanced_analysis['process'] else 'Disabled'}")
            elif choice == '2':
                self.advanced_analysis['memory'] = not self.advanced_analysis['memory']
                print(f"Memory Analysis: {'Enabled' if self.advanced_analysis['memory'] else 'Disabled'}")
            elif choice == '3':
                self.advanced_analysis['dataflow'] = not self.advanced_analysis['dataflow']
                print(f"Data Flow Analysis: {'Enabled' if self.advanced_analysis['dataflow'] else 'Disabled'}")
            elif choice == '4':
                self.advanced_analysis['taint'] = not self.advanced_analysis['taint']
                print(f"Taint Analysis: {'Enabled' if self.advanced_analysis['taint'] else 'Disabled'}")
            elif choice == '5':
                self.advanced_analysis['fuzzing'] = not self.advanced_analysis['fuzzing']
                print(f"Enhanced Fuzzing: {'Enabled' if self.advanced_analysis['fuzzing'] else 'Disabled'}")
            elif choice == '6':
                self.advanced_analysis['hashing'] = not self.advanced_analysis['hashing']
                print(f"Hashing: {'Enabled' if self.advanced_analysis['hashing'] else 'Disabled'}")
            elif choice == '7':
                break
            else:
                print("Invalid choice. Try again.")

    def menu(self):
        self.display_banner()
        while True:
            print("\nSelect a functionality:")
            print("[1] Fuzz Target and Analyze Responses")
            print("[2] Scan Open Ports and Running Processes")
            print("[3] Train/Run ML Model on Real Network Data")
            print("[4] Configure Advanced Analysis Features")
            print("[5] Exit")
            choice = input("\nEnter choice: ")

            if choice == '1':
                ip = input("Enter target IP: ")
                self.fuzz_target(ip)
            elif choice == '2':
                self.analyze_system()
            elif choice == '3':
                self.train_or_test_model()
            elif choice == '4':
                self.configure_advanced_features()
            elif choice == '5':
                print("Exiting NetSurf...")
                break
            else:
                print("Invalid choice. Try again.")

    def generate_fuzz_payload(self):
        if self.advanced_analysis['fuzzing']:
            
            payloads = [
                ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(5, 20))),
                f"{'A' * random.randint(100, 1000)}",
                f"<!-- {random.randint(1,10000)} -->",
                f"%{random.randint(10,99)}x",
                ''.join(random.choices(string.printable, k=random.randint(10, 50)))
            ]
            return random.choice(payloads)
        else:
            return f"/test{random.randint(1,1000)}?x={random.randint(1,1000)}"

    def hash_response(self, data):
        if self.advanced_analysis['hashing']:
            return hashlib.sha256(data.encode(errors='ignore')).hexdigest()
        return None

    def perform_taint_analysis(self, data):
        if self.advanced_analysis['taint']:
            rules = """
            rule TaintCheck {
                strings:
                    $sql_injection = /[Uu][Nn][Ii][Oo][Nn].*[Ss][Ee][Ll][Ee][Cc][Tt]/
                    $xss = /<script.*?>/
                    $cmd_injection = /[;&|]/
                condition:
                    any of them
            }
            """
            with open(os.path.join(self.results_dir, "taint.yara"), 'w') as f:
                f.write(rules)
            yara_rules = yara.compile(os.path.join(self.results_dir, "taint.yara"))
            matches = yara_rules.match(data=data.encode(errors='ignore'))
            return [str(match) for match in matches]
        return []

    def perform_dataflow_analysis(self, data):
        if self.advanced_analysis['dataflow']:
            graph = pydot.Dot(graph_type='digraph')
            
            node = pydot.Node("Input", label=f"Data: {data[:50]}...")
            graph.add_node(node)
            return graph.write_dot()
        return None

    def perform_memory_analysis(self, pid):
        if self.advanced_analysis['memory']:
            try:
                
                ctx = contexts.Context()
                symbol_table = symbols.SymbolTable(ctx, 'windows')
                plugin = pslist.PsList(ctx, symbol_table)
                mem_data = []
                for proc in plugin.run():
                    if proc.UniqueProcessId == pid:
                        mem_map = memmap.Memmap(ctx, symbol_table).run(pid=pid)
                        mem_data.append(f"Memory Map for PID {pid}: {mem_map}")
                return mem_data
            except Exception as e:
                return [f"Memory Analysis Error: {e}"]
        return []

    def perform_process_analysis(self, proc):
        if self.advanced_analysis['process']:
            try:
                process = psutil.Process(proc.info['pid'])
                return [
                    f"Process Analysis for {proc.info['name']}:",
                    f"CPU Usage: {process.cpu_percent(interval=0.1)}%",
                    f"Memory Usage: {process.memory_info().rss / 1024 / 1024:.2f} MB",
                    f"Threads: {process.num_threads()}",
                    f"Open Files: {len(process.open_files())}"
                ]
            except Exception as e:
                return [f"Process Analysis Error: {e}"]
        return []

    def fuzz_target(self, ip):
        logger.info(f"[+] Fuzzing {ip}...")
        results = []
        for i in tqdm(range(50), desc="Fuzzing progress"):
            payload = self.generate_fuzz_payload()
            try:
                with socket.create_connection((ip, 80), timeout=2) as s:
                    s.sendall(f"GET {payload} HTTP/1.1\r\nHost: {ip}\r\n\r\n".encode())
                    data = s.recv(1024).decode(errors='ignore')
                    
                    result = {
                        'payload': payload,
                        'response': data[:100],
                        'hash': self.hash_response(data) if self.advanced_analysis['hashing'] else None,
                        'taint': self.perform_taint_analysis(data) if self.advanced_analysis['taint'] else [],
                        'dataflow': self.perform_dataflow_analysis(data) if self.advanced_analysis['dataflow'] else None
                    }
                    results.append(json.dumps(result))
            except Exception as e:
                result = {
                    'payload': payload,
                    'error': str(e),
                    'hash': None,
                    'taint': [],
                    'dataflow': None
                }
                results.append(json.dumps(result))

        self.save_results(ip, results, "fuzz")


    def analyze_system(self, ip=None):
        if not ip:
            ip = input("Enter IP to scan (or leave blank for localhost): ").strip() or "localhost"

        logger.info(f"[+] Scanning open ports and running processes on {ip}...")
        report = []

        for proc in psutil.process_iter(['pid', 'name', 'username']):
            proc_info = f"[PROC] PID: {proc.info['pid']}, Name: {proc.info['name']}, User: {proc.info['username']}"
            report.append(proc_info)

            if self.advanced_analysis['process']:
                report.extend(self.perform_process_analysis(proc))
            if self.advanced_analysis['memory']:
                report.extend(self.perform_memory_analysis(proc.info['pid']))

        net_conns = psutil.net_connections()
        for conn in net_conns:
            if conn.status == 'LISTEN':
                proto = 'TCP' if conn.type == 1 else 'UDP' if conn.type == 2 else 'UNKNOWN'
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                process_info = "N/A"
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        process_info = f"PID: {conn.pid}, Name: {proc.name()}, User: {proc.username()}"
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_info = f"PID: {conn.pid} (Process details unavailable)"
                port_info = (
                    f"[PORT] Protocol: {proto}, Local: {local_addr}, Remote: {remote_addr}, "
                    f"Status: {conn.status}, Process: {process_info}"
                )
                report.append(port_info)

        self.save_results(ip, report, "system_scan")


    from sklearn.feature_selection import VarianceThreshold

    def clean_dataframe(self, df, keep_label=False):
        from sklearn.feature_selection import VarianceThreshold
        drop_cols = ["Flow ID", "Src IP", "Dst IP", "Timestamp"]
        df = df.drop(columns=[col for col in drop_cols if col in df.columns], errors='ignore')
        
       
        if keep_label and 'Label' in df.columns:
            labels = df['Label']
            df = df.drop(columns=['Label'], errors='ignore')
            df = df.apply(pd.to_numeric, errors='coerce')
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.fillna(df.mean(), inplace=True)
            df['Label'] = labels
        else:
            df = df.apply(pd.to_numeric, errors='coerce')
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.fillna(df.mean(), inplace=True)
        
      
        try:
            selector = VarianceThreshold(threshold=0.01)
            feature_cols = df.drop(columns=['Label'], errors='ignore').columns
            df_selected = pd.DataFrame(selector.fit_transform(df.drop(columns=['Label'], errors='ignore')),
                                    columns=feature_cols[selector.get_support()],
                                    index=df.index)
            print(f"[DEBUG] Features after variance thresholding: {list(df_selected.columns)}")
            if keep_label and 'Label' in df.columns:
                df_selected['Label'] = df['Label']
            return df_selected
        except Exception as e:
            print(f"[!] VarianceThreshold failed: {e}. Proceeding without feature selection.")
            if keep_label and 'Label' in df.columns:
                df['Label'] = df['Label']
            return df
    def scale_data(self, df):
       
        from sklearn.preprocessing import StandardScaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(df)

       
        with open("scaler.save", "wb") as f:
            pickle.dump(scaler, f)
        return X_scaled

    def train_or_test_model(self):
        print("\nChoose ML method:")
        print("[1] Train Autoencoder")
        print("[2] Train One-Class SVM")
        print("[3] Train Isolation Forest")
        print("[4] Train Random Forest")
        print("[5] Train LSTM Autoencoder")
        print("[6] Test Model")
        print("[7] Show Anomaly Comparison")
        print("[8] Done")
        algo = input("\nEnter option: ")
        if algo == '1':
            from tensorflow.keras.models import Model
            from tensorflow.keras.layers import Input, Dense, Dropout
            from tensorflow.keras.optimizers import Adam
            from tensorflow.keras.callbacks import EarlyStopping
            model_path = "trained_models/autoencoder.h5"
            data_path = input("Path to training CSV dataset (features only): ").strip()
            try:
                df = pd.read_csv(data_path, low_memory=False)
                df.columns = df.columns.str.strip()
                df = df.reset_index(drop=True) 
                
                
                if 'Label' in df.columns:
                    y_train = df['Label'].astype(str).str.strip().str.lower()
                    y_train = y_train.apply(lambda x: 0 if x == 'benign' else 1).astype(int).values
                    print("[DEBUG] Training label counts:", dict(Counter(y_train)))
                    df = df.drop(columns=['Label'], errors='ignore')
                
               
                df = self.clean_dataframe(df)
                if df.shape[0] == 0:
                    print("[!] After cleaning, no rows remain—check CSV schema.")
                    return
                
               
                X_train = self.scale_data(df)
                
                
                input_dim = X_train.shape[1]
                model = build_autoencoder(input_dim, mse_threshold=0.1) 
                
               
                early_stopping = EarlyStopping(monitor='loss', patience=3, restore_best_weights=True)
                model.fit(X_train, X_train, epochs=50, batch_size=256, validation_split=0.2, 
                        callbacks=[early_stopping], verbose=1)
                
               
                predictions = model.predict(X_train)
                train_errors = np.mean(np.square(X_train - predictions), axis=1)
                with open("train_errors.pkl", "wb") as f:
                    pickle.dump(train_errors, f)
                print(f"[DEBUG] Training error stats: mean={np.mean(train_errors):.4f}, "
                    f"std={np.std(train_errors):.4f}, min={np.min(train_errors):.4f}, "
                    f"max={np.max(train_errors):.4f}")
                
               
                model.save(model_path)
                print(f"[+] Autoencoder model saved to {model_path}")
            except Exception as e:
                print(f"[!] Training failed: {e}")
        elif algo == '2':  
            from sklearn.svm import OneClassSVM
            data_path = input("Path to training CSV dataset (features only): ").strip()
            df = pd.read_csv(data_path)
            df = self.clean_dataframe(df)
            X_train = self.scale_data(df)
            model = OneClassSVM(kernel="rbf", gamma="auto", nu=0.05)
            model.fit(X_train)
            model_path = "trained_models/oneclass_svm.pkl"
            with open(model_path, "wb") as f:
                pickle.dump(model, f)
            print(f"[+] One-Class SVM model saved to {model_path}")

        elif algo == '3':
            from sklearn.ensemble import IsolationForest
            from sklearn.feature_selection import VarianceThreshold
            model_path = "trained_models/isolation_forest.pkl"
            data_path = input("Path to training CSV dataset (features only): ").strip()
            try:
                df = pd.read_csv(data_path, low_memory=False)
                df.columns = df.columns.str.strip()
                df = df.reset_index(drop=True)  
                
               
                if 'Label' in df.columns:
                    y_train = df['Label'].astype(str).str.strip().str.lower()
                    y_train = y_train.apply(lambda x: 0 if x == 'benign' else 1).astype(int).values
                    print("[DEBUG] Training label counts:", dict(Counter(y_train)))
                    contamination = np.mean(y_train)  
                    print(f"[DEBUG] Estimated contamination: {contamination:.4f}")
                    df = df.drop(columns=['Label'], errors='ignore')
                else:
                    contamination = 0.1 
                    print("[!] No 'Label' column found. Using default contamination=0.1")
                
                df = self.clean_dataframe(df)
                if df.shape[0] == 0:
                    print("[!] After cleaning, no rows remain—check CSV schema.")
                    return
                
                X_train = self.scale_data(df)
                
               
                model = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
                model.fit(X_train)
                
               
                joblib.dump(model, model_path)
                print(f"[+] Isolation Forest model saved to {model_path}")
            except Exception as e:
                print(f"[!] Training failed: {e}")

        elif algo == '4':
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.feature_selection import VarianceThreshold
            model_path = "trained_models/random_forest.pkl"
            data_path = input("Path to training CSV dataset (with labels): ").strip()
            try:
                df = pd.read_csv(data_path, low_memory=False)
                df.columns = df.columns.str.strip()
                df = df.reset_index(drop=True) 
                
               
                if 'Label' not in df.columns:
                    print("[!] Label column missing for Random Forest training.")
                    return
                y_train = df['Label'].astype(str).str.strip().str.lower()
                y_train = y_train.apply(lambda x: 0 if x == 'benign' else 1).astype(int).values
                print("[DEBUG] Training label counts:", dict(Counter(y_train)))
                
               
                df = self.clean_dataframe(df, keep_label=True)
                if df.shape[0] == 0:
                    print("[!] After cleaning, no rows remain—check CSV schema.")
                    return
                if 'Label' not in df.columns:
                    print("[!] Label column lost during preprocessing.")
                    return
                
               
                X_train = self.scale_data(df.drop(columns=['Label']))
                y_train = df['Label'].astype(str).str.strip().str.lower()
                y_train = y_train.apply(lambda x: 0 if x == 'benign' else 1).astype(int).values
                
                
                model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, class_weight='balanced')
                model.fit(X_train, y_train)
                
               
                joblib.dump(model, model_path)
                print(f"[+] Random Forest model saved to {model_path}")
            except Exception as e:
                print(f"[!] Training failed: {e}")

        elif algo == '5': 
            from keras.models import Sequential
            from keras.layers import LSTM, RepeatVector, TimeDistributed, Dense
            sequence_length = int(input("Enter sequence length: "))
            data_path = input("Path to training CSV dataset (features only): ").strip()
            df = pd.read_csv(data_path)
            df = self.clean_dataframe(df)
            X_train = self.scale_data(df)

           
            num_sequences = X_train.shape[0] - sequence_length + 1
            if num_sequences <= 0:
                print("[!] Not enough data for given sequence length.")
                return
            X_seq = np.array([X_train[i:i+sequence_length] for i in range(num_sequences)])

            model = Sequential()
            model.add(LSTM(64, activation='relu', input_shape=(sequence_length, X_train.shape[1]), return_sequences=False))
            model.add(RepeatVector(sequence_length))
            model.add(LSTM(64, activation='relu', return_sequences=True))
            model.add(TimeDistributed(Dense(X_train.shape[1])))
            model.compile(optimizer='adam', loss='mse')
            model.fit(X_seq, X_seq, epochs=10, batch_size=64, verbose=1)
            model_path = "trained_models/lstm_autoencoder.h5"
            model.save(model_path)
            print(f"[+] LSTM Autoencoder model saved to {model_path}")

        elif algo == '6':
            model_type = input("Model type (ae, svm, iso, rf, lstm): ").strip().lower()
            model_path = input("Path to saved model (.h5 or .pkl): ").strip()
            data_path = input("Path to CSV test data (features only): ").strip()

            if not os.path.exists(data_path):
                print(f"[!] Test data file not found: {data_path}")
                return

            print(f"[+] Loading test dataset: {data_path}")
            try:
                df = pd.read_csv(data_path, low_memory=False)
                df.columns = df.columns.str.strip()
                df = df.reset_index(drop=True)  

               
                if 'Label' in df.columns:
                    y_true = df['Label'].astype(str).str.strip().str.lower()
                    y_true = y_true.apply(lambda x: 0 if x == 'benign' else 1).astype(int).values
                    print("[DEBUG] Label counts:", dict(Counter(y_true)))
                else:
                    print("[!] 'Label' column not found. Cannot compute precision, recall, or F1-score.")
                    y_true = np.zeros(len(df), dtype=int)

                
                df_clean = self.clean_dataframe(df.drop(columns=['Label'], errors='ignore'))
                if df_clean.shape[0] == 0:
                    print("[!] After cleaning, no rows remain—check CSV schema.")
                    return

                
                y_true = y_true[df_clean.index.values]
                print("[DEBUG] y_true shape after alignment:", y_true.shape)
                print("[DEBUG] df_clean shape:", df_clean.shape)

                
                with open("scaler.save", "rb") as f:
                    scaler = pickle.load(f)
                X_test = scaler.transform(df_clean)

            except Exception as e:
                print(f"[!] Failed to load or preprocess test data: {e}")
                return

            num_anomalies = 0
            if model_type == "ae":
                try:
                    from tensorflow.keras.models import load_model
                    print("[+] Loading Autoencoder model...")
                    from autoencoder import load_model as load_ae_model
                    model = load_ae_model(model_path)

                    predictions = model.predict(X_test)
                    errors = np.mean(np.square(X_test - predictions), axis=1)
                    
                   
                    try:
                        with open("train_errors.pkl", "rb") as f:
                            train_errors = pickle.load(f)
                        threshold = np.percentile(train_errors, 65)  
                        print(f"[DEBUG] Using training error threshold: {threshold}")
                    except FileNotFoundError:
                        print("[!] train_errors.pkl not found, using test errors for threshold")
                        threshold = np.percentile(errors, 65)
                    
                    anomalies = errors > threshold
                    num_anomalies = np.sum(anomalies)
                    anomaly_indices = np.where(anomalies)[0]
                    anomalous_rows = df.iloc[anomaly_indices].copy()
                    anomalous_rows["Reconstruction_Error"] = errors[anomalies]

                   
                    attack_types = anomalous_rows["Label"].value_counts().to_dict()

                    os.makedirs(self.results_dir, exist_ok=True)
                    anomalous_rows.to_csv(os.path.join(self.results_dir, "anomalies_detected_ae.csv"), index=False)
                    print("[+] Anomaly details saved to anomalies_detected_ae.csv")

                    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
                    y_pred = anomalies.astype(int)
                    print("[DEBUG] Sample y_true:", y_true[:20])
                    print("[DEBUG] Sample y_pred:", y_pred[:20])
                    print("[DEBUG] Error stats: mean=%.4f, std=%.4f, min=%.4f, max=%.4f" % 
                        (np.mean(errors), np.std(errors), np.min(errors), np.max(errors)))
                    print("[DEBUG] Confusion matrix:")
                    cm = confusion_matrix(y_true, y_pred)
                    print(cm)

                    anomaly_indices = np.where(y_pred == 1)[0]
                    attack_indices = np.where(y_true == 1)[0]
                    print(f"[DEBUG] First 10 Anomaly Predictions at rows: {anomaly_indices[:10]}")
                    print(f"[DEBUG] First 10 Actual Attacks at rows: {attack_indices[:10]}")

                    acc = accuracy_score(y_true, y_pred)
                    prec = precision_score(y_true, y_pred, zero_division=0)
                    rec = recall_score(y_true, y_pred, zero_division=0)
                    f1 = f1_score(y_true, y_pred, zero_division=0)
                    tn, fp, fn, tp = cm.ravel() if len(np.unique(y_pred)) > 1 else (0, 0, 0, 0)
                    false_rate = (fp + fn) / len(y_true)

                    self.model_anomaly_counts[model_type.upper()] = {
                        "Anomalies": int(num_anomalies),
                        "Accuracy": acc,
                        "Precision": prec,
                        "Recall": rec,
                        "F1-Score": f1,
                        "False Rate": false_rate,
                        "Attack Types": json.dumps(attack_types)
                    }

                    print(f"[+] Detected {num_anomalies} anomalies out of {len(X_test)} samples.")
                except Exception as e:
                    print(f"[!] Autoencoder testing failed: {e}")
                    return
            elif model_type == "svm":
                try:
                    with open(model_path, "rb") as f:
                        model = pickle.load(f)
                    anomalies = model.predict(X_test) == -1
                    num_anomalies = np.sum(anomalies)
                    anomaly_df = df[anomalies]
                    os.makedirs(self.results_dir, exist_ok=True)
                    anomaly_df.to_csv(os.path.join(self.results_dir, "anomalies_detected_svm.csv"), index=False)
                    print("[+] Anomaly details saved to anomalies_detected_svm.csv")
                    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

                    y_true = np.zeros_like(anomalies)
                    y_pred = anomalies.astype(int)

                    acc = accuracy_score(y_true, y_pred)
                    prec = precision_score(y_true, y_pred, zero_division=0)
                    rec = recall_score(y_true, y_pred, zero_division=0)
                    f1 = f1_score(y_true, y_pred, zero_division=0)
                    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel() if len(np.unique(y_pred)) > 1 else (0, 0, 0, 0)
                    false_rate = (fp + fn) / len(y_true)

                    self.model_anomaly_counts[model_type.upper()] = {
                        "Anomalies": int(np.sum(anomalies)),
                        "Accuracy": acc,
                        "Precision": prec,
                        "Recall": rec,
                        "F1-Score": f1,
                        "False Rate": false_rate,
                        "Attack Types": json.dumps(attack_types)
                    }


                except Exception as e:
                    print(f"[!] SVM testing failed: {e}")
                    return

            elif model_type == "iso":
                    try:
                        print("[+] Testing Isolation Forest...")
                        model = joblib.load(model_path)
                       
                        anomalies = model.predict(X_test) == -1  
                        y_pred = anomalies.astype(int)
                        num_anomalies = np.sum(anomalies)
                        
                       
                        anomalous_rows = df_clean.iloc[np.where(anomalies)[0]].copy()
                       
                        anomalous_rows["Anomaly_Score"] = model.decision_function(X_test)[anomalies]
                        os.makedirs(self.results_dir, exist_ok=True)
                        anomalous_rows.to_csv(os.path.join(self.results_dir, "anomalies_detected_iso.csv"), index=False)
                        print("[+] Anomaly details saved to anomalies_detected_iso.csv")

                        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
                        print("[DEBUG] Sample y_true:", y_true[:20])
                        print("[DEBUG] Sample y_pred:", y_pred[:20])
                        print("[DEBUG] Confusion matrix:")
                        cm = confusion_matrix(y_true, y_pred)
                        print(cm)

                        anomaly_indices = np.where(y_pred == 1)[0]
                        attack_indices = np.where(y_true == 1)[0]
                        print(f"[DEBUG] First 10 Anomaly Predictions at rows: {anomaly_indices[:10]}")
                        print(f"[DEBUG] First 10 Actual Attacks at rows: {attack_indices[:10]}")

                        acc = accuracy_score(y_true, y_pred)
                        prec = precision_score(y_true, y_pred, zero_division=0)
                        rec = recall_score(y_true, y_pred, zero_division=0)
                        f1 = f1_score(y_true, y_pred, zero_division=0)
                        tn, fp, fn, tp = cm.ravel() if len(np.unique(y_pred)) > 1 else (0, 0, 0, 0)
                        false_rate = (fp + fn) / len(y_true)
                        if 'Label' in df.columns:
                            attack_types = df.iloc[np.where(anomalies)[0]]["Label"].value_counts().to_dict()
                        else:
                            attack_types = {}

                        self.model_anomaly_counts[model_type.upper()] = {
                            "Anomalies": int(np.sum(anomalies)),
                            "Accuracy": acc,
                            "Precision": prec,
                            "Recall": rec,
                            "F1-Score": f1,
                            "False Rate": false_rate,
                            "Attack Types": json.dumps(attack_types)
                        }

                        print(f"[+] Detected {num_anomalies} anomalies out of {len(X_test)} samples.")

                    except Exception as e:
                        print(f"[!] Isolation Forest testing failed: {e}")
                        return

            elif model_type == "rf":
                try:
                    print("[+] Testing Random Forest...")
                    model = joblib.load(model_path)
                    y_pred = model.predict(X_test) 
                    anomalies = y_pred == 1
                    num_anomalies = np.sum(anomalies)
                    
                   
                    anomalous_rows = df_clean.iloc[np.where(y_pred == 1)[0]].copy()
                    prob_anomalies = model.predict_proba(X_test)[np.where(y_pred == 1)[0], 1]  
                    anomalous_rows["Prediction_Probability"] = prob_anomalies
                    os.makedirs(self.results_dir, exist_ok=True)
                    anomalous_rows.to_csv(os.path.join(self.results_dir, "anomalies_detected_rf.csv"), index=False)
                    print("[+] Anomaly details saved to anomalies_detected_rf.csv")
                    if 'Label' in df.columns:
                        attack_types = df.iloc[np.where(anomalies)[0]]["Label"].value_counts().to_dict()
                    else:
                         attack_types = {}

                    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
                    print("[DEBUG] Sample y_true:", y_true[:20])
                    print("[DEBUG] Sample y_pred:", y_pred[:20])
                    print("[DEBUG] Confusion matrix:")
                    cm = confusion_matrix(y_true, y_pred)
                    print(cm)

                    anomaly_indices = np.where(y_pred == 1)[0]
                    attack_indices = np.where(y_true == 1)[0]
                    print(f"[DEBUG] First 10 Anomaly Predictions at rows: {anomaly_indices[:10]}")
                    print(f"[DEBUG] First 10 Actual Attacks at rows: {attack_indices[:10]}")

                    acc = accuracy_score(y_true, y_pred)
                    prec = precision_score(y_true, y_pred, zero_division=0)
                    rec = recall_score(y_true, y_pred, zero_division=0)
                    f1 = f1_score(y_true, y_pred, zero_division=0)
                    tn, fp, fn, tp = cm.ravel() if len(np.unique(y_pred)) > 1 else (0, 0, 0, 0)
                    false_rate = (fp + fn) / len(y_true)

                    self.model_anomaly_counts[model_type.upper()] = {
                        "Anomalies": int(num_anomalies),
                        "Accuracy": acc,
                        "Precision": prec,
                        "Recall": rec,
                        "F1-Score": f1,
                        "False Rate": false_rate,
                        "Attack Types": json.dumps(attack_types)
                    }

                    print(f"[+] Detected {num_anomalies} anomalies out of {len(X_test)} samples.")

                except Exception as e:
                    print(f"[!] Random Forest testing failed: {e}")
                    return
            elif model_type == "lstm":
                try:
                    from keras.losses import MeanSquaredError
                    from keras.models import load_model
                    model = load_model(model_path, custom_objects={"mse": MeanSquaredError()})
                    sequence_length = 10 
                    num_sequences = X_test.shape[0] - sequence_length + 1
                    if num_sequences <= 0:
                        print("[!] Not enough data to form sequences with the chosen length.")
                        return
                    data = np.array([X_test[i:i+sequence_length] for i in range(num_sequences)])
                    reconstructed = model.predict(data)
                    mse = np.mean(np.power(data - reconstructed, 2), axis=(1, 2))
                    threshold = np.percentile(mse, 95)
                    anomalies = mse > threshold
                    num_anomalies = np.sum(anomalies)
                    anomaly_indices = np.where(anomalies)[0]
                    anomaly_df = df.iloc[anomaly_indices]
                    os.makedirs(self.results_dir, exist_ok=True)
                    anomaly_df.to_csv(os.path.join(self.results_dir, "anomalies_detected_lstm.csv"), index=False)
                    print(f"[+] Anomalies saved to anomalies_detected_lstm.csv")
                    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

                    y_true = np.zeros_like(anomalies)
                    y_pred = anomalies.astype(int)

                    acc = accuracy_score(y_true, y_pred)
                    prec = precision_score(y_true, y_pred, zero_division=0)
                    rec = recall_score(y_true, y_pred, zero_division=0)
                    f1 = f1_score(y_true, y_pred, zero_division=0)
                    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel() if len(np.unique(y_pred)) > 1 else (0, 0, 0, 0)
                    false_rate = (fp + fn) / len(y_true)
                    if 'Label' in df.columns:
                        attack_types = df.iloc[np.where(anomalies)[0]]["Label"].value_counts().to_dict()
                    else:
                        attack_types = {}

                    self.model_anomaly_counts[model_type.upper()] = {
                        "Anomalies": int(np.sum(anomalies)),
                        "Accuracy": acc,
                        "Precision": prec,
                        "Recall": rec,
                        "F1-Score": f1,
                        "False Rate": false_rate,
                        "Attack Types": json.dumps(attack_types)
                    }


                except Exception as e:
                    print(f"[!] LSTM testing failed: {e}")
                    return

            else:
                print("[!] Unsupported model type.")
                return

           
            
            print(f"[+] Detected {num_anomalies} anomalies out of {len(X_test)} samples.")

        elif algo == '7':
            self.show_comparison()
        elif algo == '8':
            return


    def detect_lstm_anomalies(self, model, data, seq_len):
        reshaped = data.reshape((data.shape[0] // seq_len, seq_len, data.shape[1]))
        reconstructed = model.predict(reshaped)
        errors = np.mean((reshaped - reconstructed) ** 2, axis=(1, 2))
        threshold = np.percentile(errors, 95)
        anomalies = errors > threshold
        return anomalies, errors


    def save_results(self, name, results, tag):
        os.makedirs(self.results_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.results_dir, f"{tag}_{name}_{timestamp}.txt")
        try:
            with open(filename, 'w') as f:
                f.write(f"NetSurf Report - {tag}\n")
                f.write(f"Target: {name}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Advanced Features: {json.dumps(self.advanced_analysis, indent=2)}\n")
                f.write("=" * 60 + "\n\n")
                for line in results:
                  
                    try:
                        parsed = json.loads(line)
                        f.write(json.dumps(parsed, indent=2) + "\n")
                    except json.JSONDecodeError:
                        f.write(f"{line}\n")
                    f.write("-" * 60 + "\n")
            logger.info(f"[+] Report saved: {filename}")
        except Exception as e:
            logger.error(f"[!] Failed to save report: {e}")
    def show_comparison(self):
        if not self.model_anomaly_counts:
            print("\n[!] No anomaly detection results available. Run model tests first.")
            return

        print("\n=== Anomaly Detection Summary ===")
        
      
        for model, data in self.model_anomaly_counts.items():
            if not isinstance(data, dict):
                self.model_anomaly_counts[model] = {
                    "Anomalies": int(data),
                    "Accuracy": 0.0,
                    "Precision": 0.0,
                    "Recall": 0.0,
                    "F1-Score": 0.0,
                    "False Rate": 0.0
                }

        metrics_df = pd.DataFrame.from_dict(self.model_anomaly_counts, orient='index')
       
        columns = ["Anomalies", "Accuracy", "Precision", "Recall", "F1-Score", "False Rate"]
        if "Attack Types" in metrics_df.columns:
            columns.append("Attack Types")

        metrics_df = metrics_df[columns]

        metrics_df.to_csv(os.path.join(self.results_dir, "comparison_metrics.csv"))
        print(metrics_df.round(4).to_string())

        
        report_path = os.path.join(self.results_dir, f"comparison_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        try:
            with open(report_path, 'w') as f:
                f.write("=== Anomaly Detection Summary ===\n")
                f.write(metrics_df.round(4).to_string())
                f.write("\n")
            print(f"[+] Comparison report saved to {report_path}")
        except Exception as e:
            print(f"[!] Failed to save comparison report: {e}")

       
        try:
            fig, ax = plt.subplots(figsize=(12, 6))
            bar_width = 0.15
            x = np.arange(len(metrics_df))

            for i, metric in enumerate(["Accuracy", "Precision", "Recall", "F1-Score", "False Rate"]):
                ax.bar(x + i * bar_width, metrics_df[metric].astype(float), width=bar_width, label=metric)

            ax.set_xlabel("Models")
            ax.set_ylabel("Scores")
            ax.set_title("Model Performance Metrics")
            ax.set_xticks(x + bar_width * 2)
            ax.set_xticklabels(metrics_df.index)
            ax.legend()
            plt.tight_layout()

            plot_path = os.path.join(self.results_dir, f"comparison_chart_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
            plt.savefig(plot_path)
            print(f"[+] Comparison chart saved to {plot_path}")
            plt.show()
        except Exception as e:
            print(f"[!] Failed to generate comparison chart: {e}")
            print(f"Error details: {str(e)}")

       
        try:
            models = list(metrics_df.index)
            counts = metrics_df["Anomalies"].astype(int).tolist()

            plt.figure(figsize=(10, 6))
            colors = ['#36A2EB', '#FF6384', '#4BC0C0', '#FFCE56', '#9966FF']
            bars = plt.bar(models, counts, color=colors[:len(models)], edgecolor='black', width=0.25)
            plt.title('Anomalies Detected by Each Model')
            plt.xlabel('Model')
            plt.ylabel('Number of Anomalies')
            plt.grid(True, axis='y', linestyle='--', alpha=0.7)
            plt.tight_layout()

            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height,
                        f'{int(height)}',
                        ha='center', va='bottom')

            plot_path = os.path.join(self.results_dir, f"anomaly_count_plot_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
            plt.savefig(plot_path)
            print(f"[+] Anomaly count chart saved to {plot_path}")
            plt.show()
        except Exception as e:
            print(f"[!] Failed to generate anomaly count chart: {e}")
            print(f"Error details: {str(e)}")




        
if __name__ == "__main__":
    tool = NetSurf()

    tool.menu()
