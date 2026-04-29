import csv
import os
import random
import time
from datetime import datetime
from tqdm import tqdm

import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.metrics import f1_score, precision_score, recall_score

from nvd_utils import get_cve_information
from model_utils import load_model, predict_labels

random.seed(42)

def main():
    model1_name = "securebert_finetuned_cwe"
    model2_name = "bert_cwe"
    num_samples = 100

    print(f"Loading {model1_name}...")
    model1, tokenizer1, device1 = load_model(model1_name)
    
    print(f"Loading {model2_name}...")
    model2, tokenizer2, device2 = load_model(model2_name)
    
    # Create the mod_tests/compare_YY-MM-DD-HH-MM-SS directory
    timestamp = datetime.now().strftime("%y-%m-%d-%H-%M-%S")
    output_dir = os.path.join("mod_tests", f"compare_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    
    file1_path = os.path.join(output_dir, f"{model1_name}.csv")
    file2_path = os.path.join(output_dir, f"{model2_name}.csv")
    
    # Lists for in-memory metric computation
    y_true_list = []
    y_pred1_list = []
    y_pred2_list = []
    
    print(f"Fetching {num_samples} random CVEs and evaluating both models...")
    with open(file1_path, mode="w", newline="", encoding="utf-8") as f1, \
         open(file2_path, mode="w", newline="", encoding="utf-8") as f2:
         
        writer1 = csv.DictWriter(f1, fieldnames=["cve_id", "predicted", "groundtruth"])
        writer2 = csv.DictWriter(f2, fieldnames=["cve_id", "predicted", "groundtruth"])
        
        writer1.writeheader()
        writer2.writeheader()
        
        for _ in tqdm(range(num_samples), desc="Processing CVEs"):
            time.sleep(7)
            fetched_cve_id, description, true_cwes = get_cve_information(None)
            
            # Predict with model 1
            if description != "No-info" and description.strip():
                pred1 = predict_labels(description, model1, tokenizer1, device1)
            else:
                pred1 = []
                
            # Predict with model 2
            if description != "No-info" and description.strip():
                pred2 = predict_labels(description, model2, tokenizer2, device2)
            else:
                pred2 = []
                
            writer1.writerow({
                "cve_id": fetched_cve_id,
                "predicted": str(pred1),
                "groundtruth": str(true_cwes)
            })
            
            writer2.writerow({
                "cve_id": fetched_cve_id,
                "predicted": str(pred2),
                "groundtruth": str(true_cwes)
            })
            
            f1.flush()
            f2.flush()
            
            y_true_list.append(true_cwes)
            y_pred1_list.append(pred1)
            y_pred2_list.append(pred2)
            
    # --- Metrics Computation ---
    print("\nComputing metrics...")
    # MultiLabelBinarizer needs to know all possible classes.
    # We fit it on all true and predicted labels combined to ensure same dimensions.
    all_labels = y_true_list + y_pred1_list + y_pred2_list
    mlb = MultiLabelBinarizer()
    mlb.fit(all_labels)
    
    y_true_bin = mlb.transform(y_true_list)
    y_pred1_bin = mlb.transform(y_pred1_list)
    y_pred2_bin = mlb.transform(y_pred2_list)
    
    metrics = {
        model1_name: {},
        model2_name: {}
    }
    
    # Compute Macro metrics
    metrics[model1_name]['F1 (Macro)'] = f1_score(y_true_bin, y_pred1_bin, average='macro', zero_division=0)
    metrics[model1_name]['Precision (Macro)'] = precision_score(y_true_bin, y_pred1_bin, average='macro', zero_division=0)
    metrics[model1_name]['Recall (Macro)'] = recall_score(y_true_bin, y_pred1_bin, average='macro', zero_division=0)
    
    metrics[model2_name]['F1 (Macro)'] = f1_score(y_true_bin, y_pred2_bin, average='macro', zero_division=0)
    metrics[model2_name]['Precision (Macro)'] = precision_score(y_true_bin, y_pred2_bin, average='macro', zero_division=0)
    metrics[model2_name]['Recall (Macro)'] = recall_score(y_true_bin, y_pred2_bin, average='macro', zero_division=0)

    # Compute Micro metrics
    metrics[model1_name]['F1 (Micro)'] = f1_score(y_true_bin, y_pred1_bin, average='micro', zero_division=0)
    metrics[model1_name]['Precision (Micro)'] = precision_score(y_true_bin, y_pred1_bin, average='micro', zero_division=0)
    metrics[model1_name]['Recall (Micro)'] = recall_score(y_true_bin, y_pred1_bin, average='micro', zero_division=0)
    
    metrics[model2_name]['F1 (Micro)'] = f1_score(y_true_bin, y_pred2_bin, average='micro', zero_division=0)
    metrics[model2_name]['Precision (Micro)'] = precision_score(y_true_bin, y_pred2_bin, average='micro', zero_division=0)
    metrics[model2_name]['Recall (Micro)'] = recall_score(y_true_bin, y_pred2_bin, average='micro', zero_division=0)

    # Print summary
    print(f"\n--- Metrics Summary ---")
    for m_name in [model1_name, model2_name]:
        print(f"Model: {m_name}")
        for k, v in metrics[m_name].items():
            print(f"  {k}: {v:.4f}")
        print()
        
    # --- Visualization ---
    print("Generating comparative graph...")
    labels = ['Precision (Macro)', 'Recall (Macro)', 'F1 (Macro)', 'Precision (Micro)', 'Recall (Micro)', 'F1 (Micro)']
    model1_scores = [metrics[model1_name][l] for l in labels]
    model2_scores = [metrics[model2_name][l] for l in labels]
    
    x = np.arange(len(labels))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width/2, model1_scores, width, label=model1_name)
    rects2 = ax.bar(x + width/2, model2_scores, width, label=model2_name)
    
    ax.set_ylabel('Scores')
    ax.set_title('Comparative Evaluation: SecureBERT vs BERT (CWE Classification)')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.legend()
    
    ax.bar_label(rects1, fmt='%.2f', padding=3)
    ax.bar_label(rects2, fmt='%.2f', padding=3)
    
    fig.tight_layout()
    
    plot_path = os.path.join(output_dir, "metrics_comparison.png")
    plt.savefig(plot_path)
    print(f"Metrics plot saved to {plot_path}")
    print("Evaluation completed successfully!")

if __name__ == "__main__":
    main()
