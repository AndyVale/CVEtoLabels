import argparse
import csv
import os
import ast
import random
import numpy as np
from datetime import datetime
import pandas as pd
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from utils.model_utils import load_model, predict_labels
from utils.cvss_utils import generate_cvss_description
from utils.evaluation_utils import evaluate_predictions

# --- Configuration ---
TRAIN_TEST_SPLIT_RATIO = 0.6
THRESHOLD_SEARCH_RANGE = (0.1, 0.9)
THRESHOLD_STEP_SIZE = 0.05
RANDOM_SEED = 42

def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate CVE to CWE prediction model on a dataset.")
    parser.add_argument("--input_csv", type=str, required=True, 
                        help="Name of the CSV file in mod_evaluation_data or a full path to it.")
    parser.add_argument("--model", type=str, required=True, 
                        help="Name of a model folder inside 'models' or a full path to it.")
    parser.add_argument("--include_cvss", action="store_true",
                        help="If set, concatenates the CVSS description to the vulnerability description.")
    parser.add_argument("--output_csv", type=str, default=None,
                        help="Optional specific name for the output CSV file.")
    parser.add_argument("--threshold", type=float, default=None,
                        help="Optional fixed threshold to use. If provided, hyperparameter tuning is bypassed.")
    args = parser.parse_args()

    # Resolve input CSV path
    input_arg = args.input_csv
    if os.path.isabs(input_arg) or os.path.exists(input_arg):
        input_csv = input_arg
    else:
        input_csv = os.path.join("mod_evaluation_data", input_arg)
        
    if not os.path.exists(input_csv):
        print(f"Error: Could not find input CSV file at {input_csv}")
        exit(1)

    # Resolve model path
    model_arg = args.model
    if os.path.isabs(model_arg) or os.path.exists(model_arg):
        base_dir = os.path.dirname(os.path.abspath(model_arg))
        model_name = os.path.basename(os.path.abspath(model_arg))
    else:
        base_dir = "models"
        model_name = model_arg

    print(f"Loading model '{model_name}' from '{base_dir}'...")
    try:
        model, tokenizer, device, mlb, config = load_model(model_name, base_dir=base_dir)
    except Exception as e:
        print(f"Failed to load model: {e}")
        exit(1)
    
    # Read input data
    print(f"Reading data from {input_csv}...")
    df = pd.read_csv(input_csv)
    
    # Attempt to find the labels column ('labels' or 'cwes')
    if 'labels' not in df.columns:
        print(f"Error: Column 'labels' not found in {input_csv}")
        exit(1)
        
    if args.include_cvss:
        if 'cvss_vector' not in df.columns:
            print(f"Error: Column 'cvss_vector' not found in {input_csv}")
            exit(1)

    label_col = 'labels'
    
    set_seed(RANDOM_SEED)
    
    if args.threshold is not None:
        print(f"Threshold provided explicitly: {args.threshold}. Skipping tuning phase.")
        test_df = df
        optimal_threshold = args.threshold
    else:
        print("Splitting dataset for hyperparameter tuning...")
        try:
            tune_df, test_df = train_test_split(df, train_size=TRAIN_TEST_SPLIT_RATIO, random_state=RANDOM_SEED)
        except ValueError as e:
            print(f"Failed to split data: {e}")
            exit(1)
            
        print("Starting hyperparameter tuning on the tuning split...")
        tune_probs = []
        tune_groundtruth = []
        
        for _, row in tqdm(tune_df.iterrows(), total=len(tune_df), desc="Caching model probabilities"):
            description = str(row.get('description', ''))
            if pd.isna(row.get('description')):
                description = ""
                
            if args.include_cvss:
                cvss_vector = row.get('cvss_vector')
                if not pd.isna(cvss_vector) and cvss_vector:
                    try:
                        cvss_desc = generate_cvss_description(str(cvss_vector))
                        description = f"{description}\n\n{cvss_desc}".strip()
                    except Exception:
                        pass
                        
            true_cwes = row.get(label_col, []) if label_col else []
            if isinstance(true_cwes, str):
                try:
                    true_cwes = ast.literal_eval(true_cwes)
                except Exception:
                    true_cwes = []
            tune_groundtruth.append(true_cwes)
            
            # Get all labels and their raw probabilities
            probs = predict_labels(description, model, tokenizer, device, mlb=mlb, max_len=config.get('max_len', 512), threshold=0.0, confidences=True)
            tune_probs.append(probs)
            
        print("Evaluating candidate thresholds...")
        best_f1 = -1.0
        optimal_threshold = None
        
        # Adding a small epsilon to the upper bound to ensure the last step is included
        candidate_thresholds = np.arange(
            THRESHOLD_SEARCH_RANGE[0], 
            THRESHOLD_SEARCH_RANGE[1] + (THRESHOLD_STEP_SIZE / 2), 
            THRESHOLD_STEP_SIZE
        )
        
        for candidate in candidate_thresholds:
            candidate_preds = []
            for probs in tune_probs:
                pred_labels = [label for label, conf in probs if conf >= candidate]
                candidate_preds.append(pred_labels)
                
            metrics = evaluate_predictions(tune_groundtruth, candidate_preds, classes=mlb.classes_.tolist())
            micro_f1 = metrics.get('Micro F1-Score', 0.0)
            
            if micro_f1 > best_f1:
                print(f"New best threshold: {candidate} (Micro F1-Score: {micro_f1:.4f})")
                best_f1 = micro_f1
                optimal_threshold = candidate
                
        if optimal_threshold is None:
            print("Warning: Could not find an optimal threshold. Falling back to default 0.5.")
            optimal_threshold = 0.5
        else:
            print(f"Optimal threshold found: {optimal_threshold:.2f} (Micro F1-Score: {best_f1:.4f})")
    
    # Output directory
    output_dir = "mod_tests"
    os.makedirs(output_dir, exist_ok=True)
    
    if args.output_csv:
        output_name = args.output_csv if args.output_csv.endswith('.csv') else f"{args.output_csv}.csv"
        output_file = os.path.join(output_dir, output_name)
    else:
        # Generate filename based on current time
        timestamp = datetime.now().strftime("%y-%m-%d-%H-%M-%S")
        output_file = os.path.join(output_dir, f"{model_name}_{timestamp}.csv" if not args.include_cvss else f"{model_name}_CVSS_{timestamp}.csv")
    
    print(f"Predicting CVEs from dataset...")
    print(f"Results will be written to {output_file} as they are processed.")
    
    # Process and write results
    with open(output_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id", "predicted", "groundtruth"])
        writer.writeheader()
        f.flush()
        
        for _, row in tqdm(test_df.iterrows(), total=len(test_df), desc="Processing final evaluation"):
            cve_id = row.get('cve_id', 'Unknown')
            description = str(row.get('description', ''))
            
            if pd.isna(row.get('description')):
                description = ""
                
            if args.include_cvss:
                cvss_vector = row.get('cvss_vector')
                if not pd.isna(cvss_vector) and cvss_vector:
                    try:
                        cvss_desc = generate_cvss_description(str(cvss_vector))
                        description = f"{cvss_desc}\n\n{description}".strip()
                    except Exception:
                        pass
                        
            true_cwes = row.get(label_col, []) if label_col else []
            if isinstance(true_cwes, str):
                try:
                    true_cwes = ast.literal_eval(true_cwes)
                except Exception:
                    pass
            
            predicted_cwes = predict_labels(description, model, tokenizer, device, mlb=mlb, max_len=config.get('max_len', 512), threshold=optimal_threshold)
                
            writer.writerow({
                "cve_id": cve_id,
                "predicted": str(predicted_cwes),
                "groundtruth": str(true_cwes)
            })
            f.flush()
            
    print("Done!")