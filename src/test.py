import argparse
import csv
import os
from datetime import datetime
import pandas as pd
from tqdm import tqdm
from utils.model_utils import load_model, predict_labels
from utils.cvss_utils import generate_cvss_description


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
        model, tokenizer, device = load_model(model_name, base_dir=base_dir)
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
        
        for _, row in tqdm(df.iterrows(), total=len(df), desc="Processing CVEs"):
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
            
            if description != "No-info" and description.strip():
                predicted_cwes = predict_labels(description, model, tokenizer, device, threshold = 0.7)
            else:
                predicted_cwes = []
                
            writer.writerow({
                "cve_id": cve_id,
                "predicted": str(predicted_cwes),
                "groundtruth": str(true_cwes)
            })
            f.flush()
            
    print("Done!")