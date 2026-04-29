import csv
import os
import random
import time
from datetime import datetime
from tqdm import tqdm
from nvd_utils import get_cve_information
from model_utils import load_model, predict_labels

random.seed(42)

if __name__ == "__main__":
    model_name = "bert_cwe"
    print("Loading model...")
    model, tokenizer, device = load_model(model_name)
    
    # Create the mod_tests directory if it doesn't exist
    output_dir = "mod_tests"
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate filename based on current time (yy-mm-dd-hh-mm-ss)
    timestamp = datetime.now().strftime("%y-%m-%d-%H-%M-%S")
    output_file = os.path.join(output_dir, f"{model_name}_{timestamp}.csv")
    
    print(f"Fetching and predicting 100 random CVEs...")
    print(f"Results will be written to {output_file} as they are processed.")
    
    # Open file in write mode and keep it open during the loop
    with open(output_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["cve_id", "predicted", "groundtruth"])
        writer.writeheader()
        f.flush()
        
        for _ in tqdm(range(100), desc="Processing CVEs"):
            time.sleep(7)
            fetched_cve_id, description, true_cwes = get_cve_information(None)
            
            if description != "No-info" and description.strip():
                predicted_cwes = predict_labels(description, model, tokenizer, device)
            else:
                predicted_cwes = []
                
            writer.writerow({
                "cve_id": fetched_cve_id,
                "predicted": str(predicted_cwes),
                "groundtruth": str(true_cwes)
            })
            # Flush after every row so data is saved immediately
            f.flush()
            
    print("Done!")