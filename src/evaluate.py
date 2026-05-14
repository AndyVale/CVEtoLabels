import os
import ast
import json
import pandas as pd
from utils.evaluation_utils import evaluate_predictions

def get_classes_for_model(filename):
    base_dir = "models"
    if not os.path.exists(base_dir):
        return None
    for model_name in os.listdir(base_dir):
        if os.path.isdir(os.path.join(base_dir, model_name)):
            if filename.startswith(model_name):
                classes_path = os.path.join(base_dir, model_name, "mlb_classes.json")
                if not os.path.exists(classes_path):
                    classes_path = os.path.join(base_dir, model_name, "train_unique_labels.json")
                if os.path.exists(classes_path):
                    with open(classes_path, "r") as f:
                        return json.load(f)
    return None

if __name__ == "__main__":
    # Add as many file paths as you want to this list
    FILE_PATHS = [os.path.join('mod_tests', x) for x in os.listdir('mod_tests') if x.endswith('.csv')]
    all_results = {}
    
    for file_path in FILE_PATHS:
        try:
            df = pd.read_csv(file_path)
            
            # Safely convert string representations of lists back into actual Python lists
            df['predicted'] = df['predicted'].apply(ast.literal_eval)
            df['groundtruth'] = df['groundtruth'].apply(ast.literal_eval)
            
            # Use the filename as the column header
            file_name = os.path.basename(file_path)
            classes = get_classes_for_model(file_name)
            
            all_results[file_name] = evaluate_predictions(df['groundtruth'].tolist(), df['predicted'].tolist(), classes=classes)
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            
    if all_results:
        # Create a DataFrame from the dictionary of dictionaries
        comparison_df = pd.DataFrame(all_results)
        
        # Reset index so 'Metric' becomes a regular column instead of the index
        comparison_df = comparison_df.reset_index().rename(columns={'index': 'Metric'})
        
        # Format the numbers to 4 decimal places across all model columns
        for col in comparison_df.columns:
            if col != 'Metric':
                comparison_df[col] = comparison_df[col].apply(lambda x: f"{float(x):.4f}")
        
        print(f"=== Multi-Label Evaluation Comparison ===")
        print(comparison_df.to_string(index=False))
    else:
        print("No valid files to compare.")