import os
import ast
import pandas as pd
from utils.evaluation_utils import evaluate_predictions

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
            all_results[file_name] = evaluate_predictions(df['groundtruth'].tolist(), df['predicted'].tolist())
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