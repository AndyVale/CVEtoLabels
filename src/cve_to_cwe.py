from nvd_utils import get_cve_information
from model_utils import load_model, predict_labels

if __name__ == "__main__":
    # Set to None to fetch a random CVE, or provide a specific ID like "CVE-2020-0601"
    cve_id = None
    
    if cve_id:
        print(f"Fetching information for {cve_id}...")
    else:
        print("Fetching information for a random CVE...")
        
    fetched_cve_id, description, true_cwes = get_cve_information(cve_id)
    
    print(f"\nCVE ID: {fetched_cve_id}")
    print(f"Description: {description}")
    print(f"NVD CWEs: {true_cwes}")
    
    if description != "No-info":
        print("\nLoading model...")
        model, tokenizer, device = load_model("securebert_finetuned_cwe")
        
        print("Predicting CWEs...")
        predicted_cwes = predict_labels(description, model, tokenizer, device)
        print(f"Predicted CWEs: {predicted_cwes}")
    else:
        print("\nNo description available to predict CWEs.")