from nvd_utils import get_cve_information
from model_utils import load_model, predict_labels

if __name__ == "__main__":
    cve_id = "CVE-2020-0601"
    print(f"Fetching information for {cve_id}...")
    description, true_cwes = get_cve_information(cve_id)
    
    print(f"\nDescription: {description}")
    print(f"NVD CWEs: {true_cwes}")
    
    if description != "No-info":
        print("\nLoading model...")
        model, tokenizer, device = load_model("securebert_finetuned_cwe")
        
        print("Predicting CWEs...")
        predicted_cwes = predict_labels(description, model, tokenizer, device)
        print(f"Predicted CWEs: {predicted_cwes}")
    else:
        print("\nNo description available to predict CWEs.")