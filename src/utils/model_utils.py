import os
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

def load_model(model_name: str, base_dir: str = "models"):
    """
    Loads a fine-tuned model and its tokenizer given the model's directory name.
    
    Args:
        model_name (str): The name of the model directory (e.g., "securebert_finetuned_cwe").
        base_dir (str): The base directory where models are stored.
        
    Returns:
        tuple: (model, tokenizer, device)
    """
    # Build the path assuming the structure: models/<model_name>/checkpoints/final/
    model_path = os.path.join(base_dir, model_name, "checkpoints", "final")
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model path does not exist: {model_path}")
        
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    
    # Load custom classification head if it exists (specific to some architectures)
    head_path = os.path.join(model_path, "classification_head.pth")
    if os.path.exists(head_path):
        model.classifier.load_state_dict(torch.load(head_path, map_location=torch.device('cpu')))
        
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    
    return model, tokenizer, device

def predict_labels(text: str, model, tokenizer, device, threshold: float = 0.5) -> list[str]:
    """
    Predicts labels for a given text input using a loaded sequence classification model.
    
    Args:
        text (str): The input text to classify.
        model: The loaded HuggingFace model.
        tokenizer: The corresponding tokenizer.
        device: The PyTorch device (CPU or CUDA).
        threshold (float): Threshold for the multi-label sigmoid probabilities.
        
    Returns:
        list[str]: A list of predicted labels.
    """
    if text == "No-info" or not text.strip():
        return []
        
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True
    ).to(device)
    if len(inputs) == 512: print("Input is 512, truncating!")
    
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        
    probabilities = torch.sigmoid(logits)
    
    # Ensure we're extracting the first item in the batch
    probs_1d = probabilities.squeeze(0)
    predicted_indices = (probs_1d > threshold).nonzero(as_tuple=True)[0]
    
    labels = []
    if hasattr(model.config, "id2label") and getattr(model.config, "id2label", None):
        for idx in predicted_indices:
            idx_val = idx.item()
            label_name = model.config.id2label[idx_val]
            labels.append(label_name)
    else:
        # Fallback if id2label is missing
        for idx in predicted_indices:
            labels.append(str(idx.item()))
            
    return labels
