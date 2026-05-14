import os
import json
import yaml
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from sklearn.preprocessing import MultiLabelBinarizer

def load_model(model_name: str, base_dir: str = "models"):
    """
    Loads a fine-tuned model and its tokenizer given the model's directory name.
    
    Args:
        model_name (str): The name of the model directory (e.g., "securebert_finetuned_cwe").
        base_dir (str): The base directory where models are stored.
        
    Returns:
        tuple: (model, tokenizer, device, mlb, config)
    """
    # Build the path assuming the structure: models/<model_name>/checkpoints/final/
    model_folder = os.path.join(base_dir, model_name)
    model_path = os.path.join(model_folder, "checkpoints", "final")
    
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"Model path does not exist: {model_path}")
        
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    
    classes_path = os.path.join(model_folder, "mlb_classes.json")
    if not os.path.exists(classes_path):
        classes_path = os.path.join(model_folder, "train_unique_labels.json")
    with open(classes_path, "r") as f:
        classes = json.load(f)
    mlb = MultiLabelBinarizer(classes=classes)
    mlb.fit(classes)
    
    config_path = os.path.join(model_folder, "config.yaml")
    with open(config_path, "r") as f:
        config = yaml.safe_load(f)
        
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()
    
    return model, tokenizer, device, mlb, config

def predict_labels(text: str, model, tokenizer, device, mlb, max_len=512, threshold: float = 0.5, confidences=False) -> list[str]:
    """
    Predicts labels for a given text input using a loaded sequence classification model.
    
    Args:
        text (str): The input text to classify.
        model: The loaded HuggingFace model.
        tokenizer: The corresponding tokenizer.
        device: The PyTorch device (CPU or CUDA).
        mlb: The fitted MultiLabelBinarizer.
        max_len: Maximum token length.
        threshold (float): Threshold for the multi-label sigmoid probabilities.
        confidences (bool): If True, returns the confidence values for each label, otherwise returns thresholded labels only.
        
    Returns:
        list[str] or list[tuple]: A list of predicted labels or (label, confidence) pairs ordered by confidence.
    """
    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=max_len,
        padding=True
    ).to(device)
    
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        
    probabilities = torch.sigmoid(logits)
    
    # Ensure we're extracting the first item in the batch
    probs_1d = probabilities.squeeze(0)
    predicted_indices = (probs_1d >= threshold).nonzero(as_tuple=True)[0]
    
    labels_with_conf = []
    for idx in predicted_indices:
        idx_val = idx.item()
        label_name = mlb.classes_[idx_val]
        conf = probs_1d[idx_val].item()
        labels_with_conf.append((label_name, conf))
            
    if confidences:
        labels_with_conf.sort(key=lambda x: x[1], reverse=True)
        return labels_with_conf
    else:
        return [label for label, _ in labels_with_conf]
