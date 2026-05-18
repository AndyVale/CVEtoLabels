import os
import json
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score, hamming_loss

def evaluate_predictions(groundtruth_list, predicted_list, classes=None):
    if classes is not None:
        mlb = MultiLabelBinarizer(classes=classes)
        mlb.fit([classes])
    else:
        mlb = MultiLabelBinarizer()
        mlb.fit(groundtruth_list + predicted_list)
        
    y_true = mlb.transform(groundtruth_list)
    y_pred = mlb.transform(predicted_list)
    
    metrics = {
        "Micro F1": f1_score(y_true, y_pred, average="micro", zero_division=0),
        "Macro F1": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "Weighted F1": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "Micro Precision": precision_score(y_true, y_pred, average="micro", zero_division=0),
        "Macro Precision": precision_score(y_true, y_pred, average="macro", zero_division=0),
        "Micro Recall": recall_score(y_true, y_pred, average="micro", zero_division=0),
        "Macro Recall": recall_score(y_true, y_pred, average="macro", zero_division=0),
        "Subset Accuracy": accuracy_score(y_true, y_pred),
        "Hamming Loss": hamming_loss(y_true, y_pred)
    }
    
    return {"Model Performance": metrics}

def get_classes_for_model(path_to_model):
    classes_path = os.path.join(path_to_model, "mlb_classes.json")
    if not os.path.exists(classes_path):
        classes_path = os.path.join(path_to_model, "train_unique_labels.json")
    if os.path.exists(classes_path):
        with open(classes_path, "r", encoding="utf-8") as f:
            return json.load(f)
    raise FileNotFoundError(f"Classes file not found at {classes_path}")
