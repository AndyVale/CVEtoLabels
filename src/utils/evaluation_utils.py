import pandas as pd
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.metrics import precision_recall_fscore_support, accuracy_score

def evaluate_predictions(groundtruth_list, predicted_list, classes=None):
    """
    Evaluates multi-label predictions against groundtruth lists.
    
    Args:
        groundtruth_list: List of lists of true labels.
        predicted_list: List of lists of predicted labels.
        classes: Optional list of all possible classes to ensure consistent label space.
        
    Returns:
        Dictionary containing Exact Match and Precision, Recall, F1 for micro, macro, samples.
    """
    if classes is not None:
        mlb = MultiLabelBinarizer(classes=classes)
        mlb.fit(classes)
    else:
        mlb = MultiLabelBinarizer()
        # Fit the binarizer on the union of all labels to ensure dimensions match
        mlb.fit(pd.concat([pd.Series(groundtruth_list), pd.Series(predicted_list)]))
    
    y_true = mlb.transform(groundtruth_list)
    y_pred = mlb.transform(predicted_list)
    
    results = {}
    
    # Exact Match (Subset Accuracy)
    results['Exact Match'] = accuracy_score(y_true, y_pred)
    
    # Calculate Precision, Recall, and F1
    for avg in ['micro', 'weighted']:
        p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average=avg, zero_division=0)
        results[f'{avg.capitalize()} Precision'] = p
        results[f'{avg.capitalize()} Recall'] = r
        results[f'{avg.capitalize()} F1-Score'] = f
        
    return results
