# CVE to Labels

This project aims to compare different ways of classifying CVEs into their corresponding labels (like CWEs) in an automated way.

The system evaluates model accuracy by comparing predictions against ground truth data.

## Project Structure

```text
.
├── AGENTS.md               # Guide for AI agents/developers
├── README.md               # Main project documentation
├── requirements.txt        # Python dependencies
├── models/                 # Fine-tuned model weights and local runners
├── mod_evaluation_data/    # Ground truth datasets
├── mod_tests/              # Evaluation results and performance reports
└── src/                    # Source code
    ├── test.py             # Main evaluation entrypoint
    └── utils/              # Core utility modules
        ├── cvss_utils.py   # CVSS score processing
        ├── data_utils.py   # Data loading and transformation
        ├── model_utils.py  # Model inference logic
        └── nvd_utils.py    # NVD API interaction
```

## Getting Started

1. **Install dependencies**:
   ```bash
   uv pip install -r requirements.txt
   ```
2. **Run a batch test**:
   ```bash
   python src/test.py
   ```
