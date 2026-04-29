# CVE to Labels

This project aims to compare different ways of classifying CVEs into their corresponding labels (like CWEs) in an automated way.

The correctness of the results is verified using the NVD API, which, given a CVE, returns the associated CWEs.

## Project Structure

```
src/
├── cve_to_cwe.py    # Main entry point for single CVE analysis
├── nvd_utils.py     # Utilities for interacting with the NVD API
├── model_utils.py   # Utilities for loading and running ML models
└── test.py          # Script for batch testing random CVEs
mod_tests/           # Directory for storing test results
models/              # Directory for storing ML models
```

