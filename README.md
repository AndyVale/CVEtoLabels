# CVE to CWE

This project aims to compare different ways of classifying CVEs into their corresponding CWEs in an automated way.

The correctness of the results is verified using the NVD API, which, given a CVE, returns the associated CWEs.

## Project Structure

```

src/
├── cve_to_cwe.py    # Main entry point of the project
└── nvd_utils.py     # Utilities for interacting with the NVD API

```
