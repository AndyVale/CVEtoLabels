# CVE to Labels Agents Guide

## Context

Main entrypoint: `src/cve_to_cwe.py`
Goal: evaluate models that map a CVE (ID/description) to one or more labels (e.g., CWE classes).

## Structure

* `src/cve_to_cwe.py` — main script for single CVE analysis
* `src/nvd_utils.py` — NVD API utilities
* `src/model_utils.py` — ML model utilities
* `src/test.py` — batch testing script


## Dev

Install dependencies with:

```bash
uv pip install <package>
```
