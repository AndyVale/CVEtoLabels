# CVE to Labels Agents Guide

## Context

Goal: Evaluate models that map a CVE (ID/description) to one or more labels (e.g., CWE classes).

## Structure

* **`src/test.py`** — Main entrypoint for batch testing and evaluation of random CVEs.
* **`src/utils/`**:
    * `nvd_utils.py` — NVD API utilities.
    * `model_utils.py` — ML model utilities.
    * `cvss_utils.py` — CVSS score utilities.

## Dev

Install dependencies with:

```bash
uv pip install <package>
```
