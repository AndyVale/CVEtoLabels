# CVE to CWE Agents Guide

## Context

Main entrypoint: `src/cve_to_cwe.py`
Goal: evaluate models that map a CVE (ID/description) to one or more CWE classes.

## Structure

* `src/cve_to_cwe.py` — main script
* `src/nvd_utils.py` — NVD API utilities

## Dev

Install dependencies with:

```bash
uv pip install <package>
```
