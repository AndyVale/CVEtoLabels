import os
import json
import re
import pandas as pd
from tqdm import tqdm

def extract_cwes(container):
    """Extracts CWEs robustly using Regex to handle varying formatting from CNAs/ADPs."""
    found = []
    descriptions = [d for pt in container.get('problemTypes', []) for d in pt.get('descriptions',[])]
    
    for desc in descriptions:
        if "cweId" in desc:
            found.append(desc["cweId"])
            continue
            
        txt = desc.get('description', '')
        
        if match := re.search(r'(?:CWE[\s\-\u2011\u2013\u2014:]*(?:ID\s*)?|definitions/)(\d+)', txt, re.IGNORECASE):
            found.append(f"CWE-{match.group(1)}")
        elif re.search(r'(?i)\b(?:NOINFO|OTHER|UNKNOWN|CWE|NO_CWE)\b', txt):
            found.append("CWE-noinfo")
            
    return list(set(found))

def extract_description(containers):
    """Extracts the English description, encoding newlines and tabs to literal string representations."""
    
    def clean_text(text):
        if not text:
            return text
        # Replace actual control characters with their literal string equivalents
        return text.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')

    # Try CNA first
    for desc in containers.get('cna', {}).get('descriptions',[]):
        if desc.get('lang') == 'en':
            return clean_text(desc.get('value'))
    
    # Try ADP fallback
    for adp in containers.get('adp', []):
        for desc in adp.get('descriptions',[]):
            if desc.get('lang') == 'en':
                return desc.get('value')
                
    return None

def get_cve_file_path(base_dir, cve_id):
    """Dynamically calculates the MITRE cvelistV5 folder structure to avoid globbing."""
    try:
        parts = cve_id.split('-')
        year = parts[1]
        seq = parts[2]
        folder = seq[:-3] + "xxx" # e.g., 12345 -> 12xxx, 0166 -> 0xxx
        
        # Check both with and without the 'cves' subdirectory to be safe
        path1 = os.path.join(base_dir, "cves", year, folder, f"{cve_id}.json")
        path2 = os.path.join(base_dir, year, folder, f"{cve_id}.json")
        
        if os.path.exists(path1): return path1
        if os.path.exists(path2): return path2
    except IndexError:
        pass
        
    return None

def create_cvecvss_dataset(target_cves_csv, cvelist_dir, cvss_version='cvssV3_1'):
    """
    Enriches an existing CSV with a CVSS vector column looked up from cvelistV5.

    target_cves_csv: Path to the CSV file (must contain a 'CVE_ID' column). All original columns are preserved.
    cvelist_dir: Path to cveListV5 directory.
    cvss_version: Version of CVSS data to be extracted (default: cvssV3_1).

    Saves the enriched CSV as <original_name>_<cvss_version>.csv and returns the dataframe.
    """

    target_df = pd.read_csv(target_cves_csv)
    cvss_keys = ['cvssV2_0', 'cvssV3_0', 'cvssV3_1', 'cvssV4_0']

    # Build a lookup: CVE_ID -> cvss vector string
    cvss_lookup = {}
    for cve_id in tqdm(target_df['CVE_ID'].dropna().unique(), desc=f'Processing {cvss_version} Data'):
        file_path = get_cve_file_path(cvelist_dir, cve_id)
        if not file_path:
            cvss_lookup[cve_id] = "CVSS_NOT_AVAILABLE"
            continue

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                containers = data.get('containers', {})
                cna_container = containers.get('cna', {})
                adp_containers = containers.get('adp', [])

                cvss_data = {k: None for k in cvss_keys}

                def extract_vectors(container):
                    for metric in container.get('metrics', []):
                        for version in cvss_keys:
                            if version in metric and not cvss_data[version]:
                                cvss_data[version] = metric[version].get('vectorString')

                for adp in adp_containers:
                    extract_vectors(adp)
                extract_vectors(cna_container)

                vector = cvss_data.get(cvss_version)
                cvss_lookup[cve_id] = vector if vector is not None else "CVSS_NOT_AVAILABLE"
        except Exception:
            cvss_lookup[cve_id] = "CVSS_NOT_AVAILABLE"

    # Map the lookup onto the original dataframe, preserving all columns and rows
    target_df['cvss_vector'] = target_df['CVE_ID'].map(cvss_lookup).fillna("CVSS_NOT_AVAILABLE")

    # Save with naming convention: originalname_cvssVersion.csv
    base, ext = os.path.splitext(target_cves_csv)
    out_path = f"{base}_{cvss_version}{ext}"
    target_df.to_csv(out_path, index=False)
    print(f"Saved {len(target_df)} rows to {out_path}")

    return target_df

if __name__ == "__main__":
    CVE_LISTV5_DIR = 'mod_evaluation_data/cvelistV5'
    TARGET_CVES_CSV = 'mod_evaluation_data/data_cwe_all.csv'
    CVSS_VERSION = 'cvssV3_1'

    create_cvecvss_dataset(TARGET_CVES_CSV, CVE_LISTV5_DIR, CVSS_VERSION)