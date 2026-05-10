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
    target_cves_csv: Path to the CSV file acting as a list of targeted CVEs (must contain 'cve_id').
    cvelist_dir: Path to cveListV5 directory.
    cvss_version: Version of CVSS data to be extracted (default: cvssV3_1).
    
    Returns a pandas dataframe containing: cve_id, description, CWEs, and the requested CVSS vector.
    """

    target_df = pd.read_csv(target_cves_csv)
    wanted_cve_ids = set(target_df['cve_id'].dropna().tolist())

    records = []
    cvss_keys =['cvssV2_0', 'cvssV3_0', 'cvssV3_1', 'cvssV4_0']
    
    for cve_id in tqdm(wanted_cve_ids, desc=f'Processing {cvss_version} Data'):
        file_path = get_cve_file_path(cvelist_dir, cve_id)
        if not file_path:
            continue
            
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                containers = data.get('containers', {})
                cna_container = containers.get('cna', {})
                adp_containers = containers.get('adp',[])

                # --- 1. Description Extraction ---
                description = extract_description(containers)

                # --- 2. CWE Extraction ---
                cna_cwes = extract_cwes(cna_container)
                adp_cwes =[]
                for adp in adp_containers:
                    adp_cwes.extend(extract_cwes(adp))
                
                # Combine them (removing duplicates via set)
                all_cwes = list(set(cna_cwes + adp_cwes))

                # --- 3. CVSS Extraction ---
                cvss_data = {k: None for k in cvss_keys}
                
                def extract_vectors(container):
                    for metric in container.get('metrics',[]):
                        for version in cvss_keys:
                            if version in metric and not cvss_data[version]:
                                cvss_data[version] = metric[version].get('vectorString')

                for adp in adp_containers:
                    extract_vectors(adp)
                extract_vectors(cna_container)

                target_vector = cvss_data.get(cvss_version)
                
                # Skip appending if the requested CVSS version isn't present for this CVE
                if target_vector is None:
                    continue

                records.append({
                    'cve_id': cve_id,
                    'description': description,
                    'cwes': all_cwes,
                    'cvss_vector': target_vector
                })
            except Exception:
                continue
                
    return pd.DataFrame(records)

if __name__ == "__main__":
    CVE_LISTV5_DIR = 'mod_evaluation_data/cvelistV5'
    TARGET_CVES_CSV = 'mod_evaluation_data/test.csv'
    CVSS_VERSION = 'cvssV3_1'

    df_cve_cvss = create_cvecvss_dataset(TARGET_CVES_CSV, CVE_LISTV5_DIR, CVSS_VERSION)
    
    out_path = f'mod_evaluation_data/cve_cvss_{CVSS_VERSION}.csv'

    df_cve_cvss['labels'] = df_cve_cvss['cwes']
    df_cve_cvss.drop(columns=['cwes'], inplace=True)

    df_cve_cvss.to_csv(out_path, index=False)
    
    print(f"Saved {len(df_cve_cvss)} rows to {out_path}")