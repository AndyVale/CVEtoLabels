import random
import requests
from requests.exceptions import RequestException

def get_cve_information(cve_id: str = None) -> tuple[str, str, list[str]]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        if cve_id:
            params = {"cveId": cve_id}
        else:
            # Replicate a random cve 
            start_index = random.randint(0, 345000)
            params = {"resultsPerPage": 1, "startIndex": start_index}
            
        resp = requests.get(url, params=params, headers={"Accept": "application/json"}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except RequestException:
        return cve_id or "Unknown", "No-info", []

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return cve_id or "Unknown", "No-info", []
    
    cve_data = vulnerabilities[0].get("cve", {})
    fetched_cve_id = cve_data.get("id", cve_id or "Unknown")
    
    eng_desc = "No-info"
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            eng_desc = desc.get("value", "No-info")
            break
            
    cwes = []
    for w in cve_data.get("weaknesses", []):
        for d in w.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-") and val not in cwes:
                cwes.append(val)
    
    return fetched_cve_id, eng_desc, cwes
    