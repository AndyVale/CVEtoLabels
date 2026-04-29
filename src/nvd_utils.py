import requests
from requests.exceptions import RequestException

def get_cve_information(cve_id: str) -> tuple[str, list[str]]:
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        resp = requests.get(url, params={"cveId": cve_id}, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except RequestException:
        return "No-info", []

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        return "No-info", []
    
    cve_data = vulnerabilities[0].get("cve", {})
    
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
    
    return eng_desc, cwes
    