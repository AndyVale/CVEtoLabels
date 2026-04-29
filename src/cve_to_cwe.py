from nvd_utils import get_cve_information

if __name__ == "__main__":
    cve_id = "CVE-2023-23414"
    description, cwes = get_cve_information(cve_id)
    print(description, cwes)