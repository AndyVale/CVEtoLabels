import pandas as pd

CVSS3_1 = {
    "AV": {
        "N": "is reachable from any remote network location",
        "A": "is limited to the same local network or subnet",
        "L": "requires local system access or a local shell",
        "P": "requires physical access to the device"
    },
    "AC": {
        "L": "The attack complexity is low, meaning the exploit is predictable and repeatable",
        "H": "The attack complexity is high, as it requires specific, non-trivial conditions to succeed"
    },
    "PR": {
        "N": "requires no prior authentication or user privileges",
        "L": "requires basic user privileges",
        "H": "requires administrative privileges"
    },
    "UI": {
        "N": "requires no interaction from a victim",
        "R": "depends on a legitimate user performing a specific action"
    },
    "S": {
        "U": "The impact is confined only to the vulnerable software component and does not affect external systems",
        "C": "The impact can spread to other systems or security authorities"
    },
    "C": {
        "H": "total loss of data confidentiality",
        "L": "partial loss of data confidentiality",
        "N": "lack of impact on data confidentiality"
    },
    "I": {
        "H": "total loss of data integrity or unauthorized modification",
        "L": "partial loss of data integrity or unauthorized modification",
        "N": "lack of impact on data integrity"
    },
    "A": {
        "H": "causes a total loss of system availability",
        "L": "causes a partial loss of system availability",
        "N": "has no effect on the system's availability"
    }
}

def generate_cvss_description(vector, metrics_dict=CVSS3_1, cve=""):
    if vector == "CVSS_NOT_AVAILABLE":
        return ""
    v = dict(item.split(':') for item in vector.split('/')[1:])
    cve_str = f" {cve}" if cve else ""
    
    conj = ", but it " if (v.get('PR') == 'N') != (v.get('UI') == 'N') else ", and it "
    
    desc = (f"The vulnerability{cve_str} {metrics_dict['AV'][v['AV']]}. "
            f"{metrics_dict['AC'][v['AC']]}. "
            f"Exploitation {metrics_dict['PR'][v['PR']]}{conj}{metrics_dict['UI'][v['UI']]}. "
            f"{metrics_dict['S'][v['S']]}.\\n"
            f"Regarding the impact on the system: it results in a {metrics_dict['C'][v['C']]}, "
            f"a {metrics_dict['I'][v['I']]}, and {metrics_dict['A'][v['A']]}.")
    
    return desc

def process_dataset_with_cvss(df):
    """
    Given a DataFrame containing 'description', 'cvss_vector', and 'CVE_ID',
    generates the CVSS description and concatenates it to the original description.
    Rows with CVSS_NOT_AVAILABLE keep their original description unchanged.
    """
    cvss_descs = df.apply(lambda row: generate_cvss_description(row['cvss_vector'], cve=row['CVE_ID']), axis=1)
    # Only append when there is actually a CVSS description
    df['description'] = df.apply(
        lambda row: row['description'] + "\\n\\n" + cvss_descs[row.name] if cvss_descs[row.name] else row['description'],
        axis=1
    )
    return df

def enrich_description_with_cvss(input_csv='mod_evaluation_data/data_cwe_all_cvssV3_1.csv'):
    """
    Reads a CSV enriched with a 'cvss_vector' column, concatenates the generated
    CVSS natural-language description with the original 'description' column,
    drops the 'cvss_vector' column, and saves the result.

    Output file: <original_name> with '_cvssV3_1' replaced by '_cvssV3.1' (or appends '_cvss_desc').
    """
    import os

    df = pd.read_csv(input_csv)

    print(f"Read {len(df)} rows from {input_csv}")
    print("Generating and concatenating CVSS descriptions...")
    df = process_dataset_with_cvss(df)

    # Drop the raw vector column
    df.drop(columns=['cvss_vector'], inplace=True)

    # Build output path
    base, ext = os.path.splitext(input_csv)
    out_path = base.replace('_cvssV3_1', '_cvssV3.1') + ext if '_cvssV3_1' in base else f"{base}_cvss_desc{ext}"

    df.to_csv(out_path, index=False)
    print(f"Saved {len(df)} rows to {out_path}")

    return df

if __name__ == "__main__":
    enrich_description_with_cvss()
