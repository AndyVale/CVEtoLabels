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
    v = dict(item.split(':') for item in vector.split('/')[1:])
    cve_str = f" {cve}" if cve else ""
    
    conj = ", but it " if (v.get('PR') == 'N') != (v.get('UI') == 'N') else ", and it "
    
    desc = (f"The vulnerability{cve_str} {metrics_dict['AV'][v['AV']]}. "
            f"{metrics_dict['AC'][v['AC']]}. "
            f"Exploitation {metrics_dict['PR'][v['PR']]}{conj}{metrics_dict['UI'][v['UI']]}. "
            f"{metrics_dict['S'][v['S']]}.\n\n"
            f"Regarding the impact on the system: it results in a {metrics_dict['C'][v['C']]}, "
            f"a {metrics_dict['I'][v['I']]}, and {metrics_dict['A'][v['A']]}.")
    
    return desc
