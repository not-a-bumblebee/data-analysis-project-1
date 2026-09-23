import pandas as pd

# pass json of container
def get_metrics_from_cve(containers):
    # 1. Primary: Try CNA first
    cna_metrics = containers.get("cna", {}).get("metrics", [])
    if cna_metrics:
        score, severity, vector, _version = extract_best_cvss(cna_metrics)
        if score is not None:
            return score, severity,vector, "CNA"

    # 2. Fallback: Check ADP containers if CNA has no score
    adp_list = containers.get("adp", [])
    for adp in adp_list:
        adp_metrics = adp.get("metrics", [])
        if adp_metrics:
            score, severity, vector, _version = extract_best_cvss(adp_metrics)
            if score is not None:
                return score, severity, vector, "ADP"

    return None, None, None, None

def extract_best_cvss(metrics_list):
    """
    Evaluates a metrics array and returns the preferred CVSS score,
    severity, and version string based on priority rules.
    """
    if not metrics_list:
        return None, None, None,None
    
    # Priority 1: Check for CVSS v4.0
    for metric in metrics_list:
        if "cvssV4_0" in metric:
            v4 = metric["cvssV4_0"]
            return v4.get("baseScore"), v4.get("baseSeverity"),v4.get("attackVector"), "4.0"
            
    # Priority 2: Check for CVSS v3.1
    for metric in metrics_list:
        if "cvssV3_1" in metric:
            v31 = metric["cvssV3_1"]
            return v31.get("baseScore"), v31.get("baseSeverity"),v31.get("attackVector"), "3.1"

    # Priority 3: Check for CVSS v3.0
    for metric in metrics_list:
        if "cvssV3_0" in metric:
            v30 = metric["cvssV3_0"]
            return v30.get("baseScore"), v30.get("baseSeverity"),v30.get("attackVector",None), "3.0"

    # Priority 4: Fallback to CVSS v2.0
    for metric in metrics_list:
        if "cvssV2_0" in metric:
            v2 = metric["cvssV2_0"]
            return v2.get("baseScore"), v2.get("baseSeverity"),v2.get("attackVector",None), "2.0"

    return None, None, None, None