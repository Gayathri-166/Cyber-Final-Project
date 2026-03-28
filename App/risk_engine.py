def calculate_risk(vuln, threat_data):
    score = 3

    if vuln["port"] in [21, 23]:
        score += 3
    elif vuln["port"] in [22, 3389]:
        score += 2
    elif vuln["port"] in [80, 443]:
        score += 1

    score += threat_data["malicious_score"]

    severity = get_severity(score)

    return score, severity


def get_severity(score):
    if score >= 9:
        return "Critical"
    elif score >= 7:
        return "High"
    elif score >= 5:
        return "Medium"
    elif score >= 3:
        return "Low"
    else:
        return "Informational"