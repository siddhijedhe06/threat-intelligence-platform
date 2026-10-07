def calculate_risk_score(
    source_score,
    severity_score,
    frequency_score,
    recency_score,
    corroboration_score
):
    total = (
        source_score
        + severity_score
        + frequency_score
        + recency_score
        + corroboration_score
    )

    # Keep score between 0 and 100
    risk_score = min(total, 100)

    return risk_score


def get_severity(risk_score):

    if risk_score <= 30:
        return "LOW"

    elif risk_score <= 60:
        return "MEDIUM"

    elif risk_score <= 80:
        return "HIGH"

    else:
        return "CRITICAL"

def classify_threat(indicator, description=""):

    text = (indicator + " " + description).lower()

    if "malware" in text:
        return "Malware"

    elif "phishing" in text:
        return "Phishing"

    elif "botnet" in text:
        return "Botnet"

    elif "brute force" in text:
        return "Brute Force"

    elif "suspicious" in text:
        return "Suspicious"

    else:
        return "Unknown"