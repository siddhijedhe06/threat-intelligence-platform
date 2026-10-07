from analysis import calculate_risk_score
from analysis import get_severity
from analysis import classify_threat


# Test risk score
score = calculate_risk_score(
    source_score=20,
    severity_score=20,
    frequency_score=15,
    recency_score=15,
    corroboration_score=15
)

print("Risk Score:", score)
print("Severity:", get_severity(score))


# Test threat classification
category = classify_threat(
    "192.168.1.50",
    "Suspicious botnet activity detected"
)

print("Threat Category:", category)