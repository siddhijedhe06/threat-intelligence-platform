import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "services", "analysis-service"))
from analysis import analyze_threat_indicator

test_cases = [
    ("http://paypal-security-update.com/login.php", "URL", "Phishing Feed", "Phishing page targeting customer credentials"),
    ("http://185.220.101.5:4444/payload.exe", "URL", "SOC Alert", "Direct IP host with Metasploit port and malware payload"),
    ("http://chase-bank-verify.xyz/auth", "URL", "AbuseIPDB", "Phishing domain impersonating Chase Bank with suspicious TLD"),
    ("192.168.1.1", "IP Address", "Manual Entry", "Default internal gateway router"),
    ("https://google.com", "URL", "Manual Entry", "Search engine homepage"),
    ("185.220.101.5", "IP Address", "AlienVault OTX", "Tor exit relay conducting brute force and botnet scanning")
]

for ind, itype, src, desc in test_cases:
    res = analyze_threat_indicator(ind, itype, src, desc)
    print(f"=== {ind} ===")
    print(f"Type: {res['indicator_type']} | Category: {res['category']} | Score: {res['risk_score']} | Severity: {res['severity']} | Alert: {res['alert_required']}")
    print(f"Findings: {len(res['findings'])}")
    print("-" * 50)
