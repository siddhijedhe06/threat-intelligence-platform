"""
Threat Analysis Engine
Analyzes IP addresses, URLs, and domains for cybersecurity risks.
Calculates multidimensional risk scores, classifies threat categories,
evaluates risk levels, and generates actionable intelligence reports.
"""

import ipaddress
import re
from urllib.parse import urlparse, parse_qs

# Known high-risk and abused Top-Level Domains (TLDs)
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "club", "work",
    "click", "cam", "live", "loan", "date", "racing", "win", "bid",
    "download", "stream", "onion", "ru", "cn", "link", "party", "kim",
    "country", "cricket", "science", "gdn", "mom", "vip", "fit"
}

# Brands commonly targeted for impersonation and phishing
TARGETED_BRANDS = [
    "paypal", "google", "microsoft", "apple", "netflix", "amazon",
    "chase", "wellsfargo", "bankofamerica", "binance", "coinbase", "meta",
    "facebook", "instagram", "whatsapp", "twitter", "x.com", "steam",
    "roblox", "outlook", "office365", "sharepoint", "adobe", "docusign",
    "yahoo", "dropbox", "ebay", "walmart", "telegram", "discord", "blockchain"
]

# Legitimate domains for targeted brands to avoid false positives
LEGITIMATE_BRAND_DOMAINS = {
    "paypal.com", "paypal.me", "google.com", "microsoft.com", "apple.com",
    "netflix.com", "amazon.com", "chase.com", "wellsfargo.com", "bankofamerica.com",
    "binance.com", "coinbase.com", "meta.com", "facebook.com", "instagram.com",
    "whatsapp.com", "twitter.com", "x.com", "steampowered.com", "roblox.com",
    "office.com", "live.com", "adobe.com", "docusign.com", "yahoo.com",
    "dropbox.com", "ebay.com", "walmart.com", "telegram.org", "discord.com"
}

# Suspicious file extensions indicating malware delivery or execution
MALICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".apk", ".jar", ".elf", ".sh", ".dll", ".msi", ".iso", ".img",
    ".vbe", ".wsf", ".cpl", ".reg"
}

# Dangerous / suspicious network ports
SUSPICIOUS_PORTS = {
    4444: ("Metasploit / C2 Listener", 25),
    6667: ("IRC Botnet Control", 25),
    31337: ("Back Orifice / Trojan", 25),
    1337: ("Elite Hacker / C2", 20),
    8080: ("Alternate Web / Proxy", 10),
    8888: ("Alternate Web / Proxy", 10),
    23: ("Telnet / IoT Botnet Attack Vector", 20),
    3389: ("RDP / Brute-force Exposure", 18),
    22: ("SSH / Brute-force Exposure", 12),
    445: ("SMB / EternalBlue Exploit Vector", 22),
    8545: ("Ethereum RPC / Crypto Miner", 20),
    30303: ("Ethereum P2P / Miner", 18),
    5900: ("VNC Remote Access Exposure", 18),
    1433: ("MSSQL Attack Vector", 15),
    3306: ("MySQL Exposure", 15),
}

# Known Tor exit node / high-risk subnets prefixes (illustrative heuristics)
KNOWN_RISKY_IP_PREFIXES = [
    "185.220.101.",  # Tor exit relays
    "185.220.102.",
    "198.98.56.",
    "194.26.29.",
    "45.154.255.",
    "193.142.146.",
]

# Phishing / Credential harvesting keywords
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "account", "update", "confirm", "security", "wallet", "banking",
    "authenticate", "password", "reset", "billing", "invoice", "auth",
    "validate", "support", "portal", "secure", "free-gift", "claim",
    "reward", "airdrop", "kyc", "recover"
]

# Malware keywords
MALWARE_KEYWORDS = [
    "malware", "ransomware", "trojan", "stealer", "infostealer", "keylogger",
    "rat", "c2", "command and control", "beacon", "cobalt strike", "payload",
    "exploit", "dropper", "backdoor", "rootkit", "worm", "spyware"
]

# Botnet keywords
BOTNET_KEYWORDS = [
    "botnet", "mirai", "ddos", "flood", "syn flood", "amplification",
    "zombie", "bot controller", "c&c"
]

# Brute force keywords
BRUTE_FORCE_KEYWORDS = [
    "brute force", "bruteforce", "credential stuffing", "dictionary attack",
    "failed logins", "ssh scan", "rdp scan", "port scan", "reconnaissance"
]


def calculate_risk_score(
    source_score: int,
    severity_score: int,
    frequency_score: int,
    recency_score: int,
    corroboration_score: int
) -> int:
    """
    Calculate combined risk score (0 to 100).
    Maintains compatibility with original function signature.
    """
    total = (
        int(source_score or 0)
        + int(severity_score or 0)
        + int(frequency_score or 0)
        + int(recency_score or 0)
        + int(corroboration_score or 0)
    )
    return max(0, min(total, 100))


def get_severity(risk_score: int) -> str:
    """
    Map numerical risk score to categorical severity level.
    """
    if risk_score <= 30:
        return "LOW"
    elif risk_score <= 60:
        return "MEDIUM"
    elif risk_score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"


def classify_threat(indicator: str, description: str = "") -> str:
    """
    Categorize threat based on indicator analysis and description context.
    Maintains compatibility with original function signature while expanding intelligence.
    """
    cleaned = indicator.strip()
    text = f"{cleaned} {description}".lower()

    # Check URL structure and domain legitimacy first
    if cleaned.startswith("http://") or cleaned.startswith("https://") or "/" in cleaned or "." in cleaned:
        try:
            parsed = urlparse(cleaned if "://" in cleaned else f"http://{cleaned}")
            host = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()

            for ext in MALICIOUS_EXTENSIONS:
                if path.endswith(ext):
                    return "Malware"

            is_legit = any(host == legit or host.endswith(f".{legit}") for legit in LEGITIMATE_BRAND_DOMAINS)
            if not is_legit:
                for brand in TARGETED_BRANDS:
                    if brand in host:
                        return "Phishing"

            if not is_legit and (any(kw in path for kw in PHISHING_KEYWORDS) or any(kw in host for kw in PHISHING_KEYWORDS)):
                return "Phishing"
            elif is_legit and not any(k in f"{path} {description}".lower() for k in MALWARE_KEYWORDS):
                return "Benign"
        except Exception:
            pass

    if any(k in text for k in MALWARE_KEYWORDS):
        return "Malware"
    elif any(k in text for k in BOTNET_KEYWORDS):
        return "Botnet"
    elif any(k in text for k in BRUTE_FORCE_KEYWORDS):
        return "Brute Force"
    elif "ransom" in text:
        return "Ransomware"
    elif any(k in text for k in PHISHING_KEYWORDS):
        return "Phishing"
    elif "harvest" in text or "credential" in text:
        return "Credential Harvesting"
    elif "suspicious" in text:
        return "Suspicious"

    # Deep inspection of IP indicators
    if is_valid_ip(cleaned):
        try:
            ip_obj = ipaddress.ip_address(cleaned.split(":")[0])
            if (ip_obj.is_private or ip_obj.is_loopback) and not any(
                k in text for k in (MALWARE_KEYWORDS + BOTNET_KEYWORDS + BRUTE_FORCE_KEYWORDS + PHISHING_KEYWORDS)
            ):
                return "Benign"
            for prefix in KNOWN_RISKY_IP_PREFIXES:
                if str(ip_obj).startswith(prefix):
                    return "Botnet"
        except Exception:
            pass

    return "Unknown"


def is_valid_ip(target: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address (with optional port)."""
    cleaned = target.strip()
    # Strip port if present
    if ":" in cleaned and not cleaned.startswith("["):
        parts = cleaned.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            cleaned = parts[0]
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def detect_indicator_type(indicator: str, hinted_type: str = "") -> str:
    """Auto-detect or refine the indicator type."""
    hint = (hinted_type or "").strip().lower()
    ind = indicator.strip().lower()

    if is_valid_ip(ind):
        return "IP Address"

    if ind.startswith("http://") or ind.startswith("https://") or ind.startswith("ftp://"):
        return "URL"

    if "/" in ind and ("." in ind.split("/")[0]):
        return "URL"

    if re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", ind):
        return "File Hash"

    if "." in ind and not " " in ind:
        return "Domain"

    if "ip" in hint:
        return "IP Address"
    if "url" in hint or "link" in hint:
        return "URL"
    if "domain" in hint:
        return "Domain"
    if "hash" in hint:
        return "File Hash"

    return hinted_type or "Unknown"


def analyze_ip_indicator(ip_str: str, source: str = "", description: str = ""):
    """Perform deep security analysis on an IP address."""
    findings = []
    base_severity = 10
    base_frequency = 10
    base_recency = 10
    base_corroboration = 5

    extracted_port = None
    ip_clean = ip_str.strip()

    if ":" in ip_clean and not ip_clean.startswith("["):
        parts = ip_clean.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            ip_clean = parts[0]
            extracted_port = int(parts[1])

    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        ip_version = f"IPv{ip_obj.version}"
    except ValueError:
        return {
            "is_valid": False,
            "category": "Suspicious",
            "findings": ["[CRITICAL] Invalid IP address format."],
            "severity_score": 25,
            "frequency_score": 10,
            "recency_score": 10,
            "corroboration_score": 5,
        }

    is_private = ip_obj.is_private
    is_loopback = ip_obj.is_loopback
    is_multicast = ip_obj.is_multicast
    is_reserved = ip_obj.is_reserved

    if is_loopback:
        findings.append("[INFO] Loopback IP address (127.0.0.1 / localhost).")
        base_severity = 5
    elif is_private:
        findings.append(f"[INFO] RFC 1918 Private Internal IP ({ip_clean}).")
        base_severity = 8
    elif is_multicast or is_reserved:
        findings.append("[INFO] Reserved or Multicast IP address space.")
        base_severity = 5
    else:
        findings.append(f"[PUBLIC] Routable Public {ip_version} address: {ip_clean}.")
        base_severity = 18

    # Check for known high-risk IP subnets (Tor exits, bulletproof hosting)
    for prefix in KNOWN_RISKY_IP_PREFIXES:
        if str(ip_obj).startswith(prefix):
            findings.append("[CRITICAL] Known Tor Exit Relay / Anonymization proxy subnet detected.")
            base_severity += 15
            base_corroboration += 10
            break

    # Analyze extracted or mentioned port
    if extracted_port and extracted_port in SUSPICIOUS_PORTS:
        desc, weight = SUSPICIOUS_PORTS[extracted_port]
        findings.append(f"[HIGH] High-risk network port detected: {extracted_port} ({desc}).")
        base_severity += weight
        base_corroboration += 5

    # Context analysis from description and source
    text_ctx = f"{description} {source}".lower()

    if any(k in text_ctx for k in MALWARE_KEYWORDS):
        findings.append("[CRITICAL] Indicator associated with active Malware / C2 beaconing.")
        base_severity += 20
        base_frequency += 10
        base_corroboration += 10
    if any(k in text_ctx for k in BOTNET_KEYWORDS):
        findings.append("[CRITICAL] Botnet activity or DDoS flood participation reported.")
        base_severity += 18
        base_frequency += 10
    if any(k in text_ctx for k in BRUTE_FORCE_KEYWORDS):
        findings.append("[HIGH] High-frequency brute force authentication attacks observed.")
        base_severity += 15
        base_frequency += 12
    if any(k in text_ctx for k in PHISHING_KEYWORDS):
        findings.append("[HIGH] Phishing infrastructure / credential harvesting host.")
        base_severity += 16
        base_corroboration += 8

    # If it's a private IP and no attack described, keep risk minimal
    if (is_private or is_loopback) and not any(
        k in text_ctx for k in (MALWARE_KEYWORDS + BOTNET_KEYWORDS + BRUTE_FORCE_KEYWORDS)
    ):
        base_severity = 6
        base_frequency = 5
        base_recency = 5
        base_corroboration = 4

    return {
        "is_valid": True,
        "ip_version": ip_version,
        "is_private": is_private,
        "is_loopback": is_loopback,
        "extracted_port": extracted_port,
        "findings": findings,
        "severity_score": min(base_severity, 30),
        "frequency_score": min(base_frequency, 20),
        "recency_score": min(base_recency, 15),
        "corroboration_score": min(base_corroboration, 15),
    }


def analyze_url_or_domain(target: str, source: str = "", description: str = ""):
    """Perform deep cybersecurity inspection on a website URL or domain."""
    findings = []
    base_severity = 10
    base_frequency = 10
    base_recency = 10
    base_corroboration = 5

    raw = target.strip()
    if not ("://" in raw):
        url = f"http://{raw}"
    else:
        url = raw

    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "http").lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        path = (parsed.path or "").lower()
        query = (parsed.query or "").lower()
    except Exception as e:
        return {
            "is_valid": False,
            "category": "Suspicious",
            "findings": [f"[CRITICAL] Malformed URL syntax: {str(e)}"],
            "severity_score": 25,
            "frequency_score": 10,
            "recency_score": 10,
            "corroboration_score": 5,
        }

    # 1. Scheme inspection
    if scheme == "http":
        findings.append("[WARNING] Insecure HTTP protocol (unencrypted transport).")
        base_severity += 5

    # 2. Hostname is direct IP address
    if hostname and is_valid_ip(hostname):
        findings.append("[CRITICAL] Raw IP address used as website host (evasion technique).")
        base_severity += 20
        base_corroboration += 8

    # 3. Port inspection
    if port and port in SUSPICIOUS_PORTS:
        desc, weight = SUSPICIOUS_PORTS[port]
        findings.append(f"[HIGH] Non-standard suspicious web port: {port} ({desc}).")
        base_severity += weight

    # 4. TLD analysis
    if "." in hostname:
        tld = hostname.split(".")[-1].lower()
        if tld in SUSPICIOUS_TLDS:
            findings.append(f"[HIGH] Suspicious / high-abuse Top-Level Domain (TLD): .{tld}")
            base_severity += 15
            base_corroboration += 8

    # 5. Brand impersonation / Typosquatting
    is_legit = any(hostname.endswith(legit) for legit in LEGITIMATE_BRAND_DOMAINS)
    if not is_legit:
        for brand in TARGETED_BRANDS:
            if brand in hostname:
                findings.append(
                    f"[CRITICAL] Brand Impersonation detected: Target brand '{brand.upper()}' embedded in unauthorized domain '{hostname}'."
                )
                base_severity += 22
                base_corroboration += 10
                break

    # 6. Excess subdomains or hyphens
    subdomain_parts = hostname.split(".")
    if len(subdomain_parts) >= 4:
        findings.append(f"[SUSPICIOUS] Excessive subdomain nesting ({len(subdomain_parts)} levels).")
        base_severity += 8
        base_corroboration += 4

    if hostname.count("-") >= 3:
        findings.append(f"[SUSPICIOUS] Excessive hyphenation in domain ({hostname.count('-')} hyphens).")
        base_severity += 6

    # 7. Credential userinfo in authority (@ in URL)
    if "@" in raw:
        findings.append("[CRITICAL] Credential obfuscation (@ sign in URL authority).")
        base_severity += 20
        base_corroboration += 8

    # 8. Malicious file extensions in path
    for ext in MALICIOUS_EXTENSIONS:
        if path.endswith(ext) or ext in query:
            findings.append(f"[CRITICAL] Executable / Malicious payload download detected: {ext}")
            base_severity += 25
            base_corroboration += 10
            break

    # 9. Phishing keywords in path or query
    detected_phish_words = [kw for kw in PHISHING_KEYWORDS if kw in path or kw in query]
    if detected_phish_words:
        findings.append(
            f"[HIGH] Phishing / credential harvesting endpoints in URL path: {', '.join(detected_phish_words[:3])}"
        )
        base_severity += 15
        base_corroboration += 6

    # 10. Web exploit patterns
    exploit_patterns = ["../", "cmd=", "exec=", "shell=", "eval=", "<script", "union select", "base64", "chmod", "wget", "curl"]
    detected_exploits = [p for p in exploit_patterns if p in url.lower()]
    if detected_exploits:
        findings.append(
            f"[CRITICAL] Web exploit / injection pattern detected in URL: {', '.join(detected_exploits)}"
        )
        base_severity += 22
        base_corroboration += 8

    # 11. Known legitimate domains
    if is_legit and not detected_phish_words and not detected_exploits:
        findings.append("[SAFE] Official reputable enterprise domain recognized.")
        base_severity = 5
        base_frequency = 5
        base_recency = 5
        base_corroboration = 3

    # Context analysis from description and source
    text_ctx = f"{description} {source}".lower()
    if any(k in text_ctx for k in MALWARE_KEYWORDS):
        findings.append("[CRITICAL] Threat feed / analyst notes confirm active Malware activity.")
        base_severity += 15
        base_frequency += 10
    if any(k in text_ctx for k in PHISHING_KEYWORDS):
        findings.append("[HIGH] Analyst report classifies this indicator as an active Phishing campaign.")
        base_severity += 15
        base_corroboration += 8

    return {
        "is_valid": True,
        "scheme": scheme,
        "hostname": hostname,
        "port": port,
        "path": path,
        "findings": findings,
        "severity_score": min(base_severity, 30),
        "frequency_score": min(base_frequency, 20),
        "recency_score": min(base_recency, 15),
        "corroboration_score": min(base_corroboration, 15),
    }


def evaluate_source_score(source: str = "") -> int:
    """Evaluate reliability score of the reporting source (0 to 20)."""
    s = (source or "").strip().lower()
    if any(k in s for k in ["cisa", "cert", "abuseipdb", "virustotal", "alienvault", "misp", "threatfeed", "feed", "firewall", "ids", "siem"]):
        return 19
    elif any(k in s for k in ["soc", "analyst", "automated scan", "honeypot", "crowdstrike", "sentinel"]):
        return 17
    elif "manual" in s or "admin" in s:
        return 15
    elif not s or s == "unknown":
        return 10
    else:
        return 12


def analyze_threat_indicator(
    indicator: str,
    indicator_type: str = "",
    source: str = "",
    description: str = "",
    override_scores: dict | None = None
) -> dict:
    """
    Main orchestration engine.
    Analyzes an indicator, computes all 5 risk scoring factors,
    determines severity and category, and builds a comprehensive report.
    """
    cleaned_indicator = indicator.strip()
    detected_type = detect_indicator_type(cleaned_indicator, indicator_type)
    source_str = source.strip() if source else "Manual Entry"
    desc_str = description.strip() if description else ""

    # Evaluate Source Reliability
    source_score = evaluate_source_score(source_str)

    # Perform targeted technical inspection
    if detected_type == "IP Address":
        intel = analyze_ip_indicator(cleaned_indicator, source=source_str, description=desc_str)
    elif detected_type in ("URL", "Domain"):
        intel = analyze_url_or_domain(cleaned_indicator, source=source_str, description=desc_str)
    else:
        # Generic indicator fallback
        intel = {
            "findings": [f"[INFO] Indicator evaluated under standard heuristics for {detected_type}."],
            "severity_score": 15,
            "frequency_score": 10,
            "recency_score": 10,
            "corroboration_score": 5,
        }

    severity_score = intel.get("severity_score", 15)
    frequency_score = intel.get("frequency_score", 10)
    recency_score = intel.get("recency_score", 10)
    corroboration_score = intel.get("corroboration_score", 5)

    category = classify_threat(cleaned_indicator, desc_str)

    # Boost frequency / corroboration for active phishing or malware
    if category in ("Phishing", "Malware") and severity_score >= 20:
        frequency_score = max(frequency_score, 14)
        corroboration_score = max(corroboration_score, 12)

    # Calibrate safe / benign indicators down to LOW risk tier (0-30)
    if category == "Benign" or (
        intel.get("is_valid") and (
            intel.get("is_loopback")
            or (intel.get("is_private") and severity_score <= 10)
            or any("[SAFE]" in f for f in intel.get("findings", []))
        )
    ):
        category = "Benign"
        source_score = min(source_score, 6)
        severity_score = min(severity_score, 6)
        frequency_score = min(frequency_score, 5)
        recency_score = min(recency_score, 5)
        corroboration_score = min(corroboration_score, 3)

    # Allow custom override scores if user specifically provided non-default values
    if override_scores:
        if "source_score" in override_scores and override_scores["source_score"] is not None:
            source_score = override_scores["source_score"]
        if "severity_score" in override_scores and override_scores["severity_score"] is not None:
            severity_score = override_scores["severity_score"]
        if "frequency_score" in override_scores and override_scores["frequency_score"] is not None:
            frequency_score = override_scores["frequency_score"]
        if "recency_score" in override_scores and override_scores["recency_score"] is not None:
            recency_score = override_scores["recency_score"]
        if "corroboration_score" in override_scores and override_scores["corroboration_score"] is not None:
            corroboration_score = override_scores["corroboration_score"]

    risk_score = calculate_risk_score(
        source_score=source_score,
        severity_score=severity_score,
        frequency_score=frequency_score,
        recency_score=recency_score,
        corroboration_score=corroboration_score
    )

    severity = get_severity(risk_score)
    category = classify_threat(cleaned_indicator, desc_str)

    # If benign domain/IP scored low, classify appropriately
    if risk_score <= 30 and category in ("Unknown", "Suspicious"):
        category = "Benign"

    findings = intel.get("findings", [])
    report_text = generate_report_markdown(
        indicator=cleaned_indicator,
        detected_type=detected_type,
        category=category,
        risk_score=risk_score,
        severity=severity,
        source=source_str,
        source_score=source_score,
        severity_score=severity_score,
        frequency_score=frequency_score,
        recency_score=recency_score,
        corroboration_score=corroboration_score,
        findings=findings,
        description=desc_str
    )

    return {
        "indicator": cleaned_indicator,
        "indicator_type": detected_type,
        "category": category,
        "risk_score": risk_score,
        "severity": severity,
        "source_score": source_score,
        "severity_score": severity_score,
        "frequency_score": frequency_score,
        "recency_score": recency_score,
        "corroboration_score": corroboration_score,
        "findings": findings,
        "analysis_details": report_text,
        "alert_required": (risk_score >= 80)
    }


def generate_report_markdown(
    indicator: str,
    detected_type: str,
    category: str,
    risk_score: int,
    severity: str,
    source: str,
    source_score: int,
    severity_score: int,
    frequency_score: int,
    recency_score: int,
    corroboration_score: int,
    findings: list,
    description: str
) -> str:
    """Format structured intelligence report for display and audit logging."""
    status_alert = "CRITICAL ALERT TRIGGERED - Immediate SOC Containment Recommended" if risk_score >= 80 else "Standard Monitoring - Routine Analysis Complete"

    findings_formatted = "\n".join([f"• {f}" for f in findings]) if findings else "• No overt anomalous indicators detected."

    mitigations = []
    if risk_score >= 80:
        mitigations = [
            "Block indicator at enterprise perimeter firewalls and web proxies.",
            "Sinkhole domain at recursive internal DNS resolvers.",
            "Cross-reference EDR telemetry for host-level connection attempts.",
            "Trigger automated SIEM alert and notify Incident Response team.",
            "Revoke active user sessions if authentication endpoints were compromised."
        ]
    elif risk_score >= 60:
        mitigations = [
            "Flag indicator in gateway egress filters with inspection logging.",
            "Monitor DNS resolution spikes and endpoint communication patterns.",
            "Verify origin and SSL certificate chain for domain validity.",
            "Add to Tier-2 threat hunting watchlist."
        ]
    else:
        mitigations = [
            "No immediate containment required.",
            "Maintain standard threat telemetry retention.",
            "Re-evaluate if external corroborating threat feeds report activity."
        ]

    mitigations_formatted = "\n".join([f"1. {m}" for m in mitigations])

    report = f"""================================================================================
SECURITY INTELLIGENCE ANALYSIS REPORT
================================================================================
Indicator: {indicator}
Type: {detected_type} | Category: {category} | Risk Level: {severity} ({risk_score}/100)
Status: {status_alert}
Reported Source: {source}

[1] EXECUTIVE SUMMARY
The indicator '{indicator}' was processed through the threat intelligence analysis engine.
Based on heuristic inspection, structural indicators, and reputation scoring, this asset
exhibits a risk score of {risk_score}/100, placing it in the {severity} risk tier.

[2] DETECTED RISK FACTORS & IOC FINDINGS
{findings_formatted}

[3] SCORING FACTOR BREAKDOWN (0-100 Scale)
• Source Reliability Factor:    {source_score:2d} / 20 pts
• Threat Severity Factor:       {severity_score:2d} / 30 pts
• Frequency & Pattern Factor:   {frequency_score:2d} / 20 pts
• Recency & Velocity Factor:    {recency_score:2d} / 15 pts
• Corroboration & Heuristics:   {corroboration_score:2d} / 15 pts
--------------------------------------------------------------------------------
• TOTAL CALCULATED RISK SCORE:  {risk_score:2d} / 100 [{severity}]

[4] ACTIONABLE MITIGATION & DEFENSE RECOMMENDATIONS
{mitigations_formatted}
================================================================================"""
    return report.strip()