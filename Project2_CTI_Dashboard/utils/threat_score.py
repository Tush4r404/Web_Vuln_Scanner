def calculate_threat_score(vt, abuse):
    vt_score = 0
    abuse_score = 0

    if vt:
        stats = vt.get("data", [{}])[0].get("attributes", {}).get("last_analysis_stats", {})
        vt_score = stats.get("malicious", 0) + stats.get("suspicious", 0)

    if abuse:
        abuse_score = abuse.get("data", {}).get("abuseConfidenceScore", 0)

    if vt_score >= 5 or abuse_score >= 70:
        return "High"
    elif vt_score >= 2 or abuse_score >= 40:
        return "Medium"
    else:
        return "Low"
