def calculate_risk_score(api):

    risk_score = 0

    # Zombie APIs are dangerous
    if api["status"] == "Zombie":
        risk_score += 40

    # Deprecated APIs are risky
    if api["status"] == "Deprecated":
        risk_score += 25

    # No authentication is highly dangerous
    if api["authentication"] == "No_Auth":
        risk_score += 30

    # Sensitive financial data increases risk
    if api["sensitive_data"] == "Yes":
        risk_score += 20

    # Very old APIs are suspicious
    if api["last_used_days"] > 300:
        risk_score += 20

    return risk_score


def classify_threat_level(risk_score):

    if risk_score >= 81:
        return "Critical"

    elif risk_score >= 61:
        return "High"

    elif risk_score >= 31:
        return "Medium"

    else:
        return "Low"