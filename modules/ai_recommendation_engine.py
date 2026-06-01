def generate_security_recommendations(api_data):

    recommendations = []

    for _, row in api_data.iterrows():

        api_name = row["api_name"]

        risk = row["threat_level"]

        auth = row["authentication"]

        status = row["status"]

        sensitive = row["sensitive_data"]

        recommendation = ""

        # =========================
        # CRITICAL APIs
        # =========================

        if risk == "Critical":

            recommendation = f"""
Critical API detected.

Immediate Actions:
- Disable unused endpoint access
- Enable multi-factor authentication
- Place API behind secure gateway
- Enable continuous traffic monitoring
- Restrict access using IP whitelisting
"""

        # =========================
        # HIGH RISK APIs
        # =========================

        elif risk == "High":

            recommendation = f"""
High risk API detected.

Recommended Actions:
- Enable OAuth2 authentication
- Monitor abnormal request patterns
- Add rate limiting protection
- Encrypt sensitive transactions
"""

        # =========================
        # MEDIUM RISK APIs
        # =========================

        elif risk == "Medium":

            recommendation = f"""
Medium risk API detected.

Suggested Improvements:
- Review API access logs
- Strengthen authentication policy
- Monitor failed login attempts
"""

        # =========================
        # LOW RISK APIs
        # =========================

        else:

            recommendation = f"""
Low risk API.

Maintenance Actions:
- Continue periodic monitoring
- Maintain regular security audits
"""

        recommendations.append({

            "api_name": api_name,

            "threat_level": risk,

            "recommendation": recommendation

        })

    return recommendations