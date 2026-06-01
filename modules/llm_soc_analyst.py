def generate_soc_summary(attack_history):

    if len(attack_history) == 0:

        return """
SOC ANALYST REPORT

No attacks detected.

System status:
STABLE

No active threats identified.
"""

    total_attacks = len(attack_history)

    critical_count = len(
        [
            attack for attack in attack_history
            if attack["severity"] == "Critical"
        ]
    )

    high_count = len(
        [
            attack for attack in attack_history
            if attack["severity"] == "High"
        ]
    )

    targeted_apis = list(
        set(
            [
                attack["api_target"]
                for attack in attack_history
            ]
        )
    )

    summary = f"""
SOC ANALYST REPORT

Total Attacks Detected:
{total_attacks}

Critical Threats:
{critical_count}

High Severity Threats:
{high_count}

Targeted APIs:
{', '.join(targeted_apis)}

Threat Assessment:
Attackers are actively probing sensitive APIs.
Patterns indicate coordinated intrusion attempts.

Recommended SOC Actions:
- Enable stricter API authentication
- Monitor zombie APIs closely
- Increase honeypot deployment
- Activate defensive response escalation
"""

    return summary