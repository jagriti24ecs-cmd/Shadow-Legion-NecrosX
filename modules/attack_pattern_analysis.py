import pandas as pd


def analyze_attack_patterns(attack_history):

    if len(attack_history) < 3:

        return []

    attack_df = pd.DataFrame(
        attack_history
    )

    detected_patterns = []

    # =========================
    # BUILD API SEQUENCES
    # =========================

    api_sequence = (
        attack_df["api_target"]
        .tolist()
    )

    # Analyze movement patterns
    for i in range(len(api_sequence) - 2):

        pattern = (
            f"{api_sequence[i]}"
            f" → "
            f"{api_sequence[i+1]}"
            f" → "
            f"{api_sequence[i+2]}"
        )

        # =========================
        # PATTERN CLASSIFICATION
        # =========================

        risk = "Low"

        behavior = (
            "General Reconnaissance"
        )

        # Privilege escalation detection
        if (
            "login" in pattern
            and "admin" in pattern
        ):

            risk = "Critical"

            behavior = (
                "Privilege Escalation Attempt"
            )

        # Lateral movement detection
        elif (
            "legacy" in pattern
            or "internal" in pattern
        ):

            risk = "High"

            behavior = (
                "Lateral Movement Across Legacy Systems"
            )

        # Financial targeting
        elif (
            "payment" in pattern
            or "transfer" in pattern
        ):

            risk = "High"

            behavior = (
                "Financial Infrastructure Targeting"
            )

        detected_patterns.append({

            "attack_pattern": pattern,

            "behavior_type": behavior,

            "risk_level": risk

        })

    return detected_patterns