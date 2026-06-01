import pandas as pd


# Zombie APIs converted into honeypots
honeypot_apis = [
    "legacy_transfer_api",
    "old_payment_gateway",
    "internal_audit_api",
    "debug_api",
    "test_admin_api"
]


def analyze_honeypot_activity(attack_logs):

    honeypot_hits = []

    for attack in attack_logs:

        if attack["api_target"] in honeypot_apis:

            attack["honeypot_triggered"] = "YES"

            honeypot_hits.append(attack)

    return pd.DataFrame(honeypot_hits)


def generate_attacker_profile(honeypot_logs):

    if honeypot_logs.empty:

        return pd.DataFrame()

    attacker_profiles = (
        honeypot_logs.groupby("source_ip")
        .size()
        .reset_index(name="honeypot_hits")
    )

    # Threat Classification
    def classify_attacker(hits):

        if hits >= 5:
            return "Critical"

        elif hits >= 3:
            return "High"

        elif hits >= 2:
            return "Medium"

        else:
            return "Low"

    attacker_profiles["threat_level"] = (
        attacker_profiles["honeypot_hits"]
        .apply(classify_attacker)
    )

    return attacker_profiles