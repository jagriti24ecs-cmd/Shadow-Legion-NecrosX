import pandas as pd


def automated_threat_response(attack_history):

    if len(attack_history) == 0:

        return []

    attack_df = pd.DataFrame(
        attack_history
    )

    response_actions = []

    for _, attack in attack_df.iterrows():

        source_ip = attack["source_ip"]

        api = attack["api_target"]

        severity = attack["severity"]

        attack_type = attack["attack_type"]

        action = ""

        # =========================
        # CRITICAL RESPONSE
        # =========================

        if severity == "Critical":

            action = (
                "BLOCK IP + "
                "QUARANTINE API + "
                "ENABLE FORENSIC LOGGING"
            )

        # =========================
        # HIGH RESPONSE
        # =========================

        elif severity == "High":

            action = (
                "RATE LIMIT SOURCE IP + "
                "ENABLE TRAFFIC MONITORING"
            )

        # =========================
        # MEDIUM RESPONSE
        # =========================

        elif severity == "Medium":

            action = (
                "MONITOR SESSION + "
                "INCREASE LOGGING"
            )

        # =========================
        # LOW RESPONSE
        # =========================

        else:

            action = (
                "CONTINUE PASSIVE MONITORING"
            )

        response_actions.append({

            "source_ip": source_ip,

            "target_api": api,

            "attack_type": attack_type,

            "severity": severity,

            "automated_action": action

        })

    return response_actions