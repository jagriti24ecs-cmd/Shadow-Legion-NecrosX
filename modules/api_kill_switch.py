import random


def activate_kill_switch(attacks):

    responses = []

    for attack in attacks:

        if attack["severity"] == "Critical":

            responses.append({
                "target_api": attack["api_target"],
                "action": random.choice([
                    "API Endpoint Isolated",
                    "Traffic Redirected",
                    "Emergency Firewall Rule Applied",
                    "Temporary API Shutdown",
                    "Zero Trust Lockdown Activated"
                ]),
                "status": "Containment Successful"
            })

    return responses