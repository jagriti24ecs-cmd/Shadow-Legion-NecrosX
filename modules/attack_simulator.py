import random
from datetime import datetime


def generate_attack():

    attack_types = [
        "SQL Injection",
        "Brute Force",
        "Credential Stuffing",
        "API Abuse",
        "Privilege Escalation",
        "Rate Limit Bypass",
        "Token Hijacking"
    ]

    targeted_apis = [
        "login_api",
        "legacy_transfer_api",
        "old_payment_gateway",
        "admin_api",
        "internal_audit_api",
        "payment_api",
        "upi_transfer_api"
    ]

    ip_addresses = [
        "192.168.1.25",
        "45.67.89.10",
        "203.54.1.90",
        "177.23.44.8",
        "99.23.11.45"
    ]

    severity_levels = [
        "Low",
        "Medium",
        "High",
        "Critical"
    ]

    attack_log = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "api_target": random.choice(targeted_apis),
        "attack_type": random.choice(attack_types),
        "source_ip": random.choice(ip_addresses),
        "severity": random.choice(severity_levels)
    }

    return attack_log


def generate_multiple_attacks(number_of_attacks=5):

    attack_logs = []

    for i in range(number_of_attacks):

        attack_logs.append(generate_attack())

    return attack_logs