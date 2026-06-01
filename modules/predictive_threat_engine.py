import pandas as pd


def predict_future_targets(attack_history):

    if len(attack_history) == 0:

        return pd.DataFrame()

    attack_df = pd.DataFrame(
        attack_history
    )

    # Count attacks per API
    api_counts = (
        attack_df["api_target"]
        .value_counts()
        .reset_index()
    )

    api_counts.columns = [
        "api_name",
        "attack_count"
    ]

    # Generate prediction score
    max_attacks = (
        api_counts["attack_count"]
        .max()
    )

    api_counts["prediction_score"] = (
        api_counts["attack_count"]
        / max_attacks
    ) * 100

    # Risk categorization
    def classify_prediction(score):

        if score >= 80:
            return "Critical"

        elif score >= 60:
            return "High"

        elif score >= 40:
            return "Medium"

        else:
            return "Low"

    api_counts["future_risk"] = (
        api_counts["prediction_score"]
        .apply(classify_prediction)
    )

    return api_counts