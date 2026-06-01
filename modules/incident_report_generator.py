from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)

from reportlab.lib.pagesizes import letter

import pandas as pd


def generate_incident_report(
    attack_history,
    soc_summary
):

    # =========================
    # REPORT FILE
    # =========================

    file_path = (
        "NECROS_X_Incident_Report.pdf"
    )

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter
    )

    styles = getSampleStyleSheet()

    elements = []

    # =========================
    # TITLE
    # =========================

    title = Paragraph(
        "NECROS X Cybersecurity Incident Report",
        styles['Title']
    )

    elements.append(title)

    elements.append(
        Spacer(1, 20)
    )

    # =========================
    # CHECK ATTACK DATA
    # =========================

    if len(attack_history) == 0:

        no_data = Paragraph(
            "No attack activity detected.",
            styles['BodyText']
        )

        elements.append(no_data)

    else:

        attack_df = pd.DataFrame(
            attack_history
        )

        total_attacks = len(
            attack_df
        )

        critical_attacks = len(
            attack_df[
                attack_df["severity"]
                == "Critical"
            ]
        )

        top_target = (
            attack_df["api_target"]
            .value_counts()
            .idxmax()
        )

        top_ip = (
            attack_df["source_ip"]
            .value_counts()
            .idxmax()
        )

        # =========================
        # ATTACK STATISTICS
        # =========================

        stats = f"""
        Total Attacks Detected: {total_attacks}
        <br/><br/>
        Critical Attacks: {critical_attacks}
        <br/><br/>
        Most Targeted API: {top_target}
        <br/><br/>
        Most Suspicious IP: {top_ip}
        """

        stats_paragraph = Paragraph(
            stats,
            styles['BodyText']
        )

        elements.append(
            stats_paragraph
        )

        elements.append(
            Spacer(1, 20)
        )

        # =========================
        # AI SUMMARY
        # =========================

        summary_title = Paragraph(
            "AI SOC Incident Summary",
            styles['Heading2']
        )

        elements.append(
            summary_title
        )

        elements.append(
            Spacer(1, 10)
        )

        summary_paragraph = Paragraph(
            soc_summary.replace(
                "\n",
                "<br/>"
            ),
            styles['BodyText']
        )

        elements.append(
            summary_paragraph
        )

    # =========================
    # BUILD PDF
    # =========================

    doc.build(elements)

    return file_path