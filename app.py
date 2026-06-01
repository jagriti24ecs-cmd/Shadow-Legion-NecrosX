import streamlit as st
import pandas as pd
import plotly.express as px
import streamlit.components.v1 as components
import time
import numpy as np

from modules.api_kill_switch import (
    activate_kill_switch
)
# =====================================
# LOAD CUSTOM CSS
# =====================================

with open(
    "assets/styles.css"
) as f:

    st.markdown(

        f"<style>{f.read()}</style>",

        unsafe_allow_html=True
    )

from modules.risk_analyzer import (
    calculate_risk_score,
    classify_threat_level
)

from modules.attack_simulator import (
    generate_attack,
    generate_multiple_attacks
)

from modules.honeypot_engine import (
    analyze_honeypot_activity,
    generate_attacker_profile
)

from modules.attack_path_visualizer import (
    generate_attack_path_graph
)

from modules.predictive_threat_engine import (
    predict_future_targets
)

from modules.ai_recommendation_engine import (
    generate_security_recommendations
)

from modules.attack_pattern_analysis import (
    analyze_attack_patterns
)

from modules.automated_response_system import (
    automated_threat_response
)

from modules.llm_soc_analyst import (
    generate_soc_summary
)

from modules.incident_report_generator import (
    generate_incident_report
)

# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="NECROS X",
    layout="wide"
)

# =====================================================
# SESSION STATE
# =====================================================

if "attack_history" not in st.session_state:
    st.session_state.attack_history = []
if "live_mode" not in st.session_state:
    st.session_state.live_mode = False
if "blocked_apis" not in st.session_state:
    st.session_state.blocked_apis = []
# =====================================================
# LOAD DATA
# =====================================================

api_data = pd.read_csv(
    "data/apis.csv"
)

# =====================================================
# RISK ENGINE
# =====================================================

api_data["risk_score"] = api_data.apply(
    calculate_risk_score,
    axis=1
)

api_data["threat_level"] = api_data[
    "risk_score"
].apply(classify_threat_level)

# =====================================================
# TABLE COLOR FUNCTION
# =====================================================

def color_risk(row):

    level = ""

    if "threat_level" in row:
        level = row["threat_level"]

    elif "severity" in row:
        level = row["severity"]

    elif "future_risk" in row:
        level = row["future_risk"]

    if level == "Critical":

        color = (
            "background-color: rgba(255,0,0,0.28)"
        )

    elif level == "High":

        color = (
            "background-color: rgba(255,165,0,0.28)"
        )

    elif level == "Medium":

        color = (
            "background-color: rgba(255,255,0,0.22)"
        )

    else:

        color = (
            "background-color: rgba(0,255,0,0.20)"
        )

    return [color] * len(row)

# =====================================================
# SIDEBAR
# =====================================================

st.sidebar.markdown(
    """
    <div class='sidebar-title'>
        ⚡ NECROS X
    </div>
    """,
    unsafe_allow_html=True
)

# ============================================
# SIDEBAR NAVIGATION
# ============================================



# Default page

if "page" not in st.session_state:
    st.session_state.page = "Dashboard Overview"

# Navigation Buttons

if st.sidebar.button("Dashboard Overview", use_container_width=True):
    st.session_state.page = "Dashboard Overview"

if st.sidebar.button("Threat Monitoring", use_container_width=True):
    st.session_state.page = "Threat Monitoring"

if st.sidebar.button("Honeypot Intelligence", use_container_width=True):
    st.session_state.page = "Honeypot Intelligence"

if st.sidebar.button("Attack Visualization", use_container_width=True):
    st.session_state.page = "Attack Visualization"

if st.sidebar.button("AI Intelligence", use_container_width=True):
    st.session_state.page = "AI Intelligence"

if st.sidebar.button("Autonomous Response", use_container_width=True):
    st.session_state.page = "Autonomous Response"

if st.sidebar.button("SOC Analyst", use_container_width=True):
    st.session_state.page = "SOC Analyst"

if st.sidebar.button("Incident Reports", use_container_width=True):
    st.session_state.page = "Incident Reports"
if st.sidebar.button("Executive Summary", use_container_width=True):
    st.session_state.page = "Executive Summary"
# Current selected page

page = st.session_state.page

# ============================================
# COMPACT TOPBAR
# ============================================

top_left, top_right1, top_right2 = st.columns([12,1,1])

with top_right1:

    if st.button("🛡️"):

        st.session_state.show_controls = not st.session_state.get(
            "show_controls",
            False
        )
with top_right2:

    st.session_state.live_mode = st.toggle(
        "LIVE",
        value=st.session_state.live_mode
    )

with top_right2:

    if "enable_colors" not in st.session_state:

        st.session_state.enable_colors = True

    st.session_state.enable_colors = st.toggle(
        "",
        value=st.session_state.enable_colors
    )
    

# ============================================
# FLOATING CONTROL CENTER
# ============================================

if st.session_state.get("show_controls", False):

    st.info("Threat Simulation Control Center")

    col1, col2, col3 = st.columns(3)

    with col1:

        if st.button("Launch Single Attack"):

            attack = generate_attack()

            st.session_state.attack_history.append(
                attack
            )

    with col2:

        if st.button("Launch Coordinated Attack"):

            attacks = generate_multiple_attacks(10)

            st.session_state.attack_history.extend(
                attacks
            )

    with col3:

        if st.button("Clear Logs"):

            st.session_state.attack_history = []

# ============================================
# LIVE THREAT STREAM ENGINE
# ============================================

if st.session_state.live_mode:

    new_attack = generate_attack()

    st.session_state.attack_history.append(
        new_attack
    )

    if len(st.session_state.attack_history) > 100:

        st.session_state.attack_history = (
            st.session_state.attack_history[-100:]
        )

    time.sleep(2)

    st.rerun()

# ============================================
# API KILL SWITCH ENGINE
# ============================================

attack_counts = {}

for attack in st.session_state.attack_history:

    api = attack["api_target"]

    attack_counts[api] = (
        attack_counts.get(api, 0) + 1
    )

for api, count in attack_counts.items():

    if count >= 5:

        if api not in st.session_state.blocked_apis:

            st.session_state.blocked_apis.append(api)


# =====================================================
# MAIN HEADER
# =====================================================

title_col, control_col = st.columns([8, 1])

with title_col:

    st.markdown(
        """
<div style='margin-top:-10px;'>

<h1 style='
font-size:64px;
font-weight:800;
margin-bottom:10px;
color:white;
'>
NECROS X
</h1>

<h3 style='
font-size:28px;
font-weight:600;
line-height:1.4;
color:white;
margin-top:0px;
'>
Autonomous Zombie API Detection & Defense System
</h3>

</div>
        """,
        unsafe_allow_html=True
    )
# =====================================================
# DASHBOARD OVERVIEW
# =====================================================

if page == "Dashboard Overview":

    st.header(
        "API Infrastructure Dashboard"
    )

    total_apis = len(api_data)

    active_apis = len(
        api_data[
            api_data["status"] == "Active"
        ]
    )

    zombie_apis = len(
        api_data[
            api_data["status"] == "Zombie"
        ]
    )

    deprecated_apis = len(
        api_data[
            api_data["status"] == "Deprecated"
        ]
    )

    critical_apis = len(
        api_data[
            api_data["threat_level"] == "Critical"
        ]
    )

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric(
        "Total APIs",
        total_apis
    )

    col2.metric(
        "Active APIs",
        active_apis
    )

    col3.metric(
        "Zombie APIs",
        zombie_apis
    )

    col4.metric(
        "Deprecated APIs",
        deprecated_apis
    )

    col5.metric(
        "Critical APIs",
        critical_apis
    )

    st.markdown("---")

    dashboard_df = (
        api_data
        .sort_values(
            by="risk_score",
            ascending=False
        )
        .reset_index(drop=True)
    )

    dashboard_df.index += 1

    styled_dashboard = (
        dashboard_df.style
        .apply(color_risk, axis=1)
    )

    st.subheader(
        "Discovered API Infrastructure"
    )

    if st.session_state.enable_colors:

        st.dataframe(
            styled_dashboard,
            width="stretch"
        )

    else:

        st.dataframe(
            dashboard_df,
            width="stretch"
        )

    st.markdown("---")

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:

        status_counts = api_data[
            "status"
        ].value_counts()

        pie_chart = px.pie(

            values=status_counts.values,

            names=status_counts.index,

            title="API Status Distribution"

        )

        st.plotly_chart(
            pie_chart,
            width="stretch"
        )

    with chart_col2:

        risk_chart = px.bar(

            api_data.sort_values(
                by="risk_score",
                ascending=False
            ),

            x="api_name",

            y="risk_score",

            color="threat_level",

            title="API Risk Scores"

        )

        st.plotly_chart(
            risk_chart,
            width="stretch"
        )

# =====================================================
# THREAT MONITORING
# =====================================================

elif page == "Threat Monitoring":

    st.header(
        "Live Threat Intelligence Feed"
    )

    if len(
        st.session_state.attack_history
    ) == 0:

        st.success(
            "No active attacks detected"
        )

    else:

        attack_df = pd.DataFrame(
            st.session_state.attack_history
        )

        attack_df = attack_df.reset_index(
            drop=True
        )

        attack_df.index += 1

        styled_attacks = (
            attack_df.style
            .apply(color_risk, axis=1)
        )

        if st.session_state.enable_colors:

            st.dataframe(
                styled_attacks,
                width="stretch"
            )

        else:

            st.dataframe(
                attack_df,
                width="stretch"
            )

        st.markdown("---")
        
        st.subheader(
            "Threat Severity Timeline"
        )

        timeline_df = attack_df.copy()

        timeline_df["timestamp"] = pd.to_datetime(
            timeline_df["timestamp"]
        )

        severity_map = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }

        timeline_df["severity_score"] = (
            timeline_df["severity"]
            .map(severity_map)
        )

        timeline_chart = px.line(

            timeline_df,

            x="timestamp",

            y="severity_score",

            color="severity",

            markers=True,

            title="Real-Time Threat Escalation"
        )

        st.plotly_chart(
            timeline_chart,
            width="stretch"
        )

        st.subheader(
            "Critical Threat Alerts"
        )

        critical_attacks = attack_df[
            attack_df["severity"] == "Critical"
        ]

        if len(critical_attacks) == 0:

            st.success(
                "No critical threats detected"
            )

        else:

            for index, row in critical_attacks.iterrows():

                st.error(
                    f"""
Critical Threat Detected

Target API:
{row['api_target']}

Attack Type:
{row['attack_type']}

Source IP:
{row['source_ip']}
"""
                )

# =====================================================
# HONEYPOT INTELLIGENCE
# =====================================================

elif page == "Honeypot Intelligence":

    st.header(
        "Honeypot Defense Intelligence"
    )

    honeypot_logs = (
        analyze_honeypot_activity(
            st.session_state.attack_history
        )
    )

    if honeypot_logs.empty:

        st.info(
            "No honeypot activity detected"
        )

    else:

        honeypot_logs = (
            honeypot_logs.reset_index(
                drop=True
            )
        )

        honeypot_logs.index += 1

        styled_honeypot = (
            honeypot_logs.style
            .apply(color_risk, axis=1)
        )

        st.subheader(
            "Captured Honeypot Intrusions"
        )

        if st.session_state.enable_colors:

            st.dataframe(
                styled_honeypot,
                width="stretch"
            )

        else:

            st.dataframe(
                honeypot_logs,
                width="stretch"
            )

        st.markdown("---")

        attacker_profiles = (
            generate_attacker_profile(
                honeypot_logs
            )
        )

        attacker_profiles = (
            attacker_profiles.reset_index(
                drop=True
            )
        )

        attacker_profiles.index += 1

        styled_profiles = (
            attacker_profiles.style
            .apply(color_risk, axis=1)
        )

        st.subheader(
            "Suspicious Attacker Profiles"
        )

        if st.session_state.enable_colors:

            st.dataframe(
                styled_profiles,
                width="stretch"
            )

        else:

            st.dataframe(
                attacker_profiles,
                width="stretch"
            )
# =====================================================
# ATTACK VISUALIZATION
# =====================================================

elif page == "Attack Visualization":

    st.header(
        "Attack Path Visualization"
    )

    if len(
        st.session_state.attack_history
    ) == 0:

        st.info(
            "No attack paths available"
        )

    else:

        graph_html = (
            generate_attack_path_graph(
                st.session_state.attack_history
            )
        )

        components.html(
            graph_html,
            height=850,
            scrolling=True
        )

# =====================================================
# AI INTELLIGENCE
# =====================================================

elif page == "AI Intelligence":

    st.header(
        "AI Predictive Threat Intelligence"
    )

    prediction_df = (
        predict_future_targets(
            st.session_state.attack_history
        )
    )

    if prediction_df.empty:

        st.info(
            "Not enough attack data"
        )

    else:

        prediction_df = (
            prediction_df
            .sort_values(
                by="prediction_score",
                ascending=False
            )
            .reset_index(drop=True)
        )

        prediction_df[
            "prediction_score"
        ] = (

            prediction_df[
                "prediction_score"
            ]
            .round(1)
            .astype(str)

            + "%"

        )

        prediction_df.index += 1

        styled_predictions = (
            prediction_df.style
            .apply(color_risk, axis=1)
        )

        st.subheader(
            "Future Threat Prediction"
        )

        if st.session_state.enable_colors:

            st.dataframe(
                styled_predictions,
                width="stretch"
            )

        else:

            st.dataframe(
                prediction_df,
                width="stretch"
            )

        st.markdown("---")

        st.subheader(
            "Threat Intelligence Heatmap"
        )

        if len(st.session_state.attack_history) > 0:

            heatmap_df = pd.DataFrame(
                st.session_state.attack_history
            )

            attack_counts = (

                heatmap_df

                .groupby([
                    "api_target",
                    "attack_type"
                ])

                .size()

                .reset_index(name="count")
            )

            heatmap = px.density_heatmap(

                attack_counts,

                x="api_target",

                y="attack_type",

                z="count",

                title="Attack Concentration Across APIs"
            )

            st.plotly_chart(
                heatmap,
                width="stretch"
            )

        st.subheader(
            "AI Security Recommendations"
        )

        recommendations = (
            generate_security_recommendations(
                api_data
            )
        )

        for rec in recommendations:

            if rec["threat_level"] == "Critical":

                st.error(
                    rec["recommendation"]
                )

            elif rec["threat_level"] == "High":

                st.warning(
                    rec["recommendation"]
                )

            else:

                st.success(
                    rec["recommendation"]
                )

        st.markdown("---")

        st.subheader(
            "Attack Pattern Analysis"
        )

        patterns = (
            analyze_attack_patterns(
                st.session_state.attack_history
            )
        )

        if len(patterns) == 0:

            st.info(
                "No attack patterns identified"
            )

        else:

            for pattern in patterns:

                st.warning(
                    f"""
Attack Pattern:
{pattern['attack_pattern']}

Behavior:
{pattern['behavior_type']}

Risk:
{pattern['risk_level']}
"""
                )

# =====================================================
# AUTONOMOUS RESPONSE
# =====================================================

elif page == "Autonomous Response":
 
    st.header(
        "Autonomous Threat Response Engine"
    )

    responses = (
        automated_threat_response(
            st.session_state.attack_history
        )
    )

    if len(responses) == 0:

        st.info(
            "No active automated responses"
        )

    else:

        for response in responses:

            message = f"""
Target API:
{response['target_api']}

Attack Type:
{response['attack_type']}

Threat Severity:
{response['severity']}

Automated Action:
{response['automated_action']}
"""

            if response["severity"] == "Critical":

                st.error(message)

            elif response["severity"] == "High":

                st.warning(message)

            else:

                st.success(message)
    st.markdown("---")

    st.subheader(
        "Critical API Kill Switch"
    )

    if len(st.session_state.blocked_apis) == 0:

        st.success(
            "No APIs currently isolated"
        )

    else:

        blocked_df = pd.DataFrame({

            "Blocked API":
            st.session_state.blocked_apis,

            "Status":
            ["BLOCKED"] * len(
                st.session_state.blocked_apis
            ),

            "Containment":
            ["Traffic Terminated"] * len(
                st.session_state.blocked_apis
            )
        })

        blocked_df.index += 1

        st.error(
            "Critical APIs Automatically Isolated"
        )

        st.dataframe(
            blocked_df,
            width="stretch"
        )       
# =====================================================
# SOC ANALYST
# =====================================================

elif page == "SOC Analyst":

    st.header(
        "LLM SOC Security Analyst"
    )

    soc_summary = (
        generate_soc_summary(
            st.session_state.attack_history
        )
    )

    st.info(
        soc_summary
    )

# =====================================================
# INCIDENT REPORTS
# =====================================================

elif page == "Incident Reports":

    st.header(
        "AI Incident Report Generator"
    )

    st.write(
        "Generate downloadable SOC incident reports"
    )

    soc_summary = (
        generate_soc_summary(
            st.session_state.attack_history
        )
    )

    if st.button(
        "Generate Incident Report PDF"
    ):

        report_path = (
            generate_incident_report(

                st.session_state.attack_history,

                soc_summary

            )
        )

        with open(
            report_path,
            "rb"
        ) as pdf_file:

            st.download_button(

                label="Download Incident Report",

                data=pdf_file,

                file_name=report_path,

                mime="application/pdf"

            )


# =====================================================
# EXECUTIVE SUMMARY
# =====================================================

elif page == "Executive Summary":

    st.header(
        "Executive SOC Intelligence Summary"
    )

    total_attacks = len(
        st.session_state.attack_history
    )

    critical_attacks = len([

        x for x in st.session_state.attack_history

        if x["severity"] == "Critical"

    ])

    high_attacks = len([

        x for x in st.session_state.attack_history

        if x["severity"] == "High"

    ])

    blocked_count = len(
        st.session_state.blocked_apis
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Attacks",
        total_attacks
    )

    col2.metric(
        "Critical Threats",
        critical_attacks
    )

    col3.metric(
        "High Severity",
        high_attacks
    )

    col4.metric(
        "Blocked APIs",
        blocked_count
    )

    st.markdown("---")

    st.warning(
        f"""
NECROS X has autonomously analyzed
the banking API infrastructure.

Total detected attacks:
{total_attacks}

Critical threats:
{critical_attacks}

Blocked APIs:
{blocked_count}

AI threat intelligence predicts
continued attacks against
legacy banking APIs.

Recommended Executive Action:
Increase Zero Trust enforcement
and strengthen authentication policies.
"""
    )