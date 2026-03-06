import streamlit as st
import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
import math

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(page_title="Zero Trust Model Demonstration", layout="wide")
st.title("Dynamic Fuzzy Logic Zero Trust Access Control Model")
st.markdown("Interactive demonstration of context-aware continuous authentication.")

# --- 2. THE FUZZY ENGINE (Cached for performance) ---
@st.cache_resource
def build_fuzzy_engine():
    norm_fail = ctrl.Antecedent(np.arange(0, 1.05, 0.05), 'norm_fail')
    norm_succ = ctrl.Antecedent(np.arange(0, 1.05, 0.05), 'norm_succ')
    trust = ctrl.Consequent(np.arange(0, 101, 1), 'trust')

    norm_fail['low'] = fuzz.trimf(norm_fail.universe, [0, 0, 0.4])
    norm_fail['med'] = fuzz.trimf(norm_fail.universe, [0.2, 0.5, 0.8])
    norm_fail['high'] = fuzz.trapmf(norm_fail.universe, [0.6, 0.8, 1, 1])

    norm_succ['low'] = fuzz.trimf(norm_succ.universe, [0, 0, 0.4])
    norm_succ['med'] = fuzz.trimf(norm_succ.universe, [0.2, 0.5, 0.8])
    norm_succ['high'] = fuzz.trapmf(norm_succ.universe, [0.6, 0.8, 1, 1])

    trust['low'] = fuzz.trimf(trust.universe, [0, 0, 40])
    trust['med'] = fuzz.trimf(trust.universe, [30, 50, 70])
    trust['high'] = fuzz.trimf(trust.universe, [60, 100, 100])

    rule1 = ctrl.Rule(norm_fail['high'], trust['low'])
    rule2 = ctrl.Rule(norm_fail['med'] & norm_succ['low'], trust['low'])
    rule3 = ctrl.Rule(norm_fail['med'] & norm_succ['high'], trust['med'])
    rule4 = ctrl.Rule(norm_fail['low'] & norm_succ['high'], trust['high'])
    rule5 = ctrl.Rule(norm_fail['low'] & norm_succ['low'], trust['med'])
    rule6 = ctrl.Rule(norm_fail['med'] & norm_succ['med'], trust['med'])
    rule7 = ctrl.Rule(norm_fail['low'] & norm_succ['med'], trust['high'])

    trust_ctrl = ctrl.ControlSystem([rule1, rule2, rule3, rule4, rule5, rule6, rule7])
    return ctrl.ControlSystemSimulation(trust_ctrl)

trust_engine = build_fuzzy_engine()

# --- 3. HELPER MATH FUNCTIONS ---
def get_action(score):
    if score >= 85: return " Seamless Access (Single Sign-On Granted)", "success"
    if score >= 60: return " Standard Multi-Factor Authentication (Require One-Time Password)", "info"
    if score >= 30: return " Step-Up Authentication (Require Biometric Verification)", "warning"
    if score >= 10: return " Quarantine (System Administrator Approval Required)", "error"
    return "🛑 Strict Block (User Account Locked)", "error"

# --- 4. STREAMLIT USER INTERFACE (SIDEBAR FORM) ---
st.sidebar.header("Configuration Parameters")

# Wrap the inputs in a form so it doesn't auto-calculate until the button is pressed
with st.sidebar.form(key='authentication_form'):
    network_risk = st.selectbox(
        "Network Environment Context (Risk Assessment Level)", 
        (
            "Low Risk (Secured Corporate Network)", 
            "Normal Risk (Standard Residential Network)", 
            "High Risk (Unverified or Foreign Internet Protocol Address)"
        )
    )

    failures = st.number_input("Recent Unsuccessful Authentication Attempts", min_value=0, value=0)
    raw_successes = st.number_input("Historical Successful Authentication Events", min_value=0, value=150)
    days_idle = st.number_input("Number of Days Since Last Active Session", min_value=0, value=1)
    
    # The Compute Button
    submit_button = st.form_submit_button(label="Compute Access Policy")

# --- 5. EXECUTE THE MODEL ---
# The code below will execute using the default values on first load, 
# and then re-execute with new values only when the button is clicked.

risk_map = {
    "Low Risk (Secured Corporate Network)": "low_risk", 
    "Normal Risk (Standard Residential Network)": "normal", 
    "High Risk (Unverified or Foreign Internet Protocol Address)": "high_risk"
}
current_risk = risk_map[network_risk]

# Step A: Time Decay
effective_succ = raw_successes * math.exp(-0.02 * days_idle)

# Step B: Dynamic k & Normalization
k_base = 3.0
if current_risk == 'low_risk': dynamic_k = k_base * 1.66
elif current_risk == 'high_risk': dynamic_k = k_base * 0.33
else: dynamic_k = k_base

f_val = failures / (failures + dynamic_k) if (failures + dynamic_k) > 0 else 0
s_val = effective_succ / (effective_succ + 50.0) if (effective_succ + 50.0) > 0 else 0

# Step C: Compute Trust
trust_engine.input['norm_fail'] = f_val
trust_engine.input['norm_succ'] = s_val

try:
    trust_engine.compute()
    final_score = round(trust_engine.output['trust'], 2)
except:
    final_score = 0.0

action_text, alert_type = get_action(final_score)

# --- 6. DISPLAY RESULTS (MAIN PAGE) ---
st.subheader("Real-Time System Evaluation Metrics")
col1, col2, col3 = st.columns(3)

col1.metric(label="Normalized Failure Rate", value=f"{f_val:.2f}", delta=f"Dynamic Sensitivity Tolerance (k) = {dynamic_k:.1f}", delta_color="inverse")
col2.metric(label="Effective Historical Trust (Post-Temporal Decay)", value=f"{effective_succ:.0f} events", delta=f"Reduction due to temporal decay: {raw_successes - effective_succ:.0f}")
col3.metric(label="Final Computed Trust Percentage", value=f"{final_score}%")

st.markdown("---")
st.subheader("Automated Policy Enforcement Action")

if alert_type == "success": st.success(action_text)
elif alert_type == "info": st.info(action_text)
elif alert_type == "warning": st.warning(action_text)
else: st.error(action_text)


st.progress(int(final_score))
