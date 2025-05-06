# streamlit_app.py
import streamlit as st # type: ignore
import requests
import matplotlib.pyplot as plt
import pandas as pd
from PIL import Image

def analyze(url):
    try:
        response = requests.post("http://localhost:5000/predict", 
                               json={"url": url},
                               timeout=10)  # Increased timeout for large blocklists
        return response.json() if response.status_code == 200 else None
    except Exception as e:
        st.error(f"Connection error: {e}")
        return None

# Threat type explanations
THREAT_EXPLANATIONS = {
    "benign": {
        "icon": "✅",
        "title": "Benign Website",
        "description": "This website appears safe with no detected malicious activity.",
        "color": "green"
    },
    "phishing": {
        "icon": "🎣",
        "title": "Phishing Threat",
        "description": "This website may be attempting to steal sensitive information by disguising as a trustworthy entity.",
        "color": "red"
    },
    "malware": {
        "icon": "🦠",
        "title": "Malware Threat",
        "description": "This website may distribute malicious software designed to harm your device or steal data.",
        "color": "darkred"
    },
    "defacement": {
        "icon": "💥",
        "title": "Defacement Threat",
        "description": "This website may have been hacked and modified to display unauthorized content.",
        "color": "orange"
    }
}

# UI Setup
st.set_page_config(layout="wide", page_title="URL Threat Analyzer")
st.title("🛡️ Enterprise URL Threat Analyzer")

# Main content area
col1, col2 = st.columns([3, 2])
url = col1.text_input("Enter URL to analyze:", "https://example.com")

if col1.button("🔍 Analyze Now", type="primary"):
    if not url:
        st.warning("Please enter a URL to analyze")
        st.stop()
    
    if not url.startswith(('http://', 'https://')):
        url = f'http://{url}'
    
    with st.spinner("🔍 Scanning URL with our threat intelligence systems..."):
        result = analyze(url)
        
        if result:
            st.divider()
            
            # Initialize threat_data from the result
            threat_data = result["threat_breakdown"]
            
            # Blocked Domain Case
            if result.get("source") == "blocklist":
                st.error(f"🚨 **CONFIRMED MALICIOUS DOMAIN** (Blocklist match: {result.get('domain')})", icon="⚠️")
                
                # Visual Alert
                cols = st.columns([2, 1])
                with cols[0]:
                    fig, ax = plt.subplots(figsize=(10, 4))
                    ax.bar(threat_data.keys(), threat_data.values(),
                          color=[THREAT_EXPLANATIONS[t]['color'] for t in threat_data.keys()])
                    ax.set_ylim(0, 1)
                    ax.set_title("Threat Breakdown (Verified Threat Database)")
                    st.pyplot(fig)
                
                with cols[1]:
                    st.metric("PHISHING SCORE", "95%", delta="Confirmed Threat", delta_color="off")
                    st.warning("""
                    ⚠️ This domain is in our global threat database. 
                    Accessing this site may compromise your security.
                    """)
                    
                    st.error("""
                    **Recommended Action**:  
                    - Do not visit this website  
                    - Do not enter any credentials  
                    - Report this URL to your security team
                    """)
            
            # AI Analysis Case
            else:
                primary_threat = max(threat_data.items(), key=lambda x: x[1])
                
                if result.get("is_malicious"):
                    threat_info = THREAT_EXPLANATIONS[primary_threat[0]]
                    st.error(f"{threat_info['icon']} **{threat_info['title'].upper()} DETECTED** (Confidence: {primary_threat[1]*100:.1f}%)", icon="⚠️")
                else:
                    st.success(f"✅ **SAFE WEBSITE** (Confidence: {threat_data['benign']*100:.1f}%)", icon="✔️")
                
                # Visualization and details in tabs
                tab1, tab2, tab3 = st.tabs(["Threat Analysis", "Threat Details", "Recommendations"])
                
                with tab1:
                    # Threat gauge visualization
                    fig, ax = plt.subplots(figsize=(10, 3))
                    bars = ax.barh(list(threat_data.keys()), list(threat_data.values()),
                                 color=[THREAT_EXPLANATIONS[t]['color'] for t in threat_data.keys()])
                    ax.set_xlim(0, 1)
                    ax.set_title("Threat Probability Distribution")
                    
                    # Add value labels
                    for bar in bars:
                        width = bar.get_width()
                        ax.text(width + 0.02, bar.get_y() + bar.get_height()/2,
                               f'{width*100:.1f}%',
                               ha='left', va='center')
                    
                    st.pyplot(fig)
                    
                    # Detailed Table
                    st.subheader("Technical Breakdown")
                    df = pd.DataFrame({
                        "Threat Type": list(threat_data.keys()),
                        "Score": [f"{v*100:.2f}%" for v in threat_data.values()],
                        "Risk Level": ["CRITICAL" if v > 0.9 else "High" if v > 0.7 else "Medium" if v > 0.4 else "Low" 
                                     for v in threat_data.values()]
                    })
                    
                    # Apply color to Threat Type column
                    def color_threat_type(val):
                        if val in THREAT_EXPLANATIONS:
                            color = THREAT_EXPLANATIONS[val]['color']
                            return f'color: {color}'
                        return ''
                    
                    styled_df = df.style.applymap(color_threat_type, subset=['Threat Type'])
                    st.dataframe(styled_df, hide_index=True)
                
                with tab2:
                    st.subheader("Threat Type Explanations")
                    
                    for threat, values in THREAT_EXPLANATIONS.items():
                        with st.expander(f"{values['icon']} {values['title']}"):
                            st.markdown(f"""
                            **Description**: {values['description']}  
                            **Current Score**: {threat_data[threat]*100:.1f}%  
                            **Risk Level**: {"CRITICAL" if threat_data[threat] > 0.9 else "High" if threat_data[threat] > 0.7 else "Medium" if threat_data[threat] > 0.4 else "Low"}
                            """)
                            
                            if threat == "phishing":
                                st.info("ℹ️ Phishing sites often mimic login pages of popular services like banks or email providers.")
                            elif threat == "malware":
                                st.info("ℹ️ Malware can be silently downloaded just by visiting a compromised website.")
                            elif threat == "defacement":
                                st.info("ℹ️ Defaced websites may contain inappropriate content or false information.")
                
                with tab3:
                    if result.get("is_malicious"):
                        st.error("""
                        **Security Recommendations**:  
                        - Do not visit this website  
                        - Do not download any files  
                        - Do not enter personal information  
                        - Consider reporting this URL to your security team  
                        - Run antivirus scan if you recently visited this site
                        """)
                    else:
                        st.success("""
                        **This website appears safe, but always practice good security habits**:  
                        - Verify the website's SSL certificate (🔒 in address bar)  
                        - Be cautious with login forms on unfamiliar sites  
                        - Keep your browser and security software updated
                        """)
                    
                    st.info("""
                    **General Security Tips**:  
                    - Use a password manager to avoid credential theft  
                    - Enable two-factor authentication where possible  
                    - Regularly check for software updates  
                    - Be wary of too-good-to-be-true offers
                    """)
                
                # Additional info for AI results
                if result.get("source") == "ai_model":
                    st.caption(f"Analysis source: AI Model | Primary threat: {primary_threat[0].title()} ({primary_threat[1]*100:.1f}%)")
        else:
            st.error("❌ Analysis failed. Please try again or check your connection.")

# Sidebar with additional info
with st.sidebar:
    st.markdown("""
    ## 🔒 About This System
    **Enterprise URL Threat Analyzer** combines multiple security approaches:
    
    - **Blocklist Database**: Real-time checks against known malicious domains (8 threat databases)
    - **AI Analysis**: Deep learning model trained to detect emerging threats
    - **Behavioral Analysis**: Identifies suspicious patterns in URLs
    
    **Detection Modes**:
    - **Blocklist Match**: Immediate 95%+ phishing score for known threats
    - **AI Analysis**: Detailed threat assessment for unknown URLs
    """)
    
    for threat, info in THREAT_EXPLANATIONS.items():
        st.markdown(f"""
        {info['icon']} **{info['title']}**  
        {info['description']}
        """)
    
    st.markdown("""
    **How to Use**:
    1. Enter any URL (with or without http://)
    2. Click "Analyze Now"
    3. Review detailed threat breakdown
    4. Follow security recommendations
    
    *Note: The system checks against {len(BLOCKED_DOMAINS)} known malicious domains*
    """)