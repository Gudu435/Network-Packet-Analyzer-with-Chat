import streamlit as st
import os
from analyzer import analyze_pcap
from openai import AzureOpenAI
 
# ================================
# Config
# ================================
st.set_page_config(page_title="AI Packet Analyzer", layout="wide")
 
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
 
MAX_SIZE_MB = 150
 
# ================================
# Azure OpenAI
# ================================
client = AzureOpenAI(
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version=os.getenv("AZURE_OPENAI_API_VERSION"),
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
)
 
# ================================
# Session State
# ================================
if "result" not in st.session_state:
    st.session_state.result = None
 
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []
 
# ================================
# Header
# ================================
st.title("🚀 AI Packet Analyzer")
st.caption("Network Intelligence Tool")
st.markdown("---")
 
# ================================
# Upload
# ================================
uploaded_file = st.file_uploader(
    "",
    type=["pcap", "pcapng"]
)
 
file_path = None
 
if uploaded_file:
    size_mb = uploaded_file.size / (1024 * 1024)
 
    if size_mb > MAX_SIZE_MB:
        st.error("❌ File too large! Max allowed is 150MB")
        st.stop()
 
    file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
 
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
 
    st.success(f"✅ Uploaded: {uploaded_file.name} ({round(size_mb,2)} MB)")
 
# ================================
# Buttons
# ================================
col1, col2 = st.columns(2)
 
with col1:
    analyze_clicked = st.button("🔍 Analyze")
 
with col2:
    reset_clicked = st.button("🔄 Reset")
 
# ================================
# Actions
# ================================
if analyze_clicked and file_path:
    with st.spinner("Analyzing PCAP..."):
        result = analyze_pcap(file_path)
 
    st.session_state.result = result
 
# Soft reset (better UX)
if reset_clicked:
    st.session_state.result = None
    st.session_state.chat_history = []
    st.rerun()
 
# ================================
# Show Result
# ================================
if st.session_state.result:
 
    result = st.session_state.result
 
    st.markdown("---")
 
    if result["status"] == "success":
 
        analysis_text = result["analysis"]
 
        # Clean unwanted headings
        for word in [
            "Analysis Result",
            "Structured Analysis Output",
        ]:
            analysis_text = analysis_text.replace(word, "")
 
        st.markdown(analysis_text)
 
    else:
        st.error(result["analysis"])
 
# ================================
# Footer
# ================================
st.markdown("---")
 
st.caption("Built with ❤️ for Network Analysis | Streamlit + Scapy + Azure OpenAI")
 
st.markdown(
    '<p style="color:#FFD700;">⚠️ Supports PCAP files up to 150MB</p>',
    unsafe_allow_html=True
)

# ================================
# 💬 Chat Section
# ================================
if st.session_state.result and st.session_state.result["status"] == "success":
 
    st.markdown("---")
    st.subheader("💬 Ask Questions about this PCAP")
 
    analysis_text = st.session_state.result["analysis"]
 
    # ✅ Show history FIRST (correct order)
    for role, msg in st.session_state.chat_history:
        with st.chat_message(role):
            st.markdown(msg)
 
    # ✅ Input at bottom
    user_question = st.chat_input("Ask anything about this PCAP...")
 
    if user_question:
 
        # Store user message
        st.session_state.chat_history.append(("user", user_question))
 
        prompt = f"""
You are a senior network engineer.
 
Use ONLY the provided PCAP analysis.
 
PCAP ANALYSIS:
{analysis_text}
 
QUESTION:
{user_question}
 
Answer clearly and technically.
"""
 
        # Assistant response with spinner
        with st.chat_message("assistant"):
            placeholder = st.empty()
 
            with st.spinner("🤖 Thinking... analyzing your question..."):
                try:
                    response = client.chat.completions.create(
                        model=os.getenv("AZURE_OPENAI_DEPLOYMENT"),
                        messages=[
                            {"role": "system", "content": "You are a network expert."},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.2
                    )
 
                    answer = response.choices[0].message.content
 
                except Exception as e:
                    answer = f"❌ Error: {str(e)}"
 
            placeholder.markdown(answer)
 
        # Store assistant response
        st.session_state.chat_history.append(("assistant", answer))
 
        # 🔥 Refresh UI so latest goes to bottom
        st.rerun()
 

 
