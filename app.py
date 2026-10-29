import streamlit as st
import requests

st.set_page_config(
    page_title="PrayShield",
    page_icon="🛡️",
    layout="centered"
)

API_URL = "https://praynova-ai-backend.prayretha.workers.dev"

st.title("🛡️ PrayShield")
st.subheader("AI Suspicious Message Checker")

st.write(
    "Check a message for potential scam warning signs "
    "using AI. PrayShield is an early prototype."
)

message = st.text_area(
    "Paste a message to check:",
    placeholder="Example: Your bank account will be blocked. Verify now...",
    max_chars=5000
)

if st.button("Analyze Message"):
    if not message.strip():
        st.warning("Please enter a message first.")
    else:
        with st.spinner("PrayShield AI is analyzing your message..."):
            try:
                response = requests.post(
                    API_URL,
                    json={"message": message},
                    timeout=60
                )

                try:
                    data = response.json()
                except ValueError:
                    data = {}

                if response.ok and data.get("success"):
                    st.subheader("Analysis Results")
                    st.write(data.get("analysis", "No analysis returned."))

                    st.info(
                        data.get(
                            "disclaimer",
                            "AI assessments can be wrong. Verify important requests through official channels."
                        )
                    )
                else:
                    st.error(
                        data.get(
                            "error",
                            f"The AI request failed (HTTP {response.status_code})."
                        )
                    )

            except requests.exceptions.RequestException:
                st.error(
                    "Could not connect to the PrayShield AI backend. "
                    "Please check the connection and try again."
                )

st.caption("PrayShield | Early prototype | Under development")
