import re
from urllib.parse import urlparse

import requests
import streamlit as st

st.set_page_config(
    page_title="PrayShield",
    page_icon="🛡️",
    layout="centered",
)

API_URL = "https://praynova-ai-backend.prayretha.workers.dev"

st.title("🛡️ PrayShield")
st.write("Your AI-powered digital safety assistant.")
st.caption("Early prototype | Under development")

message_tab, link_tab = st.tabs(
    ["💬 Message Checker", "🔗 Scam Link Checker"]
)

with message_tab:
    st.subheader("AI Suspicious Message Checker")
    st.write("Check a message for potential scam warning signs.")

    message = st.text_area(
        "Paste a message to check:",
        placeholder="Example: Your bank account will be blocked. Verify now...",
        max_chars=5000,
        key="message_input",
    )

    if st.button("Analyze Message", key="analyze_message"):
        if not message.strip():
            st.warning("Please enter a message first.")
        else:
            with st.spinner("PrayShield AI is analyzing the message..."):
                try:
                    response = requests.post(
                        API_URL,
                        json={"message": message},
                        timeout=60,
                    )

                    try:
                        data = response.json()
                    except ValueError:
                        data = {}

                    if response.ok and data.get("success"):
                        st.subheader("Analysis Results")
                        st.write(
                            data.get("analysis", "No analysis returned.")
                        )
                        st.info(
                            data.get(
                                "disclaimer",
                                "AI assessments can be wrong. Verify important requests through official channels.",
                            )
                        )
                    else:
                        st.error(
                            data.get(
                                "error",
                                f"The AI request failed (HTTP {response.status_code}).",
                            )
                        )

                except requests.exceptions.RequestException:
                    st.error(
                        "Could not connect to the AI service. Please try again."
                    )

with link_tab:
    st.subheader("Scam Link Checker")
    st.write(
        "Inspect a URL for common warning signs. "
        "This checks the URL text only; it does not visit the website."
    )

    url_text = st.text_input(
        "Paste a suspicious link:",
        placeholder="https://example.com",
        key="url_input",
    )

    if st.button("Check Link", key="check_link"):
        candidate = url_text.strip()

        if not candidate:
            st.warning("Please enter a link first.")
        else:
            normalized = (
                candidate
                if "://" in candidate
                else "https://" + candidate
            )

            parsed = urlparse(normalized)
            hostname = parsed.hostname or ""
            issues = []

            if parsed.scheme.lower() not in ("http", "https"):
                issues.append(
                    "The URL uses an unexpected protocol."
                )

            if not hostname or "." not in hostname:
                issues.append(
                    "The address does not look like a complete domain name."
                )

            if parsed.username or parsed.password:
                issues.append(
                    "The URL contains user-information before the host, "
                    "which can be used to disguise the destination."
                )

            if hostname and hostname.replace(".", "").isdigit():
                issues.append(
                    "The host looks like a numeric IP address rather than "
                    "a familiar domain name."
                )

            if hostname.startswith("xn--") or ".xn--" in hostname:
                issues.append(
                    "The domain contains an internationalized label that "
                    "may need careful inspection for lookalike characters."
                )

            if re.search(r"https?://", candidate.split("://", 1)[-1], re.I):
                issues.append(
                    "The address contains another URL scheme inside it; "
                    "check the destination carefully."
                )

            if len(candidate) > 200:
                issues.append(
                    "The URL is unusually long. Long URLs are not always "
                    "malicious, but can be harder to inspect."
                )

            if parsed.scheme.lower() == "http":
                issues.append(
                    "This link uses HTTP rather than HTTPS, so the connection "
                    "does not provide HTTPS encryption."
                )

            st.subheader("URL Inspection Results")
            st.write(f"**Detected domain:** {hostname or 'Could not identify'}")

            if issues:
                st.warning(
                    "Potential warning signs found. This does not prove "
                    "the link is malicious."
                )
                for issue in issues:
                    st.write(f"- {issue}")
            else:
                st.info(
                    "No obvious warning signs were detected by these basic "
                    "checks. This does not mean the link is safe."
                )

            st.markdown("**Safety advice**")
            st.write(
                "Do not enter passwords, payment details, or OTPs on an "
                "untrusted page. If the link claims to be from a bank or "
                "company, open its official app or type its known website "
                "address yourself."
            )

            st.caption(
                "PrayShield only inspected the text of this URL. "
                "It did not visit or verify the website."
            )

st.divider()
st.caption(
    "AI assessments can be wrong. Verify important requests through official channels."
)
