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

# ---------------- MESSAGE CHECKER ----------------

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

# ---------------- SCAM LINK CHECKER ----------------

with link_tab:
    st.subheader("Scam Link Checker")
    st.write(
        "Check a URL for common warning signs. "
        "PrayShield does not visit the website or check live threat databases."
    )

    url_text = st.text_input(
        "Paste a suspicious link:",
        placeholder="https://example.com",
        key="url_input",
    )

    if st.button("Check Link", key="check_link"):
        candidate = url_text.strip()
        issues = []

        if not candidate:
            st.warning("Please enter a link first.")

        elif any(char.isspace() for char in candidate):
            st.warning(
                "This address contains spaces. Check that you copied the full URL correctly."
            )

        else:
            normalized = (
                candidate
                if "://" in candidate
                else "https://" + candidate
            )

            parsed = urlparse(normalized)
            hostname = parsed.hostname or ""
            scheme = parsed.scheme.lower()

            # Check URL format
            if scheme not in ("http", "https"):
                issues.append(
                    "The address uses an unexpected protocol."
                )

            if not hostname or "." not in hostname:
                issues.append(
                    "The address does not look like a complete domain name."
                )

            # Detect misleading user information before the host
            if parsed.username is not None or parsed.password is not None:
                issues.append(
                    "The URL contains user-information before the host, "
                    "which can disguise the actual destination."
                )

            # Detect IP address hosts
            if hostname and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
                issues.append(
                    "The host looks like an IP address instead of a domain name."
                )

            # Detect internationalized domain labels
            if any(
                label.lower().startswith("xn--")
                for label in hostname.split(".")
            ):
                issues.append(
                    "The domain contains an encoded internationalized label. "
                    "Check carefully for lookalike characters."
                )

            # Detect common URL-shortening services
            shorteners = {
                "bit.ly",
                "tinyurl.com",
                "t.co",
                "is.gd",
                "cutt.ly",
                "rb.gy",
                "shorturl.at",
            }

            if hostname.lower() in shorteners:
                issues.append(
                    "This is a URL-shortening service. The final destination "
                    "is not obvious from the shortened address."
                )

            # Detect common deceptive URL patterns
            if "@" in parsed.netloc:
                issues.append(
                    "The address contains an @ symbol in its host section. "
                    "Inspect the actual destination carefully."
                )

            if hostname.count(".") >= 4:
                issues.append(
                    "The domain has several subdomain levels. "
                    "Check which organization actually owns it."
                )

            if len(candidate) > 200:
                issues.append(
                    "The URL is unusually long and may be harder to inspect."
                )

            if scheme == "http":
                issues.append(
                    "This link uses HTTP rather than HTTPS, so the connection "
                    "does not provide HTTPS encryption."
                )

            # Check suspicious terms in the hostname only.
            suspicious_terms = (
                "verify",
                "login",
                "secure",
                "account",
                "wallet",
                "password",
                "update",
                "confirm",
            )

            hostname_parts = hostname.lower().replace("-", ".").split(".")
            matched_terms = [
                term
                for term in suspicious_terms
                if any(term in part for part in hostname_parts)
            ]

            if matched_terms:
                issues.append(
                    "The domain contains terms often used in account-related "
                    "links. These words alone do not prove a scam."
                )

            st.subheader("URL Inspection Results")
            st.write(
                f"**Detected domain:** {hostname or 'Could not identify'}"
            )

            if issues:
                st.warning(
                    "Potential warning signs found. This does not prove "
                    "the link is malicious."
                )

                for issue in issues:
                    st.write(f"- {issue}")
            else:
                st.success(
                    "No obvious warning signs were detected by these basic checks."
                )
                st.caption(
                    "This does not mean the link is safe."
                )

            st.markdown("**Safety advice**")
            st.write(
                "For important accounts, use the official app or type the "
                "known website address yourself. Do not enter passwords, "
                "payment details, or OTPs on an untrusted page."
            )

            st.caption(
                "PrayShield inspected the URL text only. It did not visit "
                "the website, verify its ownership, or check live threat databases."
            )

st.divider()
st.caption(
    "PrayShield is an early prototype. AI and URL checks can make mistakes; "
    "verify important requests through official channels."
)
