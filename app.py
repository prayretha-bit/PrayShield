import re
from urllib.parse import urlparse

import requests
import streamlit as st


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="PrayShield",
    page_icon="🛡️",
    layout="centered",
)

API_URL = "https://praynova-ai-backend.prayretha.workers.dev"


# --------------------------------------------------
# HEADER
# --------------------------------------------------

st.title("🛡️ PrayShield")
st.subheader("Safer Today. Stronger Tomorrow.")

st.write(
    "PrayShield helps you identify possible scam messages "
    "and suspicious website links."
)

st.info(
    "Privacy reminder: Do not enter passwords, PINs, OTPs, "
    "bank details, or other sensitive personal information."
)


# --------------------------------------------------
# TABS
# --------------------------------------------------

message_tab, link_tab = st.tabs(
    ["📩 AI Message Checker", "🔗 Scam Link Checker"]
)


# --------------------------------------------------
# TAB 1: AI MESSAGE CHECKER
# --------------------------------------------------

with message_tab:

    st.header("AI Message Checker")

    st.write(
        "Check a suspicious SMS, email, WhatsApp message, "
        "or other text for possible scam warning signs."
    )

    message = st.text_area(
        "Paste the message here:",
        height=180,
        max_chars=5000,
        placeholder="Paste the message you want to check...",
    )

    if st.button("🔍 Check Message", key="check_message"):

        if not message.strip():
            st.warning("Please enter a message first.")

        else:
            with st.spinner("PrayShield AI is analyzing the message..."):

                try:
                    # Read the API key from Streamlit Secrets
                    api_key = st.secrets["PRAYSHIELD_API_KEY"]

                    # Send the message securely to the Worker
                    response = requests.post(
                        API_URL,
                        json={"message": message},
                        headers={
                            "Authorization": f"Bearer {api_key}"
                        },
                        timeout=60,
                    )

                    if response.status_code == 401:
                        st.error(
                            "Authentication failed. Please check "
                            "the API key configuration."
                        )

                    elif response.status_code != 200:
                        st.error(
                            f"AI service error: HTTP "
                            f"{response.status_code}. Please try again later."
                        )

                    else:
                        result = response.json()

                        if result.get("success") and result.get("analysis"):
                            st.subheader("PrayShield Analysis")
                            st.write(result["analysis"])

                            st.caption(
                                result.get(
                                    "disclaimer",
                                    "AI assessments can be wrong. "
                                    "Verify important requests through "
                                    "official channels.",
                                )
                            )

                        else:
                            st.error(
                                result.get(
                                    "error",
                                    "The analysis could not be completed.",
                                )
                            )

                except KeyError:
                    st.error(
                        "API key is missing. Please check "
                        "Streamlit Secrets."
                    )

                except requests.exceptions.Timeout:
                    st.error(
                        "The AI service took too long to respond. "
                        "Please try again."
                    )

                except requests.exceptions.RequestException:
                    st.error(
                        "Unable to connect to the AI service. "
                        "Please try again later."
                    )

                except ValueError:
                    st.error(
                        "The AI service returned an invalid response."
                    )

                except Exception:
                    st.error(
                        "Something went wrong. Please try again later."
                    )


# --------------------------------------------------
# TAB 2: SCAM LINK CHECKER
# --------------------------------------------------

with link_tab:

    st.header("Scam Link Checker")

    st.write(
        "Check a website address for common suspicious URL patterns."
    )

    url_input = st.text_input(
        "Enter website link:",
        placeholder="https://example.com",
    )

    if st.button("🔍 Check Link", key="check_link"):

        if not url_input.strip():
            st.warning("Please enter a website link.")

        else:
            url = url_input.strip()

            if not re.match(r"^https?://", url, re.IGNORECASE):
                url = "https://" + url

            try:
                parsed_url = urlparse(url)
                hostname = parsed_url.hostname

                if not hostname or "." not in hostname:
                    st.error("This does not look like a complete website address.")

                else:
                    warnings = []

                    if parsed_url.scheme.lower() != "https":
                        warnings.append(
                            "The link does not use HTTPS encryption."
                        )

                    if "@" in parsed_url.netloc:
                        warnings.append(
                            "The link contains an @ symbol, "
                            "which can hide the actual destination."
                        )

                    if parsed_url.username or parsed_url.password:
                        warnings.append(
                            "The address contains user information "
                            "before the hostname."
                        )

                    if re.fullmatch(
                        r"\d{1,3}(?:\.\d{1,3}){3}",
                        hostname,
                    ):
                        warnings.append(
                            "The website uses an IP address instead "
                            "of a normal domain name."
                        )

                    if hostname.startswith("xn--") or ".xn--" in hostname:
                        warnings.append(
                            "The domain contains punycode, which can "
                            "sometimes be used to imitate other domains."
                        )

                    shorteners = [
                        "bit.ly",
                        "tinyurl.com",
                        "t.co",
                        "goo.gl",
                        "is.gd",
                        "cutt.ly",
                        "rb.gy",
                    ]

                    if hostname.lower() in shorteners:
                        warnings.append(
                            "This is a URL-shortening service. "
                            "The final destination is not visible here."
                        )

                    if len(url) > 150:
                        warnings.append(
                            "The URL is unusually long."
                        )

                    if hostname.count(".") >= 4:
                        warnings.append(
                            "The website has several subdomains. "
                            "Check the actual registered domain carefully."
                        )

                    suspicious_words = [
                        "verify",
                        "account",
                        "login",
                        "secure",
                        "update",
                        "banking",
                        "payment",
                        "wallet",
                        "password",
                    ]

                    if any(
                        word in hostname.lower()
                        for word in suspicious_words
                    ):
                        warnings.append(
                            "The domain contains words commonly used "
                            "in account or payment-related links. "
                            "This alone does not prove it is fraudulent."
                        )

                    st.subheader("Link Analysis")

                    st.write(f"**Website:** {hostname}")

                    if warnings:
                        st.warning(
                            "Caution: This link has some patterns "
                            "that deserve attention."
                        )

                        for warning in warnings:
                            st.write(f"⚠️ {warning}")

                    else:
                        st.success(
                            "No obvious suspicious URL patterns were found."
                        )

                    st.info(
                        "This checker uses basic URL pattern analysis. "
                        "It does not visit the website or check a live "
                        "malware or phishing database. A clean result "
                        "does not guarantee that a website is safe."
                    )

            except ValueError:
                st.error(
                    "Unable to analyze this address. "
                    "Please enter a valid website link."
                )


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "PrayShield | Safer Today. Stronger Tomorrow."
)

st.caption(
    "PrayShield is an early-stage digital safety product. "
    "Its AI and URL checks may make mistakes and should not "
    "replace independent verification or security software."
)
