from urllib.parse import urlparse
import re


def analyze_url(url):

    result = {
        "score": 0,
        "reasons": []
    }

    # --------------------------------
    # Basic URL cleaning
    # --------------------------------

    url = url.strip()

    if not url:
        result["score"] = 100
        result["risk"] = "High Risk"
        result["reasons"].append("URL is empty or invalid.")
        return result

    # --------------------------------
    # Parse URL
    # --------------------------------

    parsed_url = urlparse(url)

    domain = parsed_url.hostname or ""
    port = parsed_url.port

    # --------------------------------
    # Rule 1: HTTPS
    # --------------------------------

    if parsed_url.scheme.lower() == "https":
        result["reasons"].append("HTTPS is used.")
    else:
        result["score"] += 10
        result["reasons"].append("HTTPS is not used.")

    # --------------------------------
    # Rule 2: URL Length
    # --------------------------------

    if len(url) > 100:
        result["score"] += 15
        result["reasons"].append("URL is unusually long.")
    else:
        result["reasons"].append("URL length is normal.")

    # --------------------------------
    # Rule 3: @ Symbol
    # --------------------------------

    if "@" in url:
        result["score"] += 20
        result["reasons"].append(
            "URL contains an @ symbol."
        )

    # --------------------------------
    # Rule 4: IP Address
    # --------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, domain):
        result["score"] += 25
        result["reasons"].append(
            "URL uses an IP address instead of a domain name."
        )
    else:
        result["reasons"].append(
            "URL uses a domain name."
        )

    # --------------------------------
    # Rule 5: Suspicious Keywords
    # --------------------------------

    suspicious_keywords = [
        "login",
        "verify",
        "verification",
        "account",
        "update",
        "password",
        "secure",
        "signin",
        "confirm",
        "bank",
        "wallet",
        "payment"
    ]

    found_keywords = []

    lower_url = url.lower()

    for keyword in suspicious_keywords:

        if keyword in lower_url:
            found_keywords.append(keyword)

    if found_keywords:

        result["score"] += 10

        result["reasons"].append(
            "Suspicious keyword(s) found: "
            + ", ".join(found_keywords)
        )

    else:

        result["reasons"].append(
            "No suspicious keywords detected."
        )

    # --------------------------------
    # Rule 6: Too Many Subdomains
    # --------------------------------

    domain_parts = domain.split(".")

    if len(domain_parts) > 3:

        result["score"] += 15

        result["reasons"].append(
            "URL contains many subdomains."
        )

    else:

        result["reasons"].append(
            "Subdomain structure looks normal."
        )

    # --------------------------------
    # Rule 7: Suspicious Port
    # --------------------------------

    if port is not None:

        common_ports = [80, 443]

        if port not in common_ports:

            result["score"] += 10

            result["reasons"].append(
                f"URL uses a non-standard port: {port}."
            )

        else:

            result["reasons"].append(
                f"URL uses a common port: {port}."
            )

    else:

        result["reasons"].append(
            "No explicit port specified."
        )

    # --------------------------------
    # Rule 8: Punycode
    # --------------------------------

    if "xn--" in domain.lower():

        result["score"] += 15

        result["reasons"].append(
            "Domain contains Punycode, which may represent encoded characters."
        )

    else:

        result["reasons"].append(
            "No Punycode detected."
        )

    # --------------------------------
    # Rule 9: Encoded Characters
    # --------------------------------

    if "%" in url:

        result["score"] += 5

        result["reasons"].append(
            "URL contains encoded characters."
        )

    else:

        result["reasons"].append(
            "No encoded characters detected."
        )

    # --------------------------------
    # Rule 10: Suspicious Double Slash
    # --------------------------------

    path = parsed_url.path

    if "//" in path:

        result["score"] += 10

        result["reasons"].append(
            "URL path contains multiple consecutive slashes."
        )

    else:

        result["reasons"].append(
            "URL path structure looks normal."
        )

    # --------------------------------
    # Rule 11: Hyphen-heavy Domain
    # --------------------------------

    if domain.count("-") >= 3:

        result["score"] += 10

        result["reasons"].append(
            "Domain contains many hyphens."
        )

    else:

        result["reasons"].append(
            "Domain hyphen usage looks normal."
        )

    # --------------------------------
    # Keep score between 0 and 100
    # --------------------------------

    result["score"] = min(result["score"], 100)

    # --------------------------------
    # Final Risk Classification
    # --------------------------------

    if result["score"] >= 40:

        result["risk"] = "High Risk"

    elif result["score"] >= 20:

        result["risk"] = "Suspicious"

    else:

        result["risk"] = "Low Risk"

    return result