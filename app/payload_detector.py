from urllib.parse import urlparse


def detect_payload(content: str) -> str:
    """
    Detect whether the QR payload is a URL,
    UPI payment link or plain text.
    """

    if not content:
        return "TEXT"

    content = content.strip()

    lower = content.lower()

    if (
        lower.startswith("http://")
        or lower.startswith("https://")
        or lower.startswith("www.")
    ):
        return "URL"

    if lower.startswith("upi://"):
        return "UPI"

    return "TEXT"