"""PII Redaction Pipeline for Logging and Memory Storage.

Implements active scrubbing mechanisms to redact sensitive data (emails, phone numbers,
SSNs, credit card numbers, IPv4 addresses, and API keys/tokens) before storage in logs,
session state, or Vertex AI Memory Bank, leveraging Google Cloud DLP API with a
deterministic regex fallback.
"""

from __future__ import annotations

import re
from typing import Any

try:
    from google.cloud import dlp_v2
except ImportError:  # pragma: no cover - fallback when google-cloud-dlp is not installed
    dlp_v2 = None  # type: ignore[assignment]


class PIIRedactionScrubber:
    """Active PII scrubber using Google Cloud DLP API and deterministic regex rules.

    Ensures zero sensitive Personal Identifiable Information (PII) or credentials
    are persisted in structured JSON logs, session databases, or long-term memory.
    """

    DEFAULT_INFO_TYPES: list[str] = [
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "US_SOCIAL_SECURITY_NUMBER",
        "CREDIT_CARD_NUMBER",
        "IP_ADDRESS",
        "GCP_API_KEY",
        "AUTH_TOKEN",
    ]

    _REGEX_RULES: list[tuple[re.Pattern[str], str]] = [
        # US Social Security Numbers (SSN)
        (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
        # Credit card numbers (13 to 16 digits with optional spaces or dashes)
        (
            re.compile(r"\b(?:\d{4}[-\s]?){3}\d{1,4}\b"),
            "[REDACTED_CREDIT_CARD]",
        ),
        # Email addresses
        (
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            "[REDACTED_EMAIL]",
        ),
        # North American & international phone numbers
        (
            re.compile(
                r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}(?!\d)"
            ),
            "[REDACTED_PHONE]",
        ),
        # Bearer tokens, OAuth tokens, and API keys
        (
            re.compile(
                r"\b(?:AIza[0-9A-Za-z_-]{35}|ya29\.[0-9A-Za-z_-]+|sk-[0-9A-Za-z]{20,}|Bearer\s+[A-Za-z0-9._~+/=-]+)\b"
            ),
            "[REDACTED_CREDENTIAL]",
        ),
        # IPv4 addresses
        (
            re.compile(
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
            ),
            "[REDACTED_IP_ADDRESS]",
        ),
    ]

    def __init__(
        self,
        project_id: str | None = None,
        enable_cloud_dlp: bool = False,
    ) -> None:
        """Initializes the PII Redaction Scrubber.

        Args:
            project_id: Google Cloud project ID for Cloud DLP API requests.
            enable_cloud_dlp: Whether to invoke the live Google Cloud DLP API
                prior to applying deterministic regex scrubbing.
        """
        self.project_id = project_id
        self.enable_cloud_dlp = enable_cloud_dlp and (dlp_v2 is not None) and bool(project_id)
        self._dlp_client: Any = None
        if self.enable_cloud_dlp and dlp_v2 is not None:
            try:
                self._dlp_client = dlp_v2.DlpServiceClient()
            except Exception:
                self._dlp_client = None

    def _scrub_with_cloud_dlp(self, text: str) -> str:
        """Calls Google Cloud DLP `deidentify_content` to mask detected InfoTypes."""
        if not self._dlp_client or not self.project_id or not text.strip():
            return text
        try:
            parent = f"projects/{self.project_id}/locations/global"
            inspect_config = {
                "info_types": [{"name": info_type} for info_type in self.DEFAULT_INFO_TYPES],
                "min_likelihood": "POSSIBLE",
            }
            deidentify_config = {
                "info_type_transformations": {
                    "transformations": [
                        {
                            "primitive_transformation": {
                                "replace_with_info_type_config": {}
                            }
                        }
                    ]
                }
            }
            response = self._dlp_client.deidentify_content(
                request={
                    "parent": parent,
                    "inspect_config": inspect_config,
                    "deidentify_config": deidentify_config,
                    "item": {"value": text},
                }
            )
            return str(response.item.value)
        except Exception:
            # Always fall through to deterministic local regex scrubbing on RPC errors
            return text

    def scrub_text(self, text: str) -> str:
        """Scrubs sensitive PII and credentials from a string.

        Args:
            text: Raw input string potentially containing PII or secrets.

        Returns:
            Sanitized string with all detected PII replaced by redaction tokens.
        """
        if not isinstance(text, str) or not text:
            return text

        sanitized = self._scrub_with_cloud_dlp(text) if self.enable_cloud_dlp else text
        for pattern, replacement in self._REGEX_RULES:
            sanitized = pattern.sub(replacement, sanitized)
        return sanitized

    def scrub_payload(self, payload: Any) -> Any:
        """Recursively scrubs PII from dictionaries, lists, and nested structures.

        Args:
            payload: Arbitrary JSON-like structure (dict, list, str, int, etc.).

        Returns:
            Deep-sanitized copy of the payload safe for logging or memory persistence.
        """
        if isinstance(payload, str):
            return self.scrub_text(payload)
        if isinstance(payload, dict):
            sanitized_dict: dict[str, Any] = {}
            for key, value in payload.items():
                lower_key = str(key).lower()
                if any(
                    sensitive in lower_key
                    for sensitive in ("password", "secret", "api_key", "token", "ssn", "authorization")
                ) and not lower_key.endswith("_token_verified"):
                    sanitized_dict[key] = "[REDACTED_SENSITIVE_FIELD]"
                else:
                    sanitized_dict[key] = self.scrub_payload(value)
            return sanitized_dict
        if isinstance(payload, list):
            return [self.scrub_payload(item) for item in payload]
        if isinstance(payload, tuple):
            return tuple(self.scrub_payload(item) for item in payload)
        return payload


default_pii_scrubber = PIIRedactionScrubber()
