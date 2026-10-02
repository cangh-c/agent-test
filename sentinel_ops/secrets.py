"""Secure Secret Management via Google Cloud Secret Manager.

Eliminates hardcoded API keys and secrets by retrieving credentials dynamically
at runtime from Google Cloud Secret Manager using Application Default Credentials (ADC)
and Workload Identity Federation.
"""

from __future__ import annotations

import functools
import os
from typing import Any

try:
    from google.cloud import secretmanager
except ImportError:  # pragma: no cover - fallback when google-cloud-secret-manager is not installed
    secretmanager = None  # type: ignore[assignment]


class SecretResolutionError(RuntimeError):
    """Raised when a required secret cannot be retrieved from Secret Manager."""


class SecretManagerClient:
    """Secure secret resolver backed by Google Cloud Secret Manager (`secretmanager_v1`).

    Follows zero-trust secret injection best practices:
    1. Never stores or logs raw secret values.
    2. Queries `projects/{project_id}/secrets/{secret_id}/versions/{version}` via ADC.
    3. Supports injected secret environment bindings mounted by Cloud Run / Secret Manager.
    """

    def __init__(self, project_id: str | None = None) -> None:
        """Initializes the Secret Manager client.

        Args:
            project_id: Google Cloud Project ID hosting Secret Manager resources.
                Defaults to `GOOGLE_CLOUD_PROJECT` environment variable.
        """
        self.project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
        self._client: Any = None
        if secretmanager is not None and self.project_id:
            try:
                self._client = secretmanager.SecretManagerServiceClient()
            except Exception:
                self._client = None

    @functools.lru_cache(maxsize=64)
    def get_secret(
        self,
        secret_id: str,
        version: str = "latest",
        *,
        allow_env_injection: bool = True,
    ) -> str:
        """Retrieves a secret payload securely from Google Cloud Secret Manager.

        Args:
            secret_id: Identifier of the secret in Google Cloud Secret Manager
                (e.g., `incident-pagerduty-webhook-secret`).
            version: Secret version to access (defaults to `"latest"`).
            allow_env_injection: Whether to check Cloud Run Secret Manager volume/env
                mounts (`SECRET_<UPPER_SECRET_ID>`) when offline or in local tests.

        Returns:
            Decoded secret string value.

        Raises:
            SecretResolutionError: If the secret cannot be resolved from Secret Manager
                or an authorized runtime injection source.
        """
        if not secret_id or not isinstance(secret_id, str):
            raise SecretResolutionError("secret_id must be a non-empty string.")

        # 1. Primary path: Google Cloud Secret Manager API
        if self._client is not None and self.project_id:
            resource_name = (
                f"projects/{self.project_id}/secrets/{secret_id}/versions/{version}"
            )
            try:
                response = self._client.access_secret_version(
                    request={"name": resource_name}
                )
                return response.payload.data.decode("utf-8").strip()
            except Exception as exc:
                if not allow_env_injection:
                    raise SecretResolutionError(
                        f"Failed to fetch secret '{secret_id}' from Secret Manager: {exc}"
                    ) from exc

        # 2. Secondary path: Cloud Run Secret Manager mounted environment injection
        if allow_env_injection:
            normalized_env_key = "SECRET_" + secret_id.upper().replace("-", "_")
            injected_val = os.environ.get(normalized_env_key) or os.environ.get(secret_id)
            if injected_val:
                return injected_val.strip()

        raise SecretResolutionError(
            f"Secret '{secret_id}' could not be resolved from Google Cloud Secret Manager "
            f"(project='{self.project_id or 'unset'}'). Configure Secret Manager IAM "
            "(`roles/secretmanager.secretAccessor`) or mount the secret via Cloud Run."
        )


default_secret_manager = SecretManagerClient()
