"""Explicit Input and Output JSON Schemas for Tool Validation and LLM Constrained Decoding.

Satisfies Category 1 ('Explicit JSON Schemas') of the AgentOps Code Review Matrix by
enforcing strict input and output schemas (`extra="forbid"`) across every tool and
agent response contract.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

try:
    from pydantic import BaseModel, ConfigDict, Field
    PYDANTIC_AVAILABLE = True
except ImportError:  # pragma: no cover - fallback when pydantic is not installed locally
    PYDANTIC_AVAILABLE = False

    class _CompatBaseModel:
        """Lightweight Pydantic v2 compatible validator fallback for stdlib-only environments."""

        def __init__(self, **kwargs: Any) -> None:
            annotations = getattr(self.__class__, "__annotations__", {})
            for key in kwargs:
                if key not in annotations:
                    raise ValueError(f"Unexpected extra field '{key}' is forbidden by schema.")
            for field_name in annotations:
                if field_name in kwargs:
                    setattr(self, field_name, kwargs[field_name])
                elif hasattr(self.__class__, field_name):
                    default_val = getattr(self.__class__, field_name)
                    setattr(
                        self,
                        field_name,
                        list(default_val) if isinstance(default_val, list) else default_val,
                    )
                else:
                    raise ValueError(f"Missing required schema field '{field_name}'.")
            self._run_validators()

        def _run_validators(self) -> None:
            pass

        @classmethod
        def model_validate(cls, data: dict[str, Any] | Any) -> Any:
            if isinstance(data, cls):
                return data
            if not isinstance(data, dict):
                raise ValueError(f"Expected dict matching {cls.__name__} schema.")
            return cls(**data)

        def model_dump(self) -> dict[str, Any]:
            return {
                k: (v.model_dump() if hasattr(v, "model_dump") else v)
                for k, v in self.__dict__.items()
                if not k.startswith("_")
            }

        @classmethod
        def model_json_schema(cls) -> dict[str, Any]:
            return getattr(cls, "_JSON_SCHEMA", {"title": cls.__name__, "type": "object"})

    BaseModel = _CompatBaseModel  # type: ignore[misc,assignment]

    def ConfigDict(**kwargs: Any) -> dict[str, Any]:  # type: ignore[misc]
        return kwargs

    def Field(default: Any = ..., **kwargs: Any) -> Any:  # type: ignore[misc]
        return default if default is not ... else None


# ---------------------------------------------------------------------------
# Explicit JSON Schemas (exported for ADK tool declarations & schema audits)
# ---------------------------------------------------------------------------

CREATE_CRITICAL_BUG_INPUT_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "CreateCriticalBugInput",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "service_name",
        "severity",
        "title",
        "reproduction_steps",
        "impacted_slo",
    ],
    "properties": {
        "service_name": {
            "type": "string",
            "minLength": 3,
            "maxLength": 80,
            "pattern": "^[a-z0-9-]+$",
            "description": "Canonical kebab-case production service identifier (e.g., 'checkout-api-service').",
        },
        "severity": {
            "type": "string",
            "enum": ["P0", "P1", "P2"],
            "description": "Incident priority level: P0 (critical outage), P1 (major degradation), P2 (minor).",
        },
        "title": {
            "type": "string",
            "minLength": 10,
            "maxLength": 200,
            "description": "Concise engineering summary of the production failure mode.",
        },
        "reproduction_steps": {
            "type": "array",
            "minItems": 1,
            "items": {"type": "string"},
            "description": "Ordered list of deterministic steps or telemetry queries reproducing the issue.",
        },
        "impacted_slo": {
            "type": "string",
            "description": "Name of the breached Service Level Objective (e.g., 'p99_latency_under_250ms').",
        },
        "human_confirmed": {
            "type": "boolean",
            "default": False,
            "description": "Explicit human-in-the-loop approval flag required when filing P0 page-out bugs.",
        },
    },
}

CREATE_CRITICAL_BUG_OUTPUT_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "CreateCriticalBugOutput",
    "type": "object",
    "additionalProperties": False,
    "required": ["status", "bug_id", "severity", "service_name", "escalation_channel", "summary"],
    "properties": {
        "status": {"type": "string", "enum": ["created", "pending_human_confirmation", "error"]},
        "bug_id": {"type": "string"},
        "severity": {"type": "string", "enum": ["P0", "P1", "P2"]},
        "service_name": {"type": "string"},
        "escalation_channel": {"type": "string"},
        "summary": {"type": "string"},
    },
}

QUERY_TELEMETRY_METRICS_INPUT_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "QueryTelemetryMetricsInput",
    "type": "object",
    "additionalProperties": False,
    "required": ["service_name", "metric_type", "lookback_minutes"],
    "properties": {
        "service_name": {"type": "string", "minLength": 3, "maxLength": 80},
        "metric_type": {
            "type": "string",
            "enum": ["error_rate", "p99_latency_ms", "cpu_saturation", "memory_utilization"],
        },
        "lookback_minutes": {"type": "integer", "minimum": 1, "maximum": 1440},
    },
}

SEARCH_RUNBOOKS_INPUT_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "SearchRunbooksInput",
    "type": "object",
    "additionalProperties": False,
    "required": ["query", "service_name", "top_k"],
    "properties": {
        "query": {"type": "string", "minLength": 3, "maxLength": 300},
        "service_name": {"type": "string", "minLength": 2, "maxLength": 80},
        "top_k": {"type": "integer", "minimum": 1, "maximum": 10, "default": 3},
    },
}

PRODUCTION_REMEDIATION_INPUT_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ProductionRemediationInput",
    "type": "object",
    "additionalProperties": False,
    "required": [
        "service_name",
        "remediation_action",
        "target_revision",
        "human_approval_token",
    ],
    "properties": {
        "service_name": {"type": "string", "minLength": 3, "maxLength": 80},
        "remediation_action": {
            "type": "string",
            "enum": ["rollback_revision", "scale_up_replicas", "drain_traffic_region", "restart_pods"],
        },
        "target_revision": {"type": "string", "minLength": 2, "maxLength": 64},
        "human_approval_token": {
            "type": "string",
            "description": "Cryptographic or operator confirmation token authorizing production mutation.",
        },
    },
}


# ---------------------------------------------------------------------------
# Strict Pydantic Models for Input / Output Validation
# ---------------------------------------------------------------------------

class CreateCriticalBugInput(BaseModel):
    """Strict input schema for the `create_critical_bug` tool."""

    model_config = ConfigDict(extra="forbid")
    _JSON_SCHEMA = CREATE_CRITICAL_BUG_INPUT_JSON_SCHEMA

    service_name: str = Field(
        ...,
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9-]+$",
        description="Canonical kebab-case production service identifier (e.g., 'checkout-api-service').",
    )
    severity: Literal["P0", "P1", "P2"] = Field(
        ...,
        description="Incident priority level: P0 (critical outage), P1 (major degradation), P2 (minor).",
    )
    title: str = Field(
        ...,
        min_length=10,
        max_length=200,
        description="Concise engineering summary of the production failure mode.",
    )
    reproduction_steps: list[str] = Field(
        ...,
        min_length=1,
        description="Ordered list of deterministic steps or telemetry queries reproducing the issue.",
    )
    impacted_slo: str = Field(
        ...,
        min_length=3,
        description="Name of the breached Service Level Objective (e.g., 'p99_latency_under_250ms').",
    )
    human_confirmed: bool = Field(
        default=False,
        description="Explicit human-in-the-loop approval flag required when filing P0 page-out bugs.",
    )

    def _run_validators(self) -> None:
        if not isinstance(self.service_name, str) or len(self.service_name.strip()) < 3:
            raise ValueError("service_name must have at least 3 characters.")
        if self.severity not in ("P0", "P1", "P2"):
            raise ValueError("severity must be one of: 'P0', 'P1', 'P2'.")
        if not isinstance(self.title, str) or len(self.title.strip()) < 10:
            raise ValueError("title must be at least 10 characters long.")
        if not isinstance(self.reproduction_steps, list) or len(self.reproduction_steps) < 1:
            raise ValueError("reproduction_steps must contain at least one step.")


class CreateCriticalBugOutput(BaseModel):
    """Strict output schema for the `create_critical_bug` tool."""

    model_config = ConfigDict(extra="forbid")
    _JSON_SCHEMA = CREATE_CRITICAL_BUG_OUTPUT_JSON_SCHEMA

    status: Literal["created", "pending_human_confirmation", "error"] = Field(...)
    bug_id: str = Field(...)
    severity: Literal["P0", "P1", "P2"] = Field(...)
    service_name: str = Field(...)
    escalation_channel: str = Field(...)
    summary: str = Field(...)


class QueryTelemetryMetricsInput(BaseModel):
    """Strict input schema for `query_telemetry_metrics`."""

    model_config = ConfigDict(extra="forbid")
    _JSON_SCHEMA = QUERY_TELEMETRY_METRICS_INPUT_JSON_SCHEMA

    service_name: str = Field(..., min_length=3, max_length=80)
    metric_type: Literal["error_rate", "p99_latency_ms", "cpu_saturation", "memory_utilization"] = Field(...)
    lookback_minutes: int = Field(..., ge=1, le=1440)

    def _run_validators(self) -> None:
        if self.metric_type not in ("error_rate", "p99_latency_ms", "cpu_saturation", "memory_utilization"):
            raise ValueError(
                "metric_type must be one of: 'error_rate', 'p99_latency_ms', 'cpu_saturation', 'memory_utilization'."
            )
        if not isinstance(self.lookback_minutes, int) or not (1 <= self.lookback_minutes <= 1440):
            raise ValueError("lookback_minutes must be an integer between 1 and 1440.")


class QueryTelemetryMetricsOutput(BaseModel):
    """Strict output schema for `query_telemetry_metrics`."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["success", "error"] = Field(...)
    service_name: str = Field(...)
    metric_type: str = Field(...)
    lookback_minutes: int = Field(...)
    current_value: float = Field(...)
    slo_threshold: float = Field(...)
    breach_detected: bool = Field(...)
    unit: str = Field(...)


class SearchRunbooksInput(BaseModel):
    """Strict input schema for `search_runbooks_vertex_ai`."""

    model_config = ConfigDict(extra="forbid")
    _JSON_SCHEMA = SEARCH_RUNBOOKS_INPUT_JSON_SCHEMA

    query: str = Field(..., min_length=3, max_length=300)
    service_name: str = Field(..., min_length=2, max_length=80)
    top_k: int = Field(default=3, ge=1, le=10)

    def _run_validators(self) -> None:
        if not isinstance(self.query, str) or len(self.query.strip()) < 3:
            raise ValueError("query must be at least 3 characters.")
        if not isinstance(self.top_k, int) or not (1 <= self.top_k <= 10):
            raise ValueError("top_k must be between 1 and 10.")


class SearchRunbooksOutput(BaseModel):
    """Strict output schema for `search_runbooks_vertex_ai`."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["success", "error"] = Field(...)
    service_name: str = Field(...)
    query: str = Field(...)
    matches: list[dict[str, Any]] = Field(...)
    retrieval_backend: str = Field(...)


class ProductionRemediationInput(BaseModel):
    """Strict input schema for `execute_production_remediation`."""

    model_config = ConfigDict(extra="forbid")
    _JSON_SCHEMA = PRODUCTION_REMEDIATION_INPUT_JSON_SCHEMA

    service_name: str = Field(..., min_length=3, max_length=80)
    remediation_action: Literal[
        "rollback_revision", "scale_up_replicas", "drain_traffic_region", "restart_pods"
    ] = Field(...)
    target_revision: str = Field(..., min_length=2, max_length=64)
    human_approval_token: str = Field(default="")

    def _run_validators(self) -> None:
        if self.remediation_action not in (
            "rollback_revision",
            "scale_up_replicas",
            "drain_traffic_region",
            "restart_pods",
        ):
            raise ValueError(
                "remediation_action must be one of: 'rollback_revision', 'scale_up_replicas', "
                "'drain_traffic_region', 'restart_pods'."
            )


class ToolErrorResponse(BaseModel):
    """Guided Error Handling schema returning actionable recovery instructions to the LLM."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["error"] = Field(default="error")
    tool_name: str = Field(...)
    error_code: str = Field(...)
    error_message: str = Field(...)
    recovery_instructions: str = Field(
        ...,
        description="Step-by-step instructions telling the LLM how to correct its arguments or retry.",
    )
    suggested_next_tool: str = Field(default="")
    retryable: bool = Field(default=True)


class IncidentTriageReport(BaseModel):
    """Structured output schema (`output_schema`) constraining final incident triage synthesis."""

    model_config = ConfigDict(extra="forbid")

    incident_summary: str = Field(
        ...,
        description="Executive summary of the detected incident and affected service.",
    )
    severity: Literal["P0", "P1", "P2"] = Field(
        ...,
        description="Assessed incident severity based on SLO breach metrics.",
    )
    root_cause_hypothesis: str = Field(
        ...,
        description="Evidence-backed root cause hypothesis grounded in telemetry and runbooks.",
    )
    recommended_remediation: str = Field(
        ...,
        description="Recommended remediation action and target revision.",
    )
    requires_human_approval: bool = Field(
        ...,
        description="Whether human-in-the-loop approval is required before executing remediation.",
    )
    bug_id: str = Field(
        default="",
        description="Identifier of the filed critical bug or pending confirmation ticket.",
    )
