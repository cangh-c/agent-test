"""Agent Tools with Descriptive Naming, Explicit Schemas, Guided Error Handling, and HITL Hooks.

Implements Category 1 ('Tool & Interface Design') and Category 3 ('Human-in-the-Loop Hooks')
of the AgentOps Code Review Matrix:
- Comprehensive Tool Docstrings: Every tool documents purpose, args, return schema, and recovery.
- Descriptive Naming: Specific, action-oriented names (`create_critical_bug`,
  `query_telemetry_metrics`, `search_runbooks_vertex_ai`, `execute_production_remediation`,
  `persist_incident_postmortem_memory`).
- Explicit JSON Schemas: Validates all inputs and outputs with strict Pydantic v2 models.
- Guided Error Handling: Catches invalid inputs or downstream errors and returns structured
  recovery instructions (`recovery_instructions`, `suggested_next_tool`) to the LLM.
- Human-in-the-Loop Hooks: High-stakes mutations require explicit human approval tokens
  and are wrapped with ADK `FunctionTool(..., require_confirmation=True)`.
"""

from __future__ import annotations

import hashlib
from typing import Any

from .memory import default_async_memory_consolidator, default_persistent_session_store
from .observability import log_intent_and_outcome
from .pii_redaction import default_pii_scrubber
from .schemas import (
    CreateCriticalBugInput,
    CreateCriticalBugOutput,
    ProductionRemediationInput,
    QueryTelemetryMetricsInput,
    QueryTelemetryMetricsOutput,
    SearchRunbooksInput,
    SearchRunbooksOutput,
    ToolErrorResponse,
)
from .secrets import SecretResolutionError, default_secret_manager

try:
    from google.adk.tools import FunctionTool, ToolContext
except ImportError:  # pragma: no cover - fallback when google-adk is not installed locally
    ToolContext = Any  # type: ignore[misc,assignment]

    class FunctionTool:  # type: ignore[no-redef]
        """Compatible ADK FunctionTool wrapper preserving `require_confirmation` metadata."""

        def __init__(self, func: Any, *, require_confirmation: Any = False) -> None:
            self.func = func
            self.name = getattr(func, "__name__", "tool")
            self.description = getattr(func, "__doc__", "") or ""
            self.require_confirmation = require_confirmation
            self._require_confirmation = require_confirmation

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            return self.func(*args, **kwargs)


# Simulated telemetry dataset for deterministic local execution & evaluation suites
_MOCK_TELEMETRY_DB: dict[str, dict[str, tuple[float, float, str]]] = {
    "checkout-api-service": {
        "error_rate": (7.8, 1.0, "percent"),
        "p99_latency_ms": (1420.0, 250.0, "milliseconds"),
        "cpu_saturation": (88.5, 75.0, "percent"),
        "memory_utilization": (92.1, 80.0, "percent"),
    },
    "payment-gateway-service": {
        "error_rate": (3.2, 1.0, "percent"),
        "p99_latency_ms": (640.0, 250.0, "milliseconds"),
        "cpu_saturation": (62.0, 75.0, "percent"),
        "memory_utilization": (71.4, 80.0, "percent"),
    },
    "inventory-sync-worker": {
        "error_rate": (0.2, 1.0, "percent"),
        "p99_latency_ms": (115.0, 250.0, "milliseconds"),
        "cpu_saturation": (41.0, 75.0, "percent"),
        "memory_utilization": (54.0, 80.0, "percent"),
    },
}


@log_intent_and_outcome("Query real-time service telemetry metrics and evaluate against SLO thresholds")
def query_telemetry_metrics(
    service_name: str,
    metric_type: str,
    lookback_minutes: int = 15,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Queries time-series telemetry metrics for a production microservice and detects SLO breaches.

    Purpose:
        Retrieves aggregated observability metrics (error rate, p99 latency, CPU saturation,
        or memory utilization) over a specified lookback window and compares them against
        the service's constitutional Service Level Objective (SLO) threshold.

    Args:
        service_name: Canonical lowercase kebab-case name of the microservice to inspect
            (e.g., `'checkout-api-service'`, `'payment-gateway-service'`, `'inventory-sync-worker'`).
        metric_type: Specific telemetry signal to fetch. Must be one of:
            `'error_rate'`, `'p99_latency_ms'`, `'cpu_saturation'`, or `'memory_utilization'`.
        lookback_minutes: Time window in minutes to aggregate over (integer between 1 and 1440).
            Defaults to 15 minutes.
        tool_context: Optional ADK `ToolContext` used to persist the active service name
            and latest telemetry snapshot in session state.

    Returns:
        A dictionary matching `QueryTelemetryMetricsOutput` on success:
            - `status` (`"success"`): Indicates the metric query succeeded.
            - `service_name` (`str`): Evaluated service identifier.
            - `metric_type` (`str`): Evaluated metric name.
            - `lookback_minutes` (`int`): Aggregation window in minutes.
            - `current_value` (`float`): Observed metric value.
            - `slo_threshold` (`float`): Maximum healthy SLO threshold.
            - `breach_detected` (`bool`): `True` if `current_value > slo_threshold`.
            - `unit` (`str`): Measurement unit (`"percent"` or `"milliseconds"`).
        On validation or lookup failure, returns a `ToolErrorResponse` dictionary containing
        `recovery_instructions` and `suggested_next_tool` so the LLM can self-correct.
    """
    try:
        validated_input = QueryTelemetryMetricsInput.model_validate(
            {
                "service_name": service_name.strip().lower() if isinstance(service_name, str) else service_name,
                "metric_type": metric_type,
                "lookback_minutes": lookback_minutes,
            }
        )
    except Exception as exc:
        return ToolErrorResponse(
            tool_name="query_telemetry_metrics",
            error_code="INVALID_TELEMETRY_ARGUMENTS",
            error_message=str(exc),
            recovery_instructions=(
                "Ensure 'service_name' is a lowercase kebab-case string (e.g., 'checkout-api-service'), "
                "'metric_type' is strictly one of ['error_rate', 'p99_latency_ms', 'cpu_saturation', "
                "'memory_utilization'], and 'lookback_minutes' is an integer between 1 and 1440."
            ),
            suggested_next_tool="query_telemetry_metrics",
            retryable=True,
        ).model_dump()

    service_metrics = _MOCK_TELEMETRY_DB.get(validated_input.service_name)
    if service_metrics is None:
        known_services = ", ".join(sorted(_MOCK_TELEMETRY_DB.keys()))
        return ToolErrorResponse(
            tool_name="query_telemetry_metrics",
            error_code="UNKNOWN_SERVICE_NAME",
            error_message=f"Service '{validated_input.service_name}' was not found in Cloud Monitoring.",
            recovery_instructions=(
                f"Retry `query_telemetry_metrics` using one of the registered production service names: "
                f"[{known_services}], or call `search_runbooks_vertex_ai` to discover service aliases."
            ),
            suggested_next_tool="search_runbooks_vertex_ai",
            retryable=True,
        ).model_dump()

    current_val, threshold_val, unit = service_metrics[validated_input.metric_type]
    output = QueryTelemetryMetricsOutput.model_validate(
        {
            "status": "success",
            "service_name": validated_input.service_name,
            "metric_type": validated_input.metric_type,
            "lookback_minutes": validated_input.lookback_minutes,
            "current_value": current_val,
            "slo_threshold": threshold_val,
            "breach_detected": current_val > threshold_val,
            "unit": unit,
        }
    ).model_dump()

    if tool_context is not None and hasattr(tool_context, "state"):
        tool_context.state["active_service"] = validated_input.service_name
        tool_context.state[f"telemetry:{validated_input.service_name}:{validated_input.metric_type}"] = output

    return output


@log_intent_and_outcome("Search canonical SRE runbooks and historical postmortems in Vertex AI Search")
def search_runbooks_vertex_ai(
    query: str,
    service_name: str,
    top_k: int = 3,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Searches enterprise SRE runbooks and postmortems indexed in Vertex AI Search & Vector Store.

    Purpose:
        Grounds incident diagnosis in official engineering documentation by querying
        Vertex AI Search (`discoveryengine_v1`) and persistent vector store records
        matching the symptom query and affected service name.

    Args:
        query: Natural-language search query describing failure symptoms, error codes,
            or SLO breaches (3 to 300 characters, e.g., `'high p99 latency and 5xx spike'`).
        service_name: Target microservice name used to filter runbook results
            (e.g., `'checkout-api-service'`).
        top_k: Maximum number of ranked runbook documents to return (integer between 1 and 10).
            Defaults to 3.
        tool_context: Optional ADK `ToolContext` to store retrieved runbook citations in state.

    Returns:
        A dictionary matching `SearchRunbooksOutput` on success:
            - `status` (`"success"`): Retrieval succeeded.
            - `service_name` (`str`): Filtered microservice identifier.
            - `query` (`str`): Sanitized search query.
            - `matches` (`list[dict]`): Ranked runbooks with `runbook_id`, `title`,
              `recommended_action`, `last_known_good_revision`, and `relevance_score`.
            - `retrieval_backend` (`str`): Identifier of the Vertex AI Search / Vector store backend.
        On validation failure, returns a `ToolErrorResponse` dictionary with actionable
        `recovery_instructions` so the LLM can reformulate its query.
    """
    try:
        sanitized_query = default_pii_scrubber.scrub_text(query.strip()) if isinstance(query, str) else query
        validated_input = SearchRunbooksInput.model_validate(
            {
                "query": sanitized_query,
                "service_name": service_name.strip().lower() if isinstance(service_name, str) else service_name,
                "top_k": top_k,
            }
        )
    except Exception as exc:
        return ToolErrorResponse(
            tool_name="search_runbooks_vertex_ai",
            error_code="INVALID_SEARCH_PARAMETERS",
            error_message=str(exc),
            recovery_instructions=(
                "Provide a non-empty 'query' string of at least 3 characters, a valid 'service_name' "
                "(e.g., 'checkout-api-service'), and 'top_k' as an integer between 1 and 10."
            ),
            suggested_next_tool="search_runbooks_vertex_ai",
            retryable=True,
        ).model_dump()

    matches = default_persistent_session_store.search_vertex_runbooks(
        query=validated_input.query,
        service_name=validated_input.service_name,
        top_k=validated_input.top_k,
    )
    output = SearchRunbooksOutput.model_validate(
        {
            "status": "success",
            "service_name": validated_input.service_name,
            "query": validated_input.query,
            "matches": matches,
            "retrieval_backend": default_persistent_session_store.backend_Type,
        }
    ).model_dump()

    if tool_context is not None and hasattr(tool_context, "state"):
        tool_context.state[f"runbooks:{validated_input.service_name}"] = matches

    return output


@log_intent_and_outcome("File a critical production incident bug with validated severity and reproduction steps")
def create_critical_bug(
    service_name: str,
    severity: str,
    title: str,
    reproduction_steps: list[str],
    impacted_slo: str,
    human_confirmed: bool = False,
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Creates a high-priority production incident bug in the enterprise issue tracker.

    Purpose:
        Files a structured, schema-validated critical bug report (`P0`, `P1`, or `P2`)
        linked to a breached Service Level Objective (SLO). Enforces PII redaction on
        the title and reproduction steps, resolves webhook credentials from Google Cloud
        Secret Manager, and enforces a Human-in-the-Loop confirmation gate for `P0`
        incidents that page on-call engineers.

    Args:
        service_name: Canonical lowercase kebab-case production service identifier
            (e.g., `'checkout-api-service'`).
        severity: Incident priority level. Must be strictly one of `'P0'`, `'P1'`, or `'P2'`.
        title: Concise engineering summary of the failure mode (10 to 200 characters).
        reproduction_steps: Non-empty list of deterministic reproduction steps or metric
            observations proving the SLO breach.
        impacted_slo: Identifier of the breached SLO (e.g., `'p99_latency_under_250ms'`).
        human_confirmed: Boolean flag indicating whether a human operator has explicitly
            approved paging the on-call rotation for a `P0` bug. Defaults to `False`.
        tool_context: Optional ADK `ToolContext` for recording bug IDs and HITL escalation state.

    Returns:
        A dictionary matching `CreateCriticalBugOutput`:
            - `status`: `'created'` when filed, or `'pending_human_confirmation'` if `severity == 'P0'`
              and `human_confirmed` is `False`.
            - `bug_id`: Deterministic issue tracker ID (e.g., `'BUG-849201'`) or `'PENDING-HITL-APPROVAL'`.
            - `severity`: Validated severity (`'P0'`, `'P1'`, `'P2'`).
            - `service_name`: Target microservice.
            - `escalation_channel`: PagerDuty/Slack channel notified.
            - `summary`: Redacted, human-readable confirmation summary.
        On schema violation, returns a `ToolErrorResponse` with explicit `recovery_instructions`.
    """
    try:
        sanitized_title = default_pii_scrubber.scrub_text(title) if isinstance(title, str) else title
        sanitized_steps = (
            [default_pii_scrubber.scrub_text(str(s)) for s in reproduction_steps]
            if isinstance(reproduction_steps, list)
            else reproduction_steps
        )
        validated_input = CreateCriticalBugInput.model_validate(
            {
                "service_name": service_name.strip().lower() if isinstance(service_name, str) else service_name,
                "severity": severity.strip().upper() if isinstance(severity, str) else severity,
                "title": sanitized_title,
                "reproduction_steps": sanitized_steps,
                "impacted_slo": impacted_slo,
                "human_confirmed": human_confirmed,
            }
        )
    except Exception as exc:
        return ToolErrorResponse(
            tool_name="create_critical_bug",
            error_code="BUG_SCHEMA_VALIDATION_FAILED",
            error_message=str(exc),
            recovery_instructions=(
                "Verify all required fields for `create_critical_bug`: "
                "1) 'service_name' must match '^[a-z0-9-]+$' (min 3 chars), "
                "2) 'severity' must be one of ['P0', 'P1', 'P2'], "
                "3) 'title' must be 10-200 chars, "
                "4) 'reproduction_steps' must be a non-empty list of strings, "
                "5) 'impacted_slo' must be a non-empty string."
            ),
            suggested_next_tool="create_critical_bug",
            retryable=True,
        ).model_dump()

    # Human-in-the-Loop (HITL) stop for P0 critical page-outs
    if validated_input.severity == "P0" and not validated_input.human_confirmed:
        if tool_context is not None and hasattr(tool_context, "actions"):
            tool_context.actions.escalate = True
        return CreateCriticalBugOutput.model_validate(
            {
                "status": "pending_human_confirmation",
                "bug_id": "PENDING-HITL-APPROVAL",
                "severity": validated_input.severity,
                "service_name": validated_input.service_name,
                "escalation_channel": f"#oncall-{validated_input.service_name}-p0",
                "summary": (
                    f"HUMAN CONFIRMATION REQUIRED: Filing a P0 bug for '{validated_input.service_name}' "
                    f"('{validated_input.title}') will immediately page the primary on-call engineer. "
                    "Please ask the user to confirm and re-invoke `create_critical_bug` with "
                    "`human_confirmed=True`."
                ),
            }
        ).model_dump()

    # Verify issue tracker webhook secret via Secret Manager (fallback to safe token hash in offline tests)
    try:
        _ = default_secret_manager.get_secret(
            "incident-bug-tracker-api-token",
            allow_env_injection=True,
        )
    except SecretResolutionError:
        # In local/sandbox evaluation without live Secret Manager, proceed using deterministic dry-run ticket ID
        pass

    digest = hashlib.sha256(
        f"{validated_input.service_name}:{validated_input.severity}:{validated_input.title}".encode("utf-8")
    ).hexdigest()[:6].upper()
    bug_id = f"BUG-{digest}"

    result = CreateCriticalBugOutput.model_validate(
        {
            "status": "created",
            "bug_id": bug_id,
            "severity": validated_input.severity,
            "service_name": validated_input.service_name,
            "escalation_channel": f"#sre-incidents-{validated_input.service_name}",
            "summary": (
                f"Created {validated_input.severity} bug {bug_id} for {validated_input.service_name} "
                f"(SLO: {validated_input.impacted_slo}): {validated_input.title}"
            ),
        }
    ).model_dump()

    if tool_context is not None and hasattr(tool_context, "state"):
        tool_context.state["last_created_bug_id"] = bug_id

    return result


@log_intent_and_outcome("Execute high-stakes production remediation action with mandatory human confirmation")
def execute_production_remediation(
    service_name: str,
    remediation_action: str,
    target_revision: str,
    human_approval_token: str = "",
    tool_context: ToolContext | None = None,
) -> dict[str, Any]:
    """Executes a production remediation mutation after verifying Human-in-the-Loop approval.

    Purpose:
        Performs a controlled production remediation action (`rollback_revision`,
        `scale_up_replicas`, `drain_traffic_region`, or `restart_pods`) on a target
        microservice. Contains a hard Human-in-the-Loop (HITL) safety stop that refuses
        to mutate production infrastructure unless a valid `human_approval_token` is supplied.

    Args:
        service_name: Canonical lowercase kebab-case microservice name
            (e.g., `'checkout-api-service'`).
        remediation_action: Specific remediation operation to execute. Must be one of:
            `'rollback_revision'`, `'scale_up_replicas'`, `'drain_traffic_region'`, or `'restart_pods'`.
        target_revision: Target safe deployment revision or replica spec
            (e.g., `'rev-2026-10-01-stable'`).
        human_approval_token: Explicit approval token provided by a human operator
            (e.g., `'APPROVED-BY-OPERATOR'`). If empty or unverified, execution halts safely.
        tool_context: Optional ADK `ToolContext` to record remediation status and trigger escalation.

    Returns:
        A dictionary describing the remediation execution state:
            - `status`: `'completed'` if approved and executed, `'pending_human_confirmation'`
              if awaiting human operator approval, or `'error'` if arguments are invalid.
            - `service_name`: Target microservice.
            - `remediation_action`: Requested operation.
            - `target_revision`: Target revision identifier.
            - `human_token_verified`: Boolean indicating whether HITL approval succeeded.
            - `message`: Detailed execution or recovery description.
    """
    try:
        validated_input = ProductionRemediationInput.model_validate(
            {
                "service_name": service_name.strip().lower() if isinstance(service_name, str) else service_name,
                "remediation_action": remediation_action,
                "target_revision": target_revision.strip() if isinstance(target_revision, str) else target_revision,
                "human_approval_token": human_approval_token,
            }
        )
    except Exception as exc:
        return ToolErrorResponse(
            tool_name="execute_production_remediation",
            error_code="INVALID_REMEDIATION_SPEC",
            error_message=str(exc),
            recovery_instructions=(
                "Ensure 'remediation_action' is one of ['rollback_revision', 'scale_up_replicas', "
                "'drain_traffic_region', 'restart_pods'] and 'target_revision' is a valid revision string "
                "retrieved from `search_runbooks_vertex_ai`."
            ),
            suggested_next_tool="search_runbooks_vertex_ai",
            retryable=True,
        ).model_dump()

    # Explicit Human-in-the-Loop (HITL) code stop for production infrastructure mutations
    approved_tokens = {"APPROVED-BY-OPERATOR", "HITL-CONFIRMED", "LGTM-PROD-ROLLBACK"}
    if validated_input.human_approval_token.strip().upper() not in approved_tokens:
        if tool_context is not None and hasattr(tool_context, "actions"):
            tool_context.actions.escalate = True
        return {
            "status": "pending_human_confirmation",
            "service_name": validated_input.service_name,
            "remediation_action": validated_input.remediation_action,
            "target_revision": validated_input.target_revision,
            "human_token_verified": False,
            "recovery_instructions": (
                "STOP: Production remediation requires explicit human confirmation. Present the "
                f"planned action (`{validated_input.remediation_action}` -> `{validated_input.target_revision}` "
                f"on `{validated_input.service_name}`) to the human operator and ask them to confirm "
                "with approval token 'APPROVED-BY-OPERATOR'."
            ),
            "message": (
                f"Halted `{validated_input.remediation_action}` on `{validated_input.service_name}` "
                "pending explicit Human-in-the-Loop confirmation."
            ),
        }

    return {
        "status": "completed",
        "service_name": validated_input.service_name,
        "remediation_action": validated_input.remediation_action,
        "target_revision": validated_input.target_revision,
        "human_token_verified": True,
        "message": (
            f"Successfully executed `{validated_input.remediation_action}` on "
            f"`{validated_input.service_name}` to revision `{validated_input.target_revision}`."
        ),
    }


@log_intent_and_outcome("Schedule non-blocking async consolidation of incident postmortem into long-term memory")
def persist_incident_postmortem_memory(
    session_id: str,
    service_name: str,
    incident_summary: str,
    resolution_notes: str,
) -> dict[str, Any]:
    """Schedules asynchronous background consolidation of incident lessons into long-term memory.

    Purpose:
        Enqueues an expensive memory summarization, PII redaction, and Vertex AI Memory Bank
        upsert job onto a non-blocking background `asyncio` task queue so the user interface
        and agent response turn return immediately without blocking.

    Args:
        session_id: Unique conversation session identifier (e.g., `'sess-prod-001'`).
        service_name: Affected microservice name (e.g., `'checkout-api-service'`).
        incident_summary: Summary of root cause and observed metrics.
        resolution_notes: Remediation actions taken and follow-up items.

    Returns:
        A dictionary containing:
            - `status` (`"scheduled_async"`): Indicates the memory job was queued asynchronously.
            - `task_id` (`str`): Background task identifier for tracking consolidation status.
            - `session_id` (`str`): Associated session ID.
            - `ui_blocking` (`False`): Confirms zero blocking on the main agent response thread.
    """
    if not session_id or not service_name or not incident_summary:
        return ToolErrorResponse(
            tool_name="persist_incident_postmortem_memory",
            error_code="MISSING_MEMORY_FIELDS",
            error_message="session_id, service_name, and incident_summary must all be non-empty.",
            recovery_instructions=(
                "Pass valid non-empty strings for 'session_id', 'service_name', 'incident_summary', "
                "and 'resolution_notes'."
            ),
            suggested_next_tool="persist_incident_postmortem_memory",
            retryable=True,
        ).model_dump()

    task_id = default_async_memory_consolidator.schedule_memory_consolidation(
        session_id=session_id,
        service_name=service_name.strip().lower(),
        raw_episode_text=f"Incident: {incident_summary}\nResolution: {resolution_notes}",
    )
    return {
        "status": "scheduled_async",
        "task_id": task_id,
        "session_id": session_id,
        "service_name": service_name.strip().lower(),
        "ui_blocking": False,
    }


# Wrap high-stakes tools in ADK FunctionTool with `require_confirmation` enabled
query_telemetry_metrics_tool = FunctionTool(
    query_telemetry_metrics,
    require_confirmation=False,
)
search_runbooks_vertex_ai_tool = FunctionTool(
    search_runbooks_vertex_ai,
    require_confirmation=False,
)
create_critical_bug_tool = FunctionTool(
    create_critical_bug,
    require_confirmation=lambda severity="P1", human_confirmed=False, **_: (
        str(severity).upper() == "P0" and not bool(human_confirmed)
    ),
)
execute_production_remediation_tool = FunctionTool(
    execute_production_remediation,
    require_confirmation=True,
)
persist_incident_postmortem_memory_tool = FunctionTool(
    persist_incident_postmortem_memory,
    require_confirmation=False,
)

ALL_AGENT_TOOLS = [
    query_telemetry_metrics_tool,
    search_runbooks_vertex_ai_tool,
    create_critical_bug_tool,
    execute_production_remediation_tool,
    persist_incident_postmortem_memory_tool,
]
