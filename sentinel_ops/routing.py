"""Strategic Model Routing for Cost, Latency, and Reasoning Optimization.

Satisfies Category 3 ('Strategic Model Routing') of the AgentOps Code Review Matrix
by dynamically routing requests to the optimal Gemini model tier:
- `gemini-2.5-flash`: High-throughput, low-latency tasks (telemetry lookups, log parsing,
  runbook search, initial triage classification).
- `gemini-2.5-pro`: Complex multi-step root cause analysis (RCA), architectural synthesis,
  and high-stakes production remediation planning.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .observability import default_logger, default_tracer


@dataclass(frozen=True)
class ModelRouteDecision:
    """Represents a deterministic model routing decision with justification."""

    selected_model: str
    task_complexity: str
    routing_reason: str
    estimated_latency_tier: str


class StrategicModelRouter:
    """Routes agent invocations between `gemini-2.5-flash` and `gemini-2.5-pro`."""

    FAST_MODEL = "gemini-2.5-flash"
    REASONING_MODEL = "gemini-2.5-pro"

    _COMPLEX_REASONING_KEYWORDS: tuple[str, ...] = (
        "root cause",
        "rca",
        "postmortem",
        "remediation plan",
        "rollback",
        "multi-region",
        "cascading failure",
        "architecture",
        "p0",
        "critical outage",
        "synthesize",
    )

    _FAST_LOOKUP_KEYWORDS: tuple[str, ...] = (
        "status",
        "metric",
        "check",
        "ping",
        "list",
        "runbook",
        "latency",
        "error rate",
    )

    def select_model(
        self,
        query: str,
        *,
        agent_role: str = "coordinator",
        severity_hint: str | None = None,
    ) -> ModelRouteDecision:
        """Selects the optimal Gemini model based on task complexity, role, and severity.

        Args:
            query: User prompt or task description.
            agent_role: Sub-agent role (`'telemetry_investigator'`, `'runbook_researcher'`,
                `'remediation_planner'`, `'self_eval_critic'`, or `'coordinator'`).
            severity_hint: Optional incident severity (`'P0'`, `'P1'`, `'P2'`).

        Returns:
            `ModelRouteDecision` specifying `selected_model` (`gemini-2.5-flash` or
            `gemini-2.5-pro`), `task_complexity`, and `routing_reason`.
        """
        with default_tracer.start_span(
            "routing.select_model",
            attributes={"agentops.agent_role": agent_role},
        ) as span:
            normalized_query = (query or "").lower()

            # 1. Explicit sub-agent role specialization
            if agent_role in ("telemetry_investigator", "runbook_researcher"):
                decision = ModelRouteDecision(
                    selected_model=self.FAST_MODEL,
                    task_complexity="low_latency_extraction",
                    routing_reason=(
                        f"Sub-agent '{agent_role}' performs bounded tool retrieval and extraction; "
                        f"routed to '{self.FAST_MODEL}' for sub-second latency."
                    ),
                    estimated_latency_tier="fast",
                )
            elif agent_role == "remediation_planner" or (severity_hint or "").upper() == "P0":
                decision = ModelRouteDecision(
                    selected_model=self.REASONING_MODEL,
                    task_complexity="high_complexity_planning",
                    routing_reason=(
                        f"Role '{agent_role}' / severity '{severity_hint or 'high'}' requires multi-step "
                        f"causal reasoning and safe remediation planning; routed to '{self.REASONING_MODEL}'."
                    ),
                    estimated_latency_tier="deep_reasoning",
                )
            # 2. Dynamic prompt complexity classification
            elif any(kw in normalized_query for kw in self._COMPLEX_REASONING_KEYWORDS) or len(normalized_query) > 240:
                decision = ModelRouteDecision(
                    selected_model=self.REASONING_MODEL,
                    task_complexity="high_complexity_reasoning",
                    routing_reason=(
                        f"Query contains complex RCA/planning signals; routed to '{self.REASONING_MODEL}'."
                    ),
                    estimated_latency_tier="deep_reasoning",
                )
            else:
                decision = ModelRouteDecision(
                    selected_model=self.FAST_MODEL,
                    task_complexity="fast_triage",
                    routing_reason=(
                        f"Standard telemetry/status lookup query; routed to '{self.FAST_MODEL}' "
                        "for optimal cost and speed."
                    ),
                    estimated_latency_tier="fast",
                )

            span.set_attribute("gen_ai.request.model", decision.selected_model)
            span.set_attribute("agentops.task_complexity", decision.task_complexity)
            default_logger.info(
                f"Routed request to model '{decision.selected_model}' ({decision.task_complexity})",
                extra={
                    "event_type": "MODEL_ROUTING_DECISION",
                    "agent_name": agent_role,
                    "metadata": {
                        "selected_model": decision.selected_model,
                        "task_complexity": decision.task_complexity,
                        "routing_reason": decision.routing_reason,
                    },
                },
            )
            return decision


default_model_router = StrategicModelRouter()


def strategic_model_routing_callback(
    callback_context: Any,
    llm_request: Any,
) -> Any:
    """ADK `before_model_callback` that dynamically sets `llm_request.model` based on query complexity."""
    query_text = ""
    if hasattr(llm_request, "contents") and llm_request.contents:
        for content in llm_request.contents:
            parts = getattr(content, "parts", None) or []
            for part in parts:
                if getattr(part, "text", None):
                    query_text += " " + str(part.text)

    agent_name = getattr(callback_context, "agent_name", "coordinator")
    decision = default_model_router.select_model(query_text.strip(), agent_role=agent_name)
    if hasattr(llm_request, "model"):
        llm_request.model = decision.selected_model
    if hasattr(callback_context, "state") and isinstance(callback_context.state, dict):
        callback_context.state["last_routed_model"] = decision.selected_model
    return None
