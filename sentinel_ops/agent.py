"""ADK Multi-Agent Orchestration: Coordinator, Parallel Diagnostic Fan-Out, and Sequential Pipeline.

Implements Category 3 ('Multi-Agent Patterns', 'Strategic Model Routing', 'Guardrails & Policy
Plugins', 'Human-in-the-Loop Hooks') and Category 2 ('History Compaction', 'Robust System
Instructions') of the AgentOps Code Review Matrix:
1. `telemetry_investigator_agent` (`LlmAgent` on `gemini-2.5-flash`): Queries SLO metrics.
2. `runbook_rag_researcher_agent` (`LlmAgent` on `gemini-2.5-flash`): Searches Vertex AI Search runbooks.
3. `diagnostic_fanout_agent` (`ParallelAgent`): Runs telemetry & runbook agents concurrently.
4. `remediation_planner_agent` (`LlmAgent` on `gemini-2.5-pro`): Synthesizes RCA, files critical bugs,
   and prepares HITL-gated production remediations.
5. `self_eval_critic_agent` (`LlmAgent` on `gemini-2.5-flash` with `output_schema=IncidentTriageReport`):
   Audits factual grounding and constitutional compliance.
6. `incident_resolution_pipeline` (`SequentialAgent`): Chains fan-out -> planner -> self-eval critic.
7. `sentinel_coordinator_agent` / `root_agent` (`LlmAgent` on `gemini-2.5-pro`): Root supervisor
   coordinating multi-agent delegation with dynamic model routing and security guardrails.
8. `app` (`App`): Top-level ADK application configured with `EventsCompactionConfig`,
   `ContextCacheConfig`, `ResumabilityConfig`, and `AgentOpsSecurityAndPolicyPlugin`.
"""

from __future__ import annotations

from typing import Any

from .guardrails import AgentOpsSecurityAndPolicyPlugin, default_security_plugin
from .memory import (
    ResumabilityConfig,
    build_adk_compaction_config,
    build_adk_context_cache_config,
    default_async_memory_consolidator,
    default_history_compactor,
    default_persistent_session_store,
)
from .observability import default_audit_logger, default_logger, default_tracer
from .pii_redaction import default_pii_scrubber
from .prompts import (
    AGENT_CONSTITUTION_SYSTEM_PROMPT,
    REMEDIATION_PLANNER_PROMPT,
    RUNBOOK_RESEARCHER_PROMPT,
    SELF_EVAL_CRITIC_PROMPT,
    TELEMETRY_INVESTIGATOR_PROMPT,
)
from .routing import (
    StrategicModelRouter,
    default_model_router,
    strategic_model_routing_callback,
)
from .schemas import IncidentTriageReport
from .tools import (
    ALL_AGENT_TOOLS,
    create_critical_bug,
    create_critical_bug_tool,
    execute_production_remediation,
    execute_production_remediation_tool,
    persist_incident_postmortem_memory,
    persist_incident_postmortem_memory_tool,
    query_telemetry_metrics,
    query_telemetry_metrics_tool,
    search_runbooks_vertex_ai,
    search_runbooks_vertex_ai_tool,
)

try:
    from google.adk.agents import LlmAgent, ParallelAgent, SequentialAgent
    from google.adk.apps import App
except ImportError:  # pragma: no cover - fallback when google-adk is not installed locally

    class _BaseFallbackAgent:
        def __init__(
            self,
            *,
            name: str,
            description: str = "",
            sub_agents: list[Any] | None = None,
            **kwargs: Any,
        ) -> None:
            self.name = name
            self.description = description
            self.sub_agents = sub_agents or []
            for k, v in kwargs.items():
                setattr(self, k, v)

    class LlmAgent(_BaseFallbackAgent):  # type: ignore[no-redef]
        def __init__(
            self,
            *,
            name: str,
            model: str = "gemini-2.5-flash",
            description: str = "",
            instruction: str = "",
            tools: list[Any] | None = None,
            sub_agents: list[Any] | None = None,
            output_schema: Any = None,
            output_key: str | None = None,
            before_model_callback: Any = None,
            after_model_callback: Any = None,
            before_tool_callback: Any = None,
            after_tool_callback: Any = None,
            **kwargs: Any,
        ) -> None:
            super().__init__(name=name, description=description, sub_agents=sub_agents, **kwargs)
            self.model = model
            self.instruction = instruction
            self.tools = tools or []
            self.output_schema = output_schema
            self.output_key = output_key
            self.before_model_callback = before_model_callback
            self.after_model_callback = after_model_callback
            self.before_tool_callback = before_tool_callback
            self.after_tool_callback = after_tool_callback

    class ParallelAgent(_BaseFallbackAgent):  # type: ignore[no-redef]
        pass

    class SequentialAgent(_BaseFallbackAgent):  # type: ignore[no-redef]
        pass

    class App:  # type: ignore[no-redef]
        def __init__(
            self,
            *,
            name: str,
            root_agent: Any,
            plugins: list[Any] | None = None,
            events_compaction_config: Any = None,
            context_cache_config: Any = None,
            resumability_config: Any = None,
        ) -> None:
            self.name = name
            self.root_agent = root_agent
            self.plugins = plugins or []
            self.events_compaction_config = events_compaction_config
            self.context_cache_config = context_cache_config
            self.resumability_config = resumability_config


# ---------------------------------------------------------------------------
# 1. Specialized Sub-Agents (Strategic Model Routing: Flash vs. Pro)
# ---------------------------------------------------------------------------

telemetry_investigator_agent = LlmAgent(
    name="telemetry_investigator_agent",
    model=StrategicModelRouter.FAST_MODEL,
    description="High-speed telemetry investigator that queries service SLO metrics.",
    instruction=TELEMETRY_INVESTIGATOR_PROMPT,
    tools=[query_telemetry_metrics_tool],
    output_key="telemetry_diagnostic_findings",
)

runbook_rag_researcher_agent = LlmAgent(
    name="runbook_rag_researcher_agent",
    model=StrategicModelRouter.FAST_MODEL,
    description="RAG specialist retrieving SRE runbooks and rollback revisions from Vertex AI Search.",
    instruction=RUNBOOK_RESEARCHER_PROMPT,
    tools=[search_runbooks_vertex_ai_tool],
    output_key="runbook_rag_findings",
)

diagnostic_fanout_agent = ParallelAgent(
    name="diagnostic_fanout_agent",
    description="Executes telemetry metric inspection and Vertex AI Search runbook RAG in parallel.",
    sub_agents=[
        telemetry_investigator_agent,
        runbook_rag_researcher_agent,
    ],
)

remediation_planner_agent = LlmAgent(
    name="remediation_planner_agent",
    model=StrategicModelRouter.REASONING_MODEL,
    description=(
        "Deep-reasoning remediation architect that correlates telemetry with runbooks, "
        "files critical bugs, and prepares HITL-gated production remediations."
    ),
    instruction=REMEDIATION_PLANNER_PROMPT,
    tools=[
        create_critical_bug_tool,
        execute_production_remediation_tool,
        persist_incident_postmortem_memory_tool,
    ],
    output_key="remediation_plan_findings",
)

self_eval_critic_agent = LlmAgent(
    name="self_eval_critic_agent",
    model=StrategicModelRouter.FAST_MODEL,
    description="Self-evaluation guardrail agent verifying factual grounding, PII safety, and HITL stops.",
    instruction=SELF_EVAL_CRITIC_PROMPT,
    output_schema=IncidentTriageReport,
    output_key="validated_incident_report",
)

incident_resolution_pipeline = SequentialAgent(
    name="incident_resolution_pipeline",
    description=(
        "End-to-end sequential incident workflow: Parallel(Telemetry, Runbook RAG) -> "
        "Remediation Planner (Pro) -> Self-Eval Critic."
    ),
    sub_agents=[
        diagnostic_fanout_agent,
        remediation_planner_agent,
        self_eval_critic_agent,
    ],
)


# ---------------------------------------------------------------------------
# 2. Root Coordinator Agent & ADK Application Container
# ---------------------------------------------------------------------------

sentinel_coordinator_agent = LlmAgent(
    name="sentinel_coordinator_agent",
    model=StrategicModelRouter.REASONING_MODEL,
    description=(
        "SentinelOps Principal SRE Coordinator Agent managing incident diagnosis, "
        "critical bug creation, and HITL-approved production remediation."
    ),
    instruction=AGENT_CONSTITUTION_SYSTEM_PROMPT,
    tools=ALL_AGENT_TOOLS,
    sub_agents=[incident_resolution_pipeline],
    before_model_callback=strategic_model_routing_callback,
)

# Canonical ADK CLI entrypoint (`adk run sentinel_ops` / `adk web`)
root_agent = sentinel_coordinator_agent

app = App(
    name="sentinel_ops_app",
    root_agent=root_agent,
    plugins=[default_security_plugin],
    events_compaction_config=build_adk_compaction_config(),
    context_cache_config=build_adk_context_cache_config(),
    resumability_config=ResumabilityConfig(is_resumable=True),
)


class SentinelOpsOrchestrator:
    """Deterministic multi-agent execution harness for local runs and golden-dataset evaluations.

    Executes the full SentinelOps lifecycle (Input Guardrail -> Session Load & History Compaction
    -> Strategic Model Routing -> Parallel Telemetry & Runbook RAG -> Critical Bug Filing &
    HITL Remediation Gate -> Self-Evaluation Guardrail -> Async Memory Consolidation) with
    OpenTelemetry distributed tracing and Intent-vs-Outcome structured JSON logging.
    """

    def __init__(
        self,
        *,
        plugin: AgentOpsSecurityAndPolicyPlugin | None = None,
        router: StrategicModelRouter | None = None,
    ) -> None:
        self.plugin = plugin or default_security_plugin
        self.router = router or default_model_router
        self.session_store = default_persistent_session_store
        self.compactor = default_history_compactor
        self.memory_consolidator = default_async_memory_consolidator

    def handle_incident_query(
        self,
        *,
        user_query: str,
        service_name: str = "checkout-api-service",
        session_id: str = "sess-default-001",
        user_id: str = "sre-operator",
        human_confirmed: bool = False,
        human_approval_token: str = "",
    ) -> dict[str, Any]:
        """Runs an end-to-end traced multi-agent incident investigation turn."""
        with default_tracer.start_span(
            "agent.handle_incident_query",
            attributes={
                "gen_ai.system": "google_adk",
                "agentops.session_id": session_id,
                "agentops.service_name": service_name,
            },
        ) as root_span:
            # Step 1: Input Guardrail & Prompt Injection Check
            input_check = self.plugin.evaluate_input_prompt_guardrail(user_query)
            if not input_check.allowed:
                root_span.set_attribute("agentops.status", "blocked_by_input_guardrail")
                return {
                    "status": "blocked_by_guardrail",
                    "reason": input_check.reason,
                    "routed_model": None,
                    "tool_trajectory": [],
                }

            # Step 2: Persist user turn & run History Compaction if needed
            session_data = self.session_store.save_session_turn(
                session_id=session_id,
                user_id=user_id,
                role="user",
                content=input_check.sanitized_text,
                state_updates={"active_service": service_name},
            )
            compaction_result = self.compactor.compact_history(session_data["history"])

            # Step 3: Strategic Model Routing
            route_decision = self.router.select_model(
                input_check.sanitized_text,
                agent_role="coordinator",
            )
            root_span.set_attribute("gen_ai.request.model", route_decision.selected_model)

            tool_trajectory: list[str] = []

            # Step 4: Parallel Diagnostic Fan-Out (Telemetry + Runbook RAG)
            with default_tracer.start_span("agent.diagnostic_fanout_agent"):
                error_metrics = query_telemetry_metrics(
                    service_name=service_name,
                    metric_type="error_rate",
                    lookback_minutes=15,
                )
                tool_trajectory.append("query_telemetry_metrics")

                latency_metrics = query_telemetry_metrics(
                    service_name=service_name,
                    metric_type="p99_latency_ms",
                    lookback_minutes=15,
                )
                runbook_results = search_runbooks_vertex_ai(
                    query=input_check.sanitized_text,
                    service_name=service_name,
                    top_k=2,
                )
                tool_trajectory.append("search_runbooks_vertex_ai")

            if error_metrics.get("status") == "error":
                return {
                    "status": "tool_error_recovered",
                    "routed_model": route_decision.selected_model,
                    "tool_trajectory": tool_trajectory,
                    "error_recovery": error_metrics,
                }

            # Determine severity based on constitutional SLO thresholds
            err_val = float(error_metrics.get("current_value", 0.0))
            lat_val = float(latency_metrics.get("current_value", 0.0))
            if err_val > 5.0 or lat_val > 1000.0:
                severity = "P0"
            elif err_val > 2.5 or lat_val > 500.0:
                severity = "P1"
            else:
                severity = "P2"

            matches = runbook_results.get("matches", [])
            target_revision = (
                matches[0].get("last_known_good_revision", "rev-2026-10-01-stable")
                if matches
                else "rev-2026-10-01-stable"
            )

            # Step 5: Remediation Planner (Create Critical Bug + Execute HITL Remediation)
            with default_tracer.start_span("agent.remediation_planner_agent"):
                bug_result = create_critical_bug(
                    service_name=service_name,
                    severity=severity,
                    title=f"{severity} SLO breach on {service_name}: error_rate={err_val}%, p99={lat_val}ms",
                    reproduction_steps=[
                        f"Query error_rate on {service_name} (observed {err_val}% vs 1.0% SLO)",
                        f"Query p99_latency_ms on {service_name} (observed {lat_val}ms vs 250.0ms SLO)",
                    ],
                    impacted_slo="error_rate_and_p99_latency_slo",
                    human_confirmed=human_confirmed,
                )
                tool_trajectory.append("create_critical_bug")

                remediation_result = execute_production_remediation(
                    service_name=service_name,
                    remediation_action="rollback_revision",
                    target_revision=target_revision,
                    human_approval_token=human_approval_token,
                )
                tool_trajectory.append("execute_production_remediation")

                memory_task = persist_incident_postmortem_memory(
                    session_id=session_id,
                    service_name=service_name,
                    incident_summary=f"{severity} incident on {service_name} (error_rate={err_val}%)",
                    resolution_notes=f"Target revision {target_revision}; status={remediation_result['status']}",
                )
                tool_trajectory.append("persist_incident_postmortem_memory")

            # Step 6: Self-Evaluation Critic & Structured Report Generation
            with default_tracer.start_span("agent.self_eval_critic_agent"):
                report = IncidentTriageReport.model_validate(
                    {
                        "incident_summary": (
                            f"Detected {severity} SLO breach on {service_name} "
                            f"(error_rate={err_val}%, p99_latency_ms={lat_val}ms)."
                        ),
                        "severity": severity,
                        "root_cause_hypothesis": (
                            f"Correlated with runbook {matches[0]['runbook_id'] if matches else 'RB-DEFAULT'}: "
                            f"{matches[0]['title'] if matches else 'Service degradation'}."
                        ),
                        "recommended_remediation": (
                            f"rollback_revision to {target_revision} "
                            f"(execution status: {remediation_result['status']})."
                        ),
                        "requires_human_approval": not bool(
                            remediation_result.get("human_token_verified", False)
                        ),
                        "bug_id": str(bug_result.get("bug_id", "")),
                    }
                ).model_dump()

                self_eval = self.plugin.evaluate_output_self_eval_guardrail(
                    report["incident_summary"],
                    evidence_context=remediation_result,
                )

            self.session_store.save_session_turn(
                session_id=session_id,
                user_id=user_id,
                role="assistant",
                content=report["incident_summary"],
                state_updates={"last_report": report},
            )

            default_logger.info(
                f"Completed incident triage workflow for '{service_name}'",
                extra={
                    "event_type": "INCIDENT_WORKFLOW_COMPLETED",
                    "session_id": session_id,
                    "metadata": {"severity": severity, "bug_id": report["bug_id"]},
                },
            )

            return {
                "status": "ok",
                "routed_model": route_decision.selected_model,
                "routing_reason": route_decision.routing_reason,
                "compaction": compaction_result,
                "telemetry": {"error_rate": error_metrics, "p99_latency_ms": latency_metrics},
                "runbooks": runbook_results,
                "bug": bug_result,
                "remediation": remediation_result,
                "async_memory_task": memory_task,
                "self_evaluation": self_eval.to_dict(),
                "report": report,
                "tool_trajectory": tool_trajectory,
            }
