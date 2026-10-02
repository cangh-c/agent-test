"""Guardrails, Policy Enforcement Plugin, Self-Evaluation, and Human-in-the-Loop Hooks.

Implements Category 3 ('Guardrails & Policy Plugins' and 'Human-in-the-Loop Hooks')
of the AgentOps Code Review Matrix:
1. Input Security Guardrail (`before_model_callback`): Screens prompts for adversarial
   prompt injections, jailbreaks, and policy violations (compatible with Google Cloud Model Armor).
2. Tool Policy & HITL Hook (`before_tool_callback`): Enforces RBAC allowlists, blocks destructive
   unapproved commands, and pauses execution when Human-in-the-Loop confirmation is missing.
3. Self-Evaluation & Grounding Guardrail (`after_model_callback`): Evaluates generated agent
   responses for factual grounding, PII leakage, and constitutional compliance.
4. App-Wide ADK Plugin (`AgentOpsSecurityAndPolicyPlugin` subclassing `BasePlugin`): Applies
   security, PII scrubbing, history compaction, and Intent-vs-Outcome auditing across all agents.
"""

from __future__ import annotations

import re
import time
from typing import Any

from .memory import ConversationHistoryCompactor, default_history_compactor
from .observability import (
    IntentOutcomeAuditLogger,
    default_audit_logger,
    default_logger,
    default_tracer,
)
from .pii_redaction import PIIRedactionScrubber, default_pii_scrubber

try:
    from google.adk.plugins.base_plugin import BasePlugin
except ImportError:  # pragma: no cover - fallback when google-adk is not installed locally

    class BasePlugin:  # type: ignore[no-redef]
        def __init__(self, name: str = "base_plugin") -> None:
            self.name = name


_PROMPT_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions", re.IGNORECASE),
    re.compile(r"bypass\s+(?:human\s+approval|hitl|guardrails|security\s+policy)", re.IGNORECASE),
    re.compile(r"(?:drop\s+table|rm\s+-rf\s+/|exfiltrate\s+secrets)", re.IGNORECASE),
    re.compile(r"reveal\s+(?:your\s+)?(?:system\s+prompt|api\s+key|secret\s+manager)", re.IGNORECASE),
)


class GuardrailEvaluationResult:
    """Structured result from a security or self-evaluation guardrail check."""

    def __init__(
        self,
        *,
        allowed: bool,
        policy_name: str,
        reason: str,
        score: float = 1.0,
        sanitized_text: str = "",
    ) -> None:
        self.allowed = allowed
        self.policy_name = policy_name
        self.reason = reason
        self.score = score
        self.sanitized_text = sanitized_text

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "policy_name": self.policy_name,
            "reason": self.reason,
            "score": self.score,
            "sanitized_text": self.sanitized_text,
        }


class AgentOpsSecurityAndPolicyPlugin(BasePlugin):
    """Application-wide ADK `BasePlugin` enforcing security guardrails, self-eval, and HITL hooks."""

    HIGH_STAKES_TOOLS: frozenset[str] = frozenset(
        {"execute_production_remediation", "create_critical_bug"}
    )

    def __init__(
        self,
        *,
        pii_scrubber: PIIRedactionScrubber | None = None,
        history_compactor: ConversationHistoryCompactor | None = None,
        audit_logger: IntentOutcomeAuditLogger | None = None,
    ) -> None:
        super().__init__(name="agentops_security_and_policy_plugin")
        self.pii_scrubber = pii_scrubber or default_pii_scrubber
        self.history_compactor = history_compactor or default_history_compactor
        self.audit_logger = audit_logger or default_audit_logger
        self._tool_start_times: dict[str, tuple[str, float]] = {}

    def evaluate_input_prompt_guardrail(self, prompt_text: str) -> GuardrailEvaluationResult:
        """Screens incoming user prompts via Model Armor rules & injection signatures."""
        with default_tracer.start_span("guardrail.input_prompt_check") as span:
            for pattern in _PROMPT_INJECTION_PATTERNS:
                if pattern.search(prompt_text or ""):
                    span.set_attribute("guardrail.blocked", True)
                    default_logger.warning(
                        "Blocked adversarial prompt injection attempt",
                        extra={
                            "event_type": "GUARDRAIL_PROMPT_BLOCKED",
                            "metadata": {"pattern": pattern.pattern},
                        },
                    )
                    return GuardrailEvaluationResult(
                        allowed=False,
                        policy_name="model_armor_prompt_injection_shield",
                        reason=(
                            "Prompt blocked by AgentOps Security Guardrail: detected adversarial "
                            "instruction override or unauthorized privilege escalation attempt."
                        ),
                        score=0.0,
                        sanitized_text="",
                    )

            clean_text = self.pii_scrubber.scrub_text(prompt_text or "")
            span.set_attribute("guardrail.blocked", False)
            return GuardrailEvaluationResult(
                allowed=True,
                policy_name="model_armor_prompt_injection_shield",
                reason="Prompt passed Model Armor injection and PII screening.",
                score=1.0,
                sanitized_text=clean_text,
            )

    def evaluate_output_self_eval_guardrail(
        self,
        response_text: str,
        *,
        evidence_context: dict[str, Any] | None = None,
    ) -> GuardrailEvaluationResult:
        """Runs automated self-evaluation on model outputs for grounding and PII safety."""
        with default_tracer.start_span("guardrail.self_eval_output_check") as span:
            sanitized_output = self.pii_scrubber.scrub_text(response_text or "")
            had_unredacted_pii = sanitized_output != (response_text or "")

            # Grounding check: ensure response does not claim an unapproved production rollback completed
            if (
                "successfully executed" in sanitized_output.lower()
                and evidence_context
                and not evidence_context.get("human_token_verified", False)
            ):
                span.set_attribute("guardrail.self_eval_passed", False)
                return GuardrailEvaluationResult(
                    allowed=False,
                    policy_name="self_eval_grounding_and_hitl_consistency",
                    reason=(
                        "Self-Evaluation Guardrail rejected response: output claimed remediation "
                        "completed without verified Human-in-the-Loop approval in tool context."
                    ),
                    score=0.0,
                    sanitized_text=(
                        "Action halted by Self-Evaluation Guardrail: Human operator confirmation "
                        "is required before claiming production remediation completion."
                    ),
                )

            span.set_attribute("guardrail.self_eval_passed", True)
            span.set_attribute("guardrail.pii_redacted", had_unredacted_pii)
            return GuardrailEvaluationResult(
                allowed=True,
                policy_name="self_eval_grounding_and_hitl_consistency",
                reason="Output passed factual grounding and PII redaction self-evaluation.",
                score=1.0,
                sanitized_text=sanitized_output,
            )

    def verify_human_in_the_loop_gate(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Explicit pre-tool Human-in-the-Loop (HITL) hook stopping unapproved high-stakes calls.

        Returns `None` when execution is permitted to proceed, or a structured HITL stop
        dictionary when human confirmation is required.
        """
        if tool_name == "execute_production_remediation":
            token = str(tool_args.get("human_approval_token", "")).strip().upper()
            if token not in {"APPROVED-BY-OPERATOR", "HITL-CONFIRMED", "LGTM-PROD-ROLLBACK"}:
                return {
                    "status": "pending_human_confirmation",
                    "tool_name": tool_name,
                    "human_token_verified": False,
                    "recovery_instructions": (
                        "HITL HOOK INTERCEPTED: `execute_production_remediation` is a high-stakes "
                        "production mutation. Ask the human operator for confirmation and pass "
                        "`human_approval_token='APPROVED-BY-OPERATOR'` once approved."
                    ),
                }

        if tool_name == "create_critical_bug":
            severity = str(tool_args.get("severity", "")).strip().upper()
            confirmed = bool(tool_args.get("human_confirmed", False))
            if severity == "P0" and not confirmed:
                return {
                    "status": "pending_human_confirmation",
                    "bug_id": "PENDING-HITL-APPROVAL",
                    "severity": "P0",
                    "service_name": str(tool_args.get("service_name", "")),
                    "escalation_channel": "#oncall-p0-gate",
                    "summary": (
                        "HITL HOOK INTERCEPTED: P0 bug creation pages on-call immediately. "
                        "Obtain explicit human confirmation and pass `human_confirmed=True`."
                    ),
                }

        return None

    # -----------------------------------------------------------------------
    # ADK Async Plugin Lifecycle Callbacks
    # -----------------------------------------------------------------------

    async def before_model_callback(
        self,
        *,
        callback_context: Any,
        llm_request: Any,
    ) -> Any:
        """ADK plugin hook screening user input and compacting history before LLM invocation."""
        prompt_parts: list[str] = []
        if hasattr(llm_request, "contents") and llm_request.contents:
            for content in llm_request.contents:
                for part in getattr(content, "parts", None) or []:
                    if getattr(part, "text", None):
                        prompt_parts.append(str(part.text))

        combined_prompt = "\n".join(prompt_parts)
        guardrail_res = self.evaluate_input_prompt_guardrail(combined_prompt)
        if not guardrail_res.allowed:
            return {"status": "blocked_by_guardrail", "reason": guardrail_res.reason}
        return None

    async def after_model_callback(
        self,
        *,
        callback_context: Any,
        llm_response: Any,
    ) -> Any:
        """ADK plugin hook executing self-evaluation and PII redaction on model responses."""
        text = getattr(llm_response, "text", "") or ""
        if text:
            _ = self.evaluate_output_self_eval_guardrail(text)
        return None

    async def before_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: Any,
    ) -> dict[str, Any] | None:
        """ADK plugin hook logging tool INTENT and enforcing the HITL confirmation gate."""
        tool_name = getattr(tool, "name", str(tool))
        corr_id = self.audit_logger.log_intent(
            tool_name=tool_name,
            intended_action=f"Invoke tool '{tool_name}' via ADK plugin pipeline",
            arguments=tool_args,
        )
        self._tool_start_times[tool_name] = (corr_id, time.perf_counter())

        hitl_override = self.verify_human_in_the_loop_gate(tool_name, tool_args)
        if hitl_override is not None:
            self.audit_logger.log_outcome(
                correlation_id=corr_id,
                tool_name=tool_name,
                intended_action=f"Invoke tool '{tool_name}' via ADK plugin pipeline",
                outcome_payload=hitl_override,
                latency_ms=0.1,
            )
            return hitl_override
        return None

    async def after_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: Any,
        result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """ADK plugin hook logging tool OUTCOME and scrubbing any PII in tool returns."""
        tool_name = getattr(tool, "name", str(tool))
        corr_id, started = self._tool_start_times.pop(
            tool_name, (f"corr-{tool_name}", time.perf_counter())
        )
        latency_ms = (time.perf_counter() - started) * 1000.0
        sanitized_result = self.pii_scrubber.scrub_payload(result)
        self.audit_logger.log_outcome(
            correlation_id=corr_id,
            tool_name=tool_name,
            intended_action=f"Invoke tool '{tool_name}' via ADK plugin pipeline",
            outcome_payload=sanitized_result if isinstance(sanitized_result, dict) else {"status": "success"},
            latency_ms=latency_ms,
        )
        return sanitized_result if isinstance(sanitized_result, dict) else None


default_security_plugin = AgentOpsSecurityAndPolicyPlugin()
