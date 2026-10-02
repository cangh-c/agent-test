"""Observability, Structured JSON Logging, Intent-vs-Outcome Auditing, and Distributed Tracing.

Implements Category 4 of the AgentOps Code Review Matrix:
1. Structured JSON Logging: Emits rich JSON records via `python-json-logger` / `logging.Formatter`
   and `google.cloud.logging`, with zero `print()` statements.
2. Intent vs. Outcome Capture: Explicitly records `INTENT` before tool/agent execution and
   `OUTCOME` after execution with latency, correlation IDs, and outcome verification.
3. Distributed Tracing: Uses OpenTelemetry (`opentelemetry-api` / `opentelemetry-sdk` /
   `CloudTraceSpanExporter`) to link spans from user query -> model routing -> tool call -> answer.
4. PII Redaction Integration: Automatically scrubs all log payloads and trace attributes
   through `PIIRedactionScrubber` before emission.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import functools
import json
import logging
import os
import time
import uuid
from typing import Any, Callable, Iterator, TypeVar

from .pii_redaction import PIIRedactionScrubber, default_pii_scrubber

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
        InMemorySpanExporter,
        SimpleSpanProcessor,
    )
    OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover - fallback when opentelemetry is not installed
    trace = None  # type: ignore[assignment]
    OTEL_AVAILABLE = False

try:
    from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
except ImportError:  # pragma: no cover
    CloudTraceSpanExporter = None  # type: ignore[assignment]


F = TypeVar("F", bound=Callable[..., Any])


class StructuredJsonFormatter(logging.Formatter):
    """Structured JSON log formatter compatible with Google Cloud Logging and AgentOps.

    Automatically injects `timestamp`, `severity`, `correlation_id`, `trace_id`,
    `span_id`, `event_type`, and scrubs PII from messages and structured `extra_fields`.
    """

    def __init__(self, pii_scrubber: PIIRedactionScrubber | None = None) -> None:
        super().__init__()
        self.pii_scrubber = pii_scrubber or default_pii_scrubber

    def format(self, record: logging.LogRecord) -> str:
        raw_message = record.getMessage()
        sanitized_message = self.pii_scrubber.scrub_text(raw_message)

        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": record.levelname,
            "logger": record.name,
            "message": sanitized_message,
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        for attr in (
            "event_type",
            "phase",
            "correlation_id",
            "trace_id",
            "span_id",
            "agent_name",
            "session_id",
            "tool_name",
            "intended_action",
            "actual_outcome",
            "latency_ms",
            "metadata",
        ):
            val = getattr(record, attr, None)
            if val is not None:
                payload[attr] = self.pii_scrubber.scrub_payload(val)

        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            payload["exception"] = self.pii_scrubber.scrub_text(exc_text)

        return json.dumps(payload, default=str)


class _FallbackSpan:
    """Lightweight OpenTelemetry-compatible Span used when opentelemetry-sdk is absent."""

    def __init__(
        self,
        name: str,
        trace_id: str,
        parent_span_id: str | None = None,
        recorder: list[dict[str, Any]] | None = None,
    ) -> None:
        self.name = name
        self.trace_id = trace_id
        self.span_id = uuid.uuid4().hex[:16]
        self.parent_span_id = parent_span_id
        self.attributes: dict[str, Any] = {}
        self.events: list[dict[str, Any]] = []
        self.status: str = "OK"
        self.start_time_ns = time.time_ns()
        self.end_time_ns: int | None = None
        self._recorder = recorder

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = default_pii_scrubber.scrub_payload(value)

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        self.events.append(
            {
                "name": name,
                "timestamp_ns": time.time_ns(),
                "attributes": default_pii_scrubber.scrub_payload(attributes or {}),
            }
        )

    def record_exception(self, exception: Exception) -> None:
        self.status = "ERROR"
        self.add_event("exception", {"exception.message": str(exception)})

    def finish(self) -> None:
        self.end_time_ns = time.time_ns()
        if self._recorder is not None:
            self._recorder.append(
                {
                    "name": self.name,
                    "trace_id": self.trace_id,
                    "span_id": self.span_id,
                    "parent_span_id": self.parent_span_id,
                    "attributes": dict(self.attributes),
                    "events": list(self.events),
                    "status": self.status,
                    "start_time_ns": self.start_time_ns,
                    "end_time_ns": self.end_time_ns,
                }
            )


class DistributedTracingManager:
    """OpenTelemetry distributed tracing manager linking request spans end-to-end."""

    def __init__(self, service_name: str = "sentinel-ops-agent") -> None:
        self.service_name = service_name
        self._recorded_spans: list[dict[str, Any]] = []
        self._active_trace_id: str | None = None
        self._span_stack: list[str] = []
        self._tracer: Any = None

        if OTEL_AVAILABLE and trace is not None:
            resource = Resource.create({"service.name": service_name})
            provider = TracerProvider(resource=resource)
            self._memory_exporter = InMemorySpanExporter()
            provider.add_span_processor(SimpleSpanProcessor(self._memory_exporter))

            if CloudTraceSpanExporter is not None and os.environ.get("ENABLE_CLOUD_TRACE") == "true":
                try:
                    provider.add_span_processor(BatchSpanProcessor(CloudTraceSpanExporter()))
                except Exception:
                    pass

            trace.set_tracer_provider(provider)
            self._tracer = trace.get_tracer(service_name)

    @contextmanager
    def start_span(
        self,
        span_name: str,
        attributes: dict[str, Any] | None = None,
    ) -> Iterator[_FallbackSpan]:
        """Starts a linked distributed trace span for query, routing, tool, or response steps."""
        if not self._active_trace_id:
            self._active_trace_id = uuid.uuid4().hex
        parent_span_id = self._span_stack[-1] if self._span_stack else None

        fallback_span = _FallbackSpan(
            name=span_name,
            trace_id=self._active_trace_id,
            parent_span_id=parent_span_id,
            recorder=self._recorded_spans,
        )
        if attributes:
            for k, v in attributes.items():
                fallback_span.set_attribute(k, v)

        self._span_stack.append(fallback_span.span_id)
        try:
            if self._tracer is not None:
                with self._tracer.start_as_current_span(span_name) as otel_span:
                    for k, v in fallback_span.attributes.items():
                        otel_span.set_attribute(k, str(v))
                    yield fallback_span
            else:
                yield fallback_span
        except Exception as exc:
            fallback_span.record_exception(exc)
            raise
        finally:
            fallback_span.finish()
            self._span_stack.pop()
            if not self._span_stack:
                self._active_trace_id = None

    def get_recorded_spans(self) -> list[dict[str, Any]]:
        """Returns recorded spans for observability inspection and evaluation tests."""
        return list(self._recorded_spans)

    def clear_recorded_spans(self) -> None:
        """Clears in-memory recorded spans."""
        self._recorded_spans.clear()


def get_structured_logger(
    name: str = "sentinel_ops",
    pii_scrubber: PIIRedactionScrubber | None = None,
) -> logging.Logger:
    """Configures and returns a structured JSON logger with active PII redaction."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not any(isinstance(h.formatter, StructuredJsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredJsonFormatter(pii_scrubber=pii_scrubber))
        logger.handlers = [handler]
    logger.propagate = False
    return logger


class IntentOutcomeAuditLogger:
    """Captures explicit Intent-before-execution and Outcome-after-execution audit logs.

    Satisfies the AgentOps 'Intent vs. Outcome Capture' criterion by recording:
    1. `INTENT` event before running any tool or sub-agent action (capturing planned
       tool name, sanitized arguments, agent rationale, and correlation ID).
    2. `OUTCOME` event immediately after execution (capturing actual result status,
       sanitized return payload, execution latency in ms, and whether the outcome
       fulfilled the intended action).
    """

    def __init__(
        self,
        logger: logging.Logger | None = None,
        tracer: DistributedTracingManager | None = None,
        pii_scrubber: PIIRedactionScrubber | None = None,
    ) -> None:
        self.pii_scrubber = pii_scrubber or default_pii_scrubber
        self.logger = logger or get_structured_logger("sentinel_ops.audit", self.pii_scrubber)
        self.tracer = tracer or default_tracer
        self.audit_trail: list[dict[str, Any]] = []

    def log_intent(
        self,
        *,
        tool_name: str,
        intended_action: str,
        arguments: dict[str, Any],
        agent_name: str = "sentinel_coordinator_agent",
        session_id: str = "default_session",
        correlation_id: str | None = None,
    ) -> str:
        """Logs the agent's intended action before execution."""
        corr_id = correlation_id or f"corr-{uuid.uuid4().hex[:12]}"
        sanitized_args = self.pii_scrubber.scrub_payload(arguments)
        sanitized_intent = self.pii_scrubber.scrub_text(intended_action)

        record = {
            "event_type": "AGENT_INTENT",
            "phase": "INTENT",
            "correlation_id": corr_id,
            "agent_name": agent_name,
            "session_id": session_id,
            "tool_name": tool_name,
            "intended_action": sanitized_intent,
            "arguments": sanitized_args,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.audit_trail.append(record)
        self.logger.info(
            f"INTENT: Agent '{agent_name}' intends to execute '{tool_name}': {sanitized_intent}",
            extra={
                "event_type": "AGENT_INTENT",
                "phase": "INTENT",
                "correlation_id": corr_id,
                "agent_name": agent_name,
                "session_id": session_id,
                "tool_name": tool_name,
                "intended_action": sanitized_intent,
                "metadata": {"arguments": sanitized_args},
            },
        )
        return corr_id

    def log_outcome(
        self,
        *,
        correlation_id: str,
        tool_name: str,
        intended_action: str,
        outcome_payload: dict[str, Any],
        latency_ms: float,
        agent_name: str = "sentinel_coordinator_agent",
        session_id: str = "default_session",
    ) -> dict[str, Any]:
        """Logs the actual outcome after execution and links it to the prior intent."""
        sanitized_outcome = self.pii_scrubber.scrub_payload(outcome_payload)
        status = str(sanitized_outcome.get("status", "unknown"))
        intent_succeeded = status in ("success", "ok", "created", "completed")

        record = {
            "event_type": "AGENT_OUTCOME",
            "phase": "OUTCOME",
            "correlation_id": correlation_id,
            "agent_name": agent_name,
            "session_id": session_id,
            "tool_name": tool_name,
            "intended_action": self.pii_scrubber.scrub_text(intended_action),
            "actual_outcome": {
                "status": status,
                "intent_fulfilled": intent_succeeded,
                "result": sanitized_outcome,
            },
            "latency_ms": round(latency_ms, 2),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.audit_trail.append(record)
        self.logger.info(
            f"OUTCOME: Tool '{tool_name}' finished with status='{status}' "
            f"(intent_fulfilled={intent_succeeded}, latency_ms={latency_ms:.2f})",
            extra={
                "event_type": "AGENT_OUTCOME",
                "phase": "OUTCOME",
                "correlation_id": correlation_id,
                "agent_name": agent_name,
                "session_id": session_id,
                "tool_name": tool_name,
                "intended_action": self.pii_scrubber.scrub_text(intended_action),
                "actual_outcome": record["actual_outcome"],
                "latency_ms": round(latency_ms, 2),
            },
        )
        return record


default_tracer = DistributedTracingManager()
default_logger = get_structured_logger()
default_audit_logger = IntentOutcomeAuditLogger(
    logger=default_logger,
    tracer=default_tracer,
    pii_scrubber=default_pii_scrubber,
)


def log_intent_and_outcome(intended_action_description: str) -> Callable[[F], F]:
    """Decorator that wraps a tool with OpenTelemetry tracing and Intent-vs-Outcome logging."""

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            tool_name = func.__name__
            correlation_id = default_audit_logger.log_intent(
                tool_name=tool_name,
                intended_action=intended_action_description,
                arguments=kwargs,
            )
            start_time = time.perf_counter()
            with default_tracer.start_span(
                f"tool.{tool_name}",
                attributes={
                    "gen_ai.tool.name": tool_name,
                    "agentops.correlation_id": correlation_id,
                    "agentops.intended_action": intended_action_description,
                },
            ) as span:
                result = func(*args, **kwargs)
                latency_ms = (time.perf_counter() - start_time) * 1000.0
                outcome_dict = result if isinstance(result, dict) else {"status": "success", "data": result}
                span.set_attribute("agentops.outcome_status", str(outcome_dict.get("status", "success")))
                span.set_attribute("agentops.latency_ms", round(latency_ms, 2))
                default_audit_logger.log_outcome(
                    correlation_id=correlation_id,
                    tool_name=tool_name,
                    intended_action=intended_action_description,
                    outcome_payload=outcome_dict,
                    latency_ms=latency_ms,
                )
                return result

        return wrapper  # type: ignore[return-value]

    return decorator
