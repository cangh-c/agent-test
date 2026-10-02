"""SentinelOps: Enterprise Incident & Bug Triage Multi-Agent System.

Built on the Google Agent Development Kit (ADK) and Gemini Enterprise Agent Platform (GEAP),
implementing all 19 AgentOps Code Review Matrix engineering standards across:
1. Tool & Interface Design
2. Context & Memory
3. Orchestration & Logic
4. Observability & Tracing
5. Infrastructure & CI/CD
"""

from .agent import app, root_agent, sentinel_coordinator_agent

__all__ = [
    "app",
    "root_agent",
    "sentinel_coordinator_agent",
]
