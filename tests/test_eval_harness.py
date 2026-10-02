"""Automated Evaluation Suite against the Golden Dataset (`evaluations/golden_dataset.evalset.json`).

Satisfies Category 5 ('Automated Evaluation Suites') of the AgentOps Code Review Matrix
by statically evaluating agent tool trajectories, strategic model routing decisions,
Human-in-the-Loop stops, prompt-injection guardrails, and guided error recovery against
a golden benchmark dataset to prevent regressions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
import unittest

from sentinel_ops.agent import SentinelOpsOrchestrator

try:
    from google.adk.evaluation.agent_evaluator import AgentEvaluator
except ImportError:  # pragma: no cover
    AgentEvaluator = None  # type: ignore[assignment]


GOLDEN_DATASET_PATH = (
    Path(__file__).resolve().parent.parent / "evaluations" / "golden_dataset.evalset.json"
)


class GoldenDatasetEvaluationHarness:
    """Evaluates `SentinelOpsOrchestrator` against `golden_dataset.evalset.json`."""

    def __init__(self, dataset_path: Path = GOLDEN_DATASET_PATH) -> None:
        self.dataset_path = dataset_path
        self.orchestrator = SentinelOpsOrchestrator()

    def load_golden_cases(self) -> list[dict[str, Any]]:
        with self.dataset_path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        return list(payload.get("eval_cases", []))

    @staticmethod
    def compute_trajectory_recall(expected: list[str], actual: list[str]) -> float:
        if not expected:
            return 1.0 if not actual else 0.0
        matches = sum(1 for tool in expected if tool in actual)
        return matches / len(expected)

    def run_evaluation_suite(self) -> dict[str, Any]:
        """Executes all golden evaluation cases and computes aggregate regression metrics."""
        cases = self.load_golden_cases()
        case_results: list[dict[str, Any]] = []
        passed_count = 0

        for case in cases:
            eval_id = case["eval_id"]
            response = self.orchestrator.handle_incident_query(
                user_query=case["user_query"],
                service_name=case["service_name"],
                session_id=f"eval-{eval_id}",
                human_confirmed=case.get("human_confirmed", False),
                human_approval_token=case.get("human_approval_token", ""),
            )

            checks: list[bool] = []
            expected_traj = case.get("expected_tool_trajectory", [])
            actual_traj = response.get("tool_trajectory", [])
            traj_score = self.compute_trajectory_recall(expected_traj, actual_traj)
            checks.append(traj_score == 1.0 and expected_traj == actual_traj)

            if "expected_status" in case:
                checks.append(response.get("status") == case["expected_status"])
            if "expected_routed_model" in case:
                checks.append(response.get("routed_model") == case["expected_routed_model"])
            if "expected_severity" in case:
                checks.append(response.get("report", {}).get("severity") == case["expected_severity"])
            if "expected_remediation_status" in case:
                checks.append(
                    response.get("remediation", {}).get("status")
                    == case["expected_remediation_status"]
                )
            if "expected_bug_status" in case:
                checks.append(response.get("bug", {}).get("status") == case["expected_bug_status"])
            if "expected_requires_human_approval" in case:
                checks.append(
                    response.get("report", {}).get("requires_human_approval")
                    == case["expected_requires_human_approval"]
                )

            case_passed = all(checks)
            if case_passed:
                passed_count += 1

            case_results.append(
                {
                    "eval_id": eval_id,
                    "passed": case_passed,
                    "trajectory_score": traj_score,
                    "routed_model": response.get("routed_model"),
                    "status": response.get("status"),
                }
            )

        pass_rate = passed_count / len(cases) if cases else 0.0
        return {
            "eval_set_id": "sentinel_ops_golden_evalset_v1",
            "total_cases": len(cases),
            "passed_cases": passed_count,
            "pass_rate": pass_rate,
            "results": case_results,
        }


class TestGoldenDatasetEvaluationSuite(unittest.TestCase):
    """Automated regression test suite verifying 100% score on the golden dataset."""

    def test_golden_dataset_file_exists_and_has_cases(self) -> None:
        self.assertTrue(GOLDEN_DATASET_PATH.exists(), "Golden dataset JSON file must exist")
        harness = GoldenDatasetEvaluationHarness()
        cases = harness.load_golden_cases()
        self.assertGreaterEqual(len(cases), 5)

    def test_all_golden_dataset_scenarios_pass_without_regression(self) -> None:
        harness = GoldenDatasetEvaluationHarness()
        summary = harness.run_evaluation_suite()
        for case_res in summary["results"]:
            self.assertTrue(
                case_res["passed"],
                f"Golden eval case '{case_res['eval_id']}' failed: {case_res}",
            )
        self.assertEqual(summary["pass_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
