"""CrewAI integration for automatic xProof certification."""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from crewai.tools import BaseTool as CrewAIBaseTool
except ImportError:
    CrewAIBaseTool = None

from ..client import XProofClient


def _hash_data(data: Any) -> str:
    serialized = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


class XProofTool:
    """CrewAI-compatible tool that lets agents certify their work products.

    Example::

        from xproof.integrations.crewai import XProofTool

        tool = XProofTool(api_key="pm_...")
        # Use in a CrewAI agent's tools list
    """

    name: str = "xproof_certify"
    description: str = (
        "Certify a piece of work on the blockchain. "
        "Input should be a JSON string with 'content' (the text to certify) "
        "and optionally 'file_name' (name for the certification)."
    )

    def __init__(
        self,
        api_key: str = "",
        client: Optional[XProofClient] = None,
        agent_name: str = "crewai-agent",
    ) -> None:
        self.client = client or XProofClient(api_key=api_key)
        self.agent_name = agent_name

    def _run(self, input_text: str) -> str:
        try:
            data = json.loads(input_text)
        except json.JSONDecodeError:
            data = {"content": input_text}

        content = data.get("content", input_text)
        file_name = data.get("file_name", "agent-output.json")

        content_hash = _hash_data(content)

        cert = self.client.certify_hash(
            file_hash=content_hash,
            file_name=file_name,
            author=self.agent_name,
            who=self.agent_name,
            what=content_hash,
            when=datetime.now(timezone.utc).isoformat(),
            why="CrewAI agent certification",
        )

        return json.dumps({
            "proof_id": cert.id,
            "file_hash": cert.file_hash,
            "transaction_hash": cert.transaction_hash,
            "status": "certified",
        })


if CrewAIBaseTool is not None:

    class XProofCrewTool(CrewAIBaseTool):
        """Native CrewAI BaseTool wrapper for xProof certification.

        Use this when CrewAI is installed and you want full framework integration.
        """

        name: str = "xproof_certify"
        description: str = (
            "Certify a piece of work on the blockchain for accountability. "
            "Input: JSON with 'content' and optional 'file_name'."
        )

        _xproof_tool: Any = None

        def __init__(self, api_key: str = "", agent_name: str = "crewai-agent", **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self._xproof_tool = XProofTool(api_key=api_key, agent_name=agent_name)

        def _run(self, input_text: str) -> str:
            return self._xproof_tool._run(input_text)


class XProofCrewCallback:
    """Callback that auto-certifies CrewAI task and crew completions.

    Attach to a crew to automatically certify each agent's task output
    with 4W metadata (WHO=agent role, WHAT=output hash, WHEN=timestamp,
    WHY=task description).

    Example::

        from xproof.integrations.crewai import XProofCrewCallback

        callback = XProofCrewCallback(api_key="pm_...")

        # Call after each task completes
        callback.on_task_complete(
            agent_role="researcher",
            task_description="Research Q1 earnings",
            output="The Q1 earnings report shows...",
        )

        # Call when the full crew finishes
        callback.on_crew_complete(
            crew_name="research-crew",
            goal="Produce quarterly analysis",
            results={"summary": "..."},
        )
    """

    def __init__(
        self,
        api_key: str = "",
        client: Optional[XProofClient] = None,
        crew_name: str = "crewai-crew",
    ) -> None:
        self.client = client or XProofClient(api_key=api_key)
        self.crew_name = crew_name
        self.certifications: List[Dict[str, Any]] = []

    def on_task_complete(
        self,
        agent_role: str,
        task_description: str,
        output: Any,
    ) -> Dict[str, Any]:
        """Certify a completed task's output."""
        output_hash = _hash_data(output)
        cert = self.client.certify_hash(
            file_hash=output_hash,
            file_name=f"task-{agent_role}.json",
            author=agent_role,
            who=agent_role,
            what=output_hash,
            when=datetime.now(timezone.utc).isoformat(),
            why=task_description,
            metadata={
                "framework": "crewai",
                "crew_name": self.crew_name,
                "agent_role": agent_role,
                "task_description": task_description,
            },
        )

        record = {
            "agent_role": agent_role,
            "task_description": task_description,
            "proof_id": cert.id,
            "file_hash": cert.file_hash,
            "transaction_hash": cert.transaction_hash,
        }
        self.certifications.append(record)
        return record

    def on_crew_complete(
        self,
        crew_name: str,
        goal: str,
        results: Any,
    ) -> Dict[str, Any]:
        """Certify the complete crew execution."""
        results_hash = _hash_data({
            "crew_name": crew_name,
            "goal": goal,
            "results": results,
            "task_certifications": [c["proof_id"] for c in self.certifications],
        })

        cert = self.client.certify_hash(
            file_hash=results_hash,
            file_name=f"crew-{crew_name}-complete.json",
            author=crew_name,
            who=crew_name,
            what=results_hash,
            when=datetime.now(timezone.utc).isoformat(),
            why=goal,
            metadata={
                "framework": "crewai",
                "crew_name": crew_name,
                "goal": goal,
                "task_count": len(self.certifications),
                "task_proof_ids": [c["proof_id"] for c in self.certifications],
            },
        )

        return {
            "crew_name": crew_name,
            "proof_id": cert.id,
            "file_hash": cert.file_hash,
            "transaction_hash": cert.transaction_hash,
            "tasks_certified": len(self.certifications),
        }
