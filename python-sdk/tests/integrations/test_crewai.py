"""Tests for the CrewAI xProof integration."""

import json
from unittest.mock import MagicMock

import pytest
from xproof.integrations.crewai import XProofCrewCallback, XProofTool


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.certify_hash.return_value = MagicMock(
        id="proof-crew",
        file_hash="h",
        transaction_hash="tx-crew",
    )
    return client


class TestXProofTool:
    def test_certifies_text_input(self, mock_client):
        tool = XProofTool(client=mock_client, agent_name="researcher")
        result = tool._run("This is my research output")
        mock_client.certify_hash.assert_called_once()

        call_kwargs = mock_client.certify_hash.call_args.kwargs
        assert call_kwargs["author"] == "researcher"
        assert call_kwargs["who"] == "researcher"

        parsed = json.loads(result)
        assert parsed["status"] == "certified"
        assert parsed["proof_id"] == "proof-crew"

    def test_certifies_json_input(self, mock_client):
        tool = XProofTool(client=mock_client, agent_name="writer")
        input_data = json.dumps({
            "content": "Article draft",
            "file_name": "article.md",
        })
        tool._run(input_data)

        call_kwargs = mock_client.certify_hash.call_args.kwargs
        assert call_kwargs["file_name"] == "article.md"


class TestXProofCrewCallback:
    def test_task_complete(self, mock_client):
        cb = XProofCrewCallback(client=mock_client, crew_name="test-crew")
        result = cb.on_task_complete(
            agent_role="researcher",
            task_description="Research market trends",
            output="Market analysis: ...",
        )

        mock_client.certify_hash.assert_called_once()
        call_kwargs = mock_client.certify_hash.call_args.kwargs

        assert call_kwargs["author"] == "researcher"
        assert call_kwargs["who"] == "researcher"
        assert call_kwargs["why"] == "Research market trends"
        assert call_kwargs["metadata"]["framework"] == "crewai"
        assert call_kwargs["metadata"]["crew_name"] == "test-crew"

        assert result["agent_role"] == "researcher"
        assert result["proof_id"] == "proof-crew"
        assert len(cb.certifications) == 1

    def test_crew_complete(self, mock_client):
        cb = XProofCrewCallback(client=mock_client, crew_name="analysis-crew")

        cb.on_task_complete("researcher", "Research", "findings")
        cb.on_task_complete("writer", "Write report", "report text")

        assert len(cb.certifications) == 2

        result = cb.on_crew_complete(
            crew_name="analysis-crew",
            goal="Produce quarterly analysis",
            results={"summary": "Q1 looks good"},
        )

        assert mock_client.certify_hash.call_count == 3
        last_call = mock_client.certify_hash.call_args.kwargs
        assert last_call["who"] == "analysis-crew"
        assert last_call["why"] == "Produce quarterly analysis"
        assert last_call["metadata"]["task_count"] == 2

        assert result["tasks_certified"] == 2
        assert result["crew_name"] == "analysis-crew"

    def test_4w_metadata(self, mock_client):
        cb = XProofCrewCallback(client=mock_client, crew_name="test-crew")
        cb.on_task_complete("agent-x", "Do thing", "output")

        call_kwargs = mock_client.certify_hash.call_args.kwargs
        assert "who" in call_kwargs
        assert "what" in call_kwargs
        assert "when" in call_kwargs
        assert "why" in call_kwargs
        assert call_kwargs["metadata"]["agent_role"] == "agent-x"

    def test_task_output_hash_matches_what(self, mock_client):
        import hashlib
        cb = XProofCrewCallback(client=mock_client, crew_name="test-crew")
        output = "My research findings"
        cb.on_task_complete("researcher", "Research task", output)

        call_kwargs = mock_client.certify_hash.call_args.kwargs
        expected_hash = hashlib.sha256(
            json.dumps(output, sort_keys=True, default=str).encode()
        ).hexdigest()
        assert call_kwargs["file_hash"] == expected_hash
        assert call_kwargs["what"] == expected_hash

    def test_crew_complete_includes_task_proof_ids(self, mock_client):
        cb = XProofCrewCallback(client=mock_client, crew_name="audit-crew")
        cb.on_task_complete("agent-a", "Task A", "output-a")
        cb.on_task_complete("agent-b", "Task B", "output-b")

        result = cb.on_crew_complete("audit-crew", "Full audit", {"done": True})
        last_call = mock_client.certify_hash.call_args.kwargs
        assert last_call["metadata"]["task_proof_ids"] == ["proof-crew", "proof-crew"]
        assert last_call["metadata"]["task_count"] == 2
        assert result["tasks_certified"] == 2
