"""CrewAI + xProof integration example.

Demonstrates a 3-agent crew (researcher, writer, reviewer) where each
agent's contribution is independently verifiable via xProof.

Usage:
    pip install xproof
    python crewai_example.py

Note: This example uses XProofCrewCallback directly (no CrewAI dependency
required to run the demo). In a real CrewAI setup, hook on_task_complete
into CrewAI's task lifecycle.
"""

from xproof import XProofClient
from xproof.integrations.crewai import XProofTool, XProofCrewCallback


def main():
    client = XProofClient.register("crewai-demo")
    print(f"Registered with trial key: {client.registration.api_key[:12]}...")
    print(f"Trial certifications remaining: {client.registration.trial.remaining}")
    print()

    callback = XProofCrewCallback(client=client, crew_name="research-crew")

    print("--- Agent 1: Researcher ---")
    research_output = "Q1 revenue grew 15% YoY driven by AI product adoption."
    task1 = callback.on_task_complete(
        agent_role="researcher",
        task_description="Research Q1 earnings data",
        output=research_output,
    )
    print(f"  Proof ID: {task1['proof_id']}")
    print(f"  Hash:     {task1['file_hash'][:16]}...")
    print()

    print("--- Agent 2: Writer ---")
    writer_output = "Executive Summary: Strong Q1 with 15% revenue growth..."
    task2 = callback.on_task_complete(
        agent_role="writer",
        task_description="Write executive summary from research",
        output=writer_output,
    )
    print(f"  Proof ID: {task2['proof_id']}")
    print(f"  Hash:     {task2['file_hash'][:16]}...")
    print()

    print("--- Agent 3: Reviewer ---")
    reviewer_output = "Review complete. Report is accurate and well-structured."
    task3 = callback.on_task_complete(
        agent_role="reviewer",
        task_description="Review and approve the executive summary",
        output=reviewer_output,
    )
    print(f"  Proof ID: {task3['proof_id']}")
    print(f"  Hash:     {task3['file_hash'][:16]}...")
    print()

    print("--- Crew Complete ---")
    crew_result = callback.on_crew_complete(
        crew_name="research-crew",
        goal="Produce quarterly earnings analysis",
        results={
            "research": research_output,
            "summary": writer_output,
            "review": reviewer_output,
        },
    )
    print(f"  Crew Proof ID: {crew_result['proof_id']}")
    print(f"  Tasks certified: {crew_result['tasks_certified']}")
    print()

    print("--- Verification ---")
    for cert in callback.certifications:
        verified = client.verify(cert["proof_id"])
        print(f"  {cert['agent_role']}: verified={verified.id == cert['proof_id']}")

    print()
    print("All agent contributions are independently verifiable on-chain.")


if __name__ == "__main__":
    main()
