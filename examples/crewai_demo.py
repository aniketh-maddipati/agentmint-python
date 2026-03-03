#!/usr/bin/env python3
"""
AgentMint + CrewAI Demo

Shows how authorization receipts flow through a multi-agent system.
Run: python examples/crewai_demo.py
"""

import time
from agentmint import AgentMint, DelegationStatus

# Simulated agent functions (replace with real CrewAI agents)
def researcher_agent(query: str) -> str:
    return f"Research results for: {query}"

def writer_agent(content: str) -> str:
    return f"Polished article about: {content}"

def publisher_agent(article: str) -> str:
    return f"Published: {article[:50]}..."


def main():
    print("\n" + "="*60)
    print("  AgentMint + CrewAI Demo")
    print("  Cryptographic proof of human authorization")
    print("="*60 + "\n")

    # Initialize
    mint = AgentMint()
    
    print("─"*60)
    print("STEP 1: Human approves a content pipeline")
    print("─"*60)
    time.sleep(0.5)
    
    # Human approves a plan
    plan = mint.issue_plan(
        action="content:pipeline",
        user="editor@news.co",
        scope=["research:*", "write:*", "publish:draft"],
        delegates_to=["researcher", "writer", "publisher"],
        requires_checkpoint=["publish:live"],  # Needs human approval
        max_depth=3,
    )
    print(f"   Plan scope: research:*, write:*, publish:draft")
    print(f"   Checkpoint: publish:live requires human approval\n")
    time.sleep(0.5)

    print("─"*60)
    print("STEP 2: Researcher agent requests authorization")
    print("─"*60)
    time.sleep(0.5)
    
    result = mint.delegate(plan, "researcher", "research:web")
    if result.ok:
        output = researcher_agent("AI agents 2025")
        print(f"   Output: {output}\n")
    time.sleep(0.5)

    print("─"*60)
    print("STEP 3: Writer agent requests authorization")
    print("─"*60)
    time.sleep(0.5)
    
    result = mint.delegate(plan, "writer", "write:article")
    if result.ok:
        output = writer_agent("AI agents in 2025")
        print(f"   Output: {output}\n")
    time.sleep(0.5)

    print("─"*60)
    print("STEP 4: Publisher tries to publish draft (allowed)")
    print("─"*60)
    time.sleep(0.5)
    
    result = mint.delegate(plan, "publisher", "publish:draft")
    if result.ok:
        output = publisher_agent("AI Agents Are Changing Everything...")
        print(f"   Output: {output}\n")
    time.sleep(0.5)

    print("─"*60)
    print("STEP 5: Publisher tries to go live (CHECKPOINT)")
    print("─"*60)
    time.sleep(0.5)
    
    result = mint.delegate(plan, "publisher", "publish:live")
    if result.status == DelegationStatus.CHECKPOINT:
        print("   ⚠ Action paused - human must approve publish:live\n")
    time.sleep(0.5)

    print("─"*60)
    print("STEP 6: Rogue agent tries to access (DENIED)")
    print("─"*60)
    time.sleep(0.5)
    
    result = mint.delegate(plan, "rogue-agent", "research:secrets")
    if result.denied:
        print(f"   Reason: {result.reason}\n")
    time.sleep(0.5)

    print("─"*60)
    print("STEP 7: Audit trail")
    print("─"*60)
    
    # Get a delegated receipt for audit
    delegated = mint.delegate(plan, "researcher", "research:audit")
    if delegated.ok:
        chain = mint.audit(delegated.receipt)
        print("   Authorization chain:")
        for i, r in enumerate(chain):
            indent = "   " + "  "*i
            print(f"{indent}└─ {r.sub} → {r.action}")
    
    print("\n" + "="*60)
    print("  ✓ Demo complete")
    print("  Every action is cryptographically signed & traceable")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
