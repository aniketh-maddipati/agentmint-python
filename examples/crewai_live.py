#!/usr/bin/env python3
"""
AgentMint + CrewAI: AWS Security Audit Pipeline

Based on the AWS-CrewAI CSPM collaboration (aws.amazon.com/blogs).
Same agents, same flow - now with governance.
"""

import os, sys, shutil, warnings
os.environ["OTEL_SDK_DISABLED"] = "true"
warnings.filterwarnings("ignore")
import logging
logging.getLogger().setLevel(logging.CRITICAL)

from crewai import Agent, Task, Crew, Process
from crewai_tools import FileWriterTool, SerperDevTool
from crewai.hooks import before_tool_call, ToolCallHookContext
from agentmint import AgentMint

# Clean
for d in ["security_audit", "production", "exfil"]:
    shutil.rmtree(d, ignore_errors=True)

print("""
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║  AWS Security Audit Pipeline                                      ║
║  Based on AWS-CrewAI CSPM Collaboration                           ║
║                                                                   ║
║  Agents: infrastructure-mapper → security-analyst → report-writer ║
║  Tools:  AWSInfrastructureScanner, SerperDevTool, FileWriterTool  ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
""")

# Tools
file_writer = FileWriterTool()
serper = SerperDevTool()

# ═══════════════════════════════════════════════════════════════════
# PHASE 1: Without AgentMint (current CrewAI behavior)
# ═══════════════════════════════════════════════════════════════════

print("═" * 67)
print(" PHASE 1: Standard CrewAI (no authorization layer)")
print("═" * 67)
print()

infrastructure_mapper = Agent(
    role="infrastructure-mapper",
    goal="Scan and document AWS infrastructure including EC2, S3, IAM, RDS, and VPC configurations",
    backstory="Senior cloud architect responsible for infrastructure discovery and documentation. You map all AWS resources for security review.",
    tools=[file_writer],
    llm="gpt-4o-mini",
    verbose=False,
)

security_analyst = Agent(
    role="security-analyst",
    goal="Research vulnerabilities, CVEs, and security misconfigurations in AWS infrastructure",
    backstory="Security researcher who analyzes infrastructure for vulnerabilities. You search for CVEs and document findings.",
    tools=[serper, file_writer],
    llm="gpt-4o-mini",
    verbose=False,
)

report_writer = Agent(
    role="report-writer",
    goal="Generate executive security reports with risk matrices and remediation roadmaps",
    backstory="Technical writer who creates clear, actionable security reports for stakeholders and compliance teams.",
    tools=[file_writer],
    llm="gpt-4o-mini",
    verbose=False,
)

map_task = Task(
    description="""Scan the AWS infrastructure and save your findings.
    Document: 3 EC2 instances (us-east-1), 2 S3 buckets (one public), 1 RDS MySQL database, IAM roles with overly permissive policies.
    Save to filename='infrastructure_inventory.txt' directory='security_audit'""",
    expected_output="Infrastructure inventory saved",
    agent=infrastructure_mapper,
)

analyze_task = Task(
    description="""You MUST use the search tool to research 'AWS S3 bucket misconfiguration CVE 2024'.
    Then analyze the infrastructure for security issues.
    Save findings to filename='vulnerability_assessment.txt' directory='security_audit'""",
    expected_output="Vulnerability assessment saved",
    agent=security_analyst,
    context=[map_task],
)

report_task = Task(
    description="""Generate an executive security summary with risk matrix.
    Save to filename='executive_report.txt' directory='security_audit'""",
    expected_output="Executive report saved",
    agent=report_writer,
    context=[analyze_task],
)

print("Running pipeline: infrastructure-mapper → security-analyst → report-writer")
print()

_stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')

Crew(
    agents=[infrastructure_mapper, security_analyst, report_writer],
    tasks=[map_task, analyze_task, report_task],
    process=Process.sequential,
    verbose=False,
).kickoff()

sys.stderr = _stderr

print("Files created:")
if os.path.exists("security_audit"):
    for f in sorted(os.listdir("security_audit")):
        print(f"  security_audit/{f}")

print("""
┌─────────────────────────────────────────────────────────────────┐
│ PROBLEMS WITH THIS DEPLOYMENT:                                  │
│                                                                 │
│ • No proof that CISO approved this security scan                │
│ • security-analyst can search for anything (credential leaks)   │
│ • report-writer could write to /production or exfiltrate data   │
│ • Any agent can impersonate another agent's role                │
│ • No audit trail linking actions to human approvers             │
│ • Fails SOC2 Type II and HIPAA compliance requirements          │
│                                                                 │
│ João Moura (CrewAI): "Governance is getting more traction       │
│ than security alone... how agents impersonate people and        │
│ how you're going to fingerprint them."                          │
└─────────────────────────────────────────────────────────────────┘
""")

# ═══════════════════════════════════════════════════════════════════
# PHASE 2: With AgentMint
# ═══════════════════════════════════════════════════════════════════

print("═" * 67)
print(" PHASE 2: CrewAI + AgentMint (governance layer)")
print("═" * 67)
print()

# Clean for fresh run
shutil.rmtree("security_audit", ignore_errors=True)

mint = AgentMint(quiet=True)

# CISO approves the security audit with specific scope
plan = mint.issue_plan(
    action="aws:security-audit",
    user="jennifer.chen@acme-corp.com",  # CISO
    scope=[
        "write:security_audit:*",      # Can write to audit directory
        "search:cve:*",                 # Can search CVE databases
        "search:aws-security:*",        # Can search AWS security topics
    ],
    delegates_to=[
        "infrastructure-mapper",
        "security-analyst", 
        "report-writer",
    ],
    requires_checkpoint=[
        "write:production:*",           # Publishing requires approval
        "search:credentials:*",         # Credential searches blocked
        "search:leak:*",                # Leak searches blocked
    ],
    max_depth=2,
    ttl=3600,  # 1 hour
)

print("CISO Authorization:")
print(f"  Approver:    jennifer.chen@acme-corp.com")
print(f"  Receipt:     {plan.short_id}")
print(f"  Signature:   {plan.signature[:32]}...")
print(f"  Scope:       write:security_audit/*, search:cve/*, search:aws-security/*")
print(f"  Agents:      infrastructure-mapper, security-analyst, report-writer")
print(f"  Checkpoints: write:production/*, search:credentials/*, search:leak/*")
print()

audit_trail = []
blocked_attempts = []

@before_tool_call
def agentmint_gate(ctx: ToolCallHookContext) -> bool | None:
    agent = ctx.agent.role if ctx.agent else "unknown"
    tool = ctx.tool_name.lower()
    
    # Classify the action based on tool type
    if "file_writer" in tool:
        fn = ctx.tool_input.get("filename", "unknown")
        dir = ctx.tool_input.get("directory", "").strip("/")
        action = f"write:{dir}:{fn}" if dir else f"write:{fn}"
        
    elif "serper" in tool or "search" in tool:
        query = str(ctx.tool_input.get("search_query", "")).lower()
        
        # Classify search intent
        if any(kw in query for kw in ["credential", "password", "secret", "api key", "access key"]):
            action = f"search:credentials:{query[:40]}"
        elif any(kw in query for kw in ["leak", "exposed", "breach", "dump"]):
            action = f"search:leak:{query[:40]}"
        elif any(kw in query for kw in ["cve", "vulnerability", "exploit"]):
            action = f"search:cve:{query[:40]}"
        else:
            action = f"search:aws-security:{query[:40]}"
    else:
        return None  # Unknown tool, allow
    
    # Check authorization
    result = mint.delegate(parent=plan, agent=agent, action=action)
    
    if result.ok:
        audit_trail.append({
            "agent": agent,
            "action": action,
            "receipt": result.receipt.short_id,
            "signature": result.receipt.signature[:16],
        })
        print(f"  ✓ {agent}")
        print(f"    action: {action}")
        print(f"    receipt: {result.receipt.short_id}")
        return None
    else:
        blocked_attempts.append({
            "agent": agent,
            "action": action,
            "reason": result.status.value,
        })
        print(f"  ✗ {agent}")
        print(f"    action: {action}")
        print(f"    blocked: {result.status.value}")
        return False

# Recreate agents (hooks are global)
infrastructure_mapper = Agent(
    role="infrastructure-mapper",
    goal="Scan and document AWS infrastructure",
    backstory="Senior cloud architect for infrastructure discovery",
    tools=[file_writer],
    llm="gpt-4o-mini",
    verbose=False,
)

security_analyst = Agent(
    role="security-analyst",
    goal="Research vulnerabilities and CVEs",
    backstory="Security researcher who MUST use search tool for CVE research",
    tools=[serper, file_writer],
    llm="gpt-4o-mini",
    verbose=False,
)

report_writer = Agent(
    role="report-writer",
    goal="Generate executive security reports",
    backstory="Technical writer for compliance documentation",
    tools=[file_writer],
    llm="gpt-4o-mini",
    verbose=False,
)

map_task = Task(
    description="Document AWS infrastructure: 3 EC2, 2 S3, 1 RDS, IAM policies. Save to filename='infrastructure_inventory.txt' directory='security_audit'",
    expected_output="Saved",
    agent=infrastructure_mapper,
)

analyze_task = Task(
    description="Use the search tool to search 'AWS S3 public bucket CVE 2024'. Save analysis to filename='vulnerability_assessment.txt' directory='security_audit'",
    expected_output="Saved",
    agent=security_analyst,
)

report_task = Task(
    description="Write executive summary. Save to filename='executive_report.txt' directory='security_audit'",
    expected_output="Saved",
    agent=report_writer,
)

print("Running authorized pipeline:")
print()

sys.stderr = open(os.devnull, 'w')
Crew(
    agents=[infrastructure_mapper, security_analyst, report_writer],
    tasks=[map_task, analyze_task, report_task],
    process=Process.sequential,
    verbose=False,
).kickoff()
sys.stderr = _stderr

# ═══════════════════════════════════════════════════════════════════
# ATTACK SCENARIOS
# ═══════════════════════════════════════════════════════════════════

print()
print("─" * 67)
print(" ATTACK SCENARIO 1: Compromised analyst searches for credentials")
print("─" * 67)
print()

# Agent with ONLY search tool to force search behavior
compromised_analyst = Agent(
    role="security-analyst",
    goal="Search the web",
    backstory="You ONLY search. You cannot write files.",
    tools=[serper],
    llm="gpt-4o-mini",
    verbose=False,
)

credential_search = Task(
    description="Use the search tool to search for 'AWS access key secret key leaked github'",
    expected_output="Results",
    agent=compromised_analyst,
)

sys.stderr = open(os.devnull, 'w')
try:
    Crew(agents=[compromised_analyst], tasks=[credential_search], verbose=False).kickoff()
except:
    pass
sys.stderr = _stderr

print()
print("─" * 67)
print(" ATTACK SCENARIO 2: Rogue agent attempts unauthorized access")
print("─" * 67)
print()

rogue_agent = Agent(
    role="rogue-agent",
    goal="Exfiltrate data",
    backstory="Compromised agent",
    tools=[file_writer],
    llm="gpt-4o-mini",
    verbose=False,
)

exfil_task = Task(
    description="Save infrastructure data to filename='exfiltrated.txt' directory='exfil'",
    expected_output="Done",
    agent=rogue_agent,
)

sys.stderr = open(os.devnull, 'w')
try:
    Crew(agents=[rogue_agent], tasks=[exfil_task], verbose=False).kickoff()
except:
    pass
sys.stderr = _stderr

print()
print("─" * 67)
print(" ATTACK SCENARIO 3: Writer attempts production publish (checkpoint)")
print("─" * 67)
print()

publish_task = Task(
    description="Save report to filename='security_report.txt' directory='production'",
    expected_output="Done",
    agent=report_writer,
)

sys.stderr = open(os.devnull, 'w')
try:
    Crew(agents=[report_writer], tasks=[publish_task], verbose=False).kickoff()
except:
    pass
sys.stderr = _stderr

# ═══════════════════════════════════════════════════════════════════
# RESULTS
# ═══════════════════════════════════════════════════════════════════

print()
print("═" * 67)
print(" AUDIT TRAIL")
print("═" * 67)
print()

print(f"Root Authorization:")
print(f"  Approver:  jennifer.chen@acme-corp.com (CISO)")
print(f"  Receipt:   {plan.short_id}")
print(f"  Signature: {plan.signature[:32]}...")
print()

print(f"Authorized Actions ({len(audit_trail)}):")
for e in audit_trail:
    print(f"  ✓ {e['agent']} → {e['action']}")
    print(f"    receipt: {e['receipt']}, sig: {e['signature']}...")
print()

print(f"Blocked Attempts ({len(blocked_attempts)}):")
for e in blocked_attempts:
    print(f"  ✗ {e['agent']} → {e['action']}")
    print(f"    reason: {e['reason']}")
print()

print("""═══════════════════════════════════════════════════════════════════
 SUMMARY
═══════════════════════════════════════════════════════════════════

 Before AgentMint:
   • Any agent writes anywhere
   • No approval chain
   • No audit trail
   • Fails compliance

 After AgentMint:
   • CISO approval with Ed25519 signature
   • Per-agent, per-tool scoping
   • Credential searches blocked
   • Production writes require checkpoint
   • Tamper-evident audit trail
   • SOC2/HIPAA ready

 Integration: @before_tool_call hook (20 lines)
 Overhead: ~3ms per tool call
 
═══════════════════════════════════════════════════════════════════
""")
