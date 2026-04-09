# AgentMint Production Readiness Assessment

**Target:** `/Users/aniketh/agentmint-python/examples`  
**Score:** 94/100 (A)  
**Tools found:** 25  
**Scan:** 6208ms

## Tool Governance

- ✓ **TG-001** Tool inventory complete [critical]
- ✗ **TG-002** High-confidence detections [high]
  - 8 tools need manual review
- ✓ **TG-003** Scope suggestions generated [high]
- ✓ **TG-004** Write/delete ops identified [high]
- ✓ **TG-005** Network ops identified [medium]

## Runtime Enforcement

- ✓ **RE-001** Input scanning available [critical]
- ✓ **RE-002** Output scanning available [critical]
- ✓ **RE-003** Rate limiting available [high]
- ✓ **RE-004** Sub-50ms enforcement [medium]

## Evidence Integrity

- ✓ **EI-001** Ed25519 signing [critical]
- ✓ **EI-002** SHA-256 hash chains [critical]
- ✓ **EI-003** Evidence export [high]

## Compliance Mapping

- ✓ **CM-001** AIUC-1 controls [high]
- ✓ **CM-002** SOC 2 audit trail [high]
- ✓ **CM-003** OWASP LLM Top 10 [high]

## Tool Inventory

| File | Symbol | Framework | Operation | Scope |
|------|--------|-----------|-----------|-------|
| gatekeeper_demo.py:227 | read_file | raw | read | `tool:read_file` |
| harness_integration.py:38 | lookup_booking | raw | read | `tool:lookup_booking` |
| harness_integration.py:42 | get_flight_status | raw | read | `tool:get_flight_status` |
| harness_integration.py:47 | send_email | raw | exec | `tool:send_email` |
| harness_integration.py:51 | search_web | raw | read | `tool:search_web` |
| mcp_real_demo.py:111 | read_file | raw | read | `tool:read_file` |
| mcp_real_demo.py:143 | write_file | raw | write | `tool:write_file` |
| crewai_aws.py:76 | s3_tool | crewai | unknown | `tool:s3_tool` |
| crewai_aws.py:212 | s3_tool | crewai | unknown | `tool:s3_tool` |
| crewai_aws.py:33 | S3ReaderTool | crewai | unknown | `tool:S3ReaderTool` |
| crewai_aws.py:176 | gate | crewai | gate | `hook:before_tool_call` |
| combined_demo.py:108 | S3Tool | crewai | unknown | `tool:S3Tool` |
| combined_demo.py:60 | S3Tool | crewai | unknown | `tool:S3Tool` |
| combined_demo.py:90 | gate | crewai | gate | `hook:before_tool_call` |
| combined_demo.py:161 | read_file | raw | read | `tool:read_file` |
| crewai_demo.py:182 | S3Reader | crewai | unknown | `tool:S3Reader` |
| crewai_demo.py:249 | S3Reader | crewai | unknown | `tool:S3Reader` |
| crewai_demo.py:29 | S3Reader | crewai | unknown | `tool:S3Reader` |
| crewai_demo.py:155 | gate | crewai | gate | `hook:before_tool_call` |
| openai_agents_receipts_demo/demo_open_ai_receipts.py:95 | get_weather | openai-sdk | read | `tool:get_weather` |
| openai_agents_receipts_demo/demo_open_ai_receipts.py:108 | lookup_account | openai-sdk | read | `tool:lookup_account` |
| openai_agents_receipts_demo/demo_open_ai_receipts.py:121 | send_notification | openai-sdk | exec | `tool:send_notification` |
| openai_agents_receipts_demo/demo_open_ai_receipts.py:151 | send_notification | openai-sdk | exec | `tool:send_notification` |
| openai_agents_receipts_demo/demo_open_ai_receipts.py:157 | get_weather | openai-sdk | read | `tool:get_weather` |
| openai_agents_receipts_demo/demo_open_ai_receipts.py:157 | lookup_account | openai-sdk | read | `tool:lookup_account` |

---
*AgentMint v0.3.0 — agentmint.run*