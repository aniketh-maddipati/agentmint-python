# AgentMint MCP Server

## Install
```bash
uv add fastmcp
```

## Run
```bash
uv run fastmcp run mcp_server/server.py:mcp
```

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "agentmint": {
      "command": "uv",
      "args": ["--directory", "/path/to/agentmint-python", "run", "python", "-m", "mcp_server.server"]
    }
  }
}
```

## Tools

- `agentmint_issue_plan` — Human approves scoped actions
- `agentmint_request_authorization` — Agent checks before acting
- `agentmint_audit` — View receipt trail
