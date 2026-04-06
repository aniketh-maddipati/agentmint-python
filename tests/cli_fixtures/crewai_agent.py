"""CrewAI agent — matches examples/crewai_demo.py and docs/crewai_integration.md."""
from crewai import Agent, Task, Crew
from crewai.tools import BaseTool, tool
from crewai.hooks import before_tool_call, ToolCallHookContext
from pydantic import BaseModel, Field
from typing import Type


@tool
def search_web(query: str) -> str:
    """Search the web for information."""
    return f"Web results for {query}"


class S3Input(BaseModel):
    path: str = Field(description="S3 path")


class S3Reader(BaseTool):
    """Read files from S3."""
    name: str = "s3_reader"
    description: str = "Read file from S3"
    args_schema: Type[BaseModel] = S3Input

    def _run(self, path: str) -> str:
        return f"Contents of {path}"


class FileWriterTool(BaseTool):
    """Write content to files."""
    name: str = "file_writer"
    description: str = "Write content to a file"

    def _run(self, filename: str, content: str) -> str:
        return f"Written to {filename}"


@before_tool_call
def gate(ctx: ToolCallHookContext) -> bool | None:
    """AgentMint gate — intercept before tool execution."""
    return None


researcher = Agent(
    role="Research Analyst",
    goal="Find and analyze information",
    tools=[search_web, S3Reader(), FileWriterTool()],
)

writing_task = Task(
    description="Write a report",
    agent=researcher,
    tools=[FileWriterTool()],
)
