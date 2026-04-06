"""LangGraph agent with @tool definitions and ToolNode registration."""
from langgraph.prebuilt import tool, ToolNode
from langgraph.graph import StateGraph


@tool
def search_docs(query: str) -> str:
    """Search documentation for relevant information."""
    return f"Results for: {query}"


@tool
def save_results(results: list, destination: str) -> bool:
    """Save search results to a destination."""
    return True


@tool
def delete_old_index(index_name: str) -> None:
    """Delete an outdated search index."""
    pass


def helper_function(x: int) -> int:
    """NOT a tool — just a helper."""
    return x + 1


tool_node = ToolNode([search_docs, save_results, delete_old_index])
graph = StateGraph()
graph.add_node("tools", tool_node)
