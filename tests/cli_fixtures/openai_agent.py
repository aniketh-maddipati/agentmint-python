"""OpenAI Agents SDK — matches examples/openai_agents_receipts_demo."""
from agents import Agent, Runner, RunHooks, function_tool


@function_tool
def get_weather(city: str) -> str:
    """Get current weather for a city."""
    return f"72F in {city}"


@function_tool
def lookup_account(account_id: str) -> str:
    """Look up account details by ID."""
    return f"Account {account_id}"


@function_tool
def send_notification(recipient: str, message: str) -> str:
    """Send a notification to a user."""
    return f"Sent to {recipient}"


def fetch_market_data(symbol: str) -> dict:
    """Fetch market data — plain function passed as tool."""
    return {"symbol": symbol, "price": 150.0}


def execute_trade(symbol: str, quantity: int, side: str) -> dict:
    """Execute a stock trade."""
    return {"status": "filled"}


notification_agent = Agent(
    name="notification_agent",
    instructions="Send notifications.",
    tools=[send_notification],
)

main_agent = Agent(
    name="main_agent",
    instructions="Use tools.",
    tools=[get_weather, lookup_account],
    handoffs=[notification_agent],
)

trading_agent = Agent(
    name="trading_bot",
    tools=[fetch_market_data, execute_trade],
)
