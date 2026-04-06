"""No framework imports — raw detector should catch tool-like functions."""


def fetch_user_profile(user_id: str) -> dict:
    """Fetch a user's profile from the API."""
    return {"id": user_id, "name": "Test User"}


def delete_account(user_id: str) -> bool:
    """Delete a user account permanently."""
    return True


def process_data(items: list) -> list:
    """NOT a tool — no tool-like prefix."""
    return [x * 2 for x in items]


class HelperClass:
    """NOT a tool — no BaseTool inheritance."""
    def run(self):
        pass
