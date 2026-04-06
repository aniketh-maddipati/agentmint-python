"""
Clinical operations agent — handles patient data retrieval,
billing, notifications, and compliance audit queries.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from agents import Agent, Runner, function_tool


@function_tool
def fetch_patient_record(patient_id: str) -> str:
    """Retrieve a patient's medical record from the EHR system.

    Returns demographics, active diagnoses, current medications,
    and recent lab results for the given patient ID.
    """
    return json.dumps({
        "patient_id": patient_id,
        "name": "Maria Chen",
        "dob": "1987-03-14",
        "ssn_last4": "7291",
        "diagnoses": ["Type 2 Diabetes", "Hypertension"],
        "medications": ["Metformin 500mg", "Lisinopril 10mg"],
        "last_a1c": 7.2,
        "provider": "Dr. Sarah Kowalski",
    })


@function_tool
def charge_customer(customer_id: str, amount: float) -> str:
    """Process a payment through the billing gateway.

    Charges the customer's payment method on file. Returns a
    transaction reference and confirmation status.
    """
    return json.dumps({
        "transaction_id": f"txn_{uuid.uuid4().hex[:12]}",
        "customer_id": customer_id,
        "amount": amount,
        "currency": "USD",
        "status": "settled",
        "processor": "stripe",
        "settled_at": datetime.now(timezone.utc).isoformat(),
    })


@function_tool
def send_notification(recipient: str, message: str) -> str:
    """Send an email or SMS notification to a patient or provider.

    Routes through the notification gateway. Supports email addresses
    and phone numbers (auto-detected from format).
    """
    channel = "email" if "@" in recipient else "sms"
    return json.dumps({
        "notification_id": f"ntf_{uuid.uuid4().hex[:12]}",
        "channel": channel,
        "recipient": recipient,
        "status": "delivered",
        "sent_at": datetime.now(timezone.utc).isoformat(),
    })


@function_tool
def query_audit_log(start_date: str, end_date: str) -> str:
    """Query the compliance audit log for a date range.

    Returns access events, data modifications, and policy violations
    recorded during the specified period.
    """
    return json.dumps({
        "query_range": {"start": start_date, "end": end_date},
        "total_events": 1847,
        "breakdown": {
            "record_access": 1203,
            "billing_events": 412,
            "notification_sent": 189,
            "policy_violations": 43,
        },
        "flagged_events": [
            {"type": "bulk_record_access", "agent": "ops-agent", "count": 87},
            {"type": "after_hours_billing", "agent": "billing-agent", "count": 12},
        ],
    })


agent = Agent(
    name="clinical-ops",
    instructions=(
        "You are a clinical operations assistant. Use the available tools "
        "to retrieve patient records, process billing, send notifications, "
        "and query audit logs. Always confirm before charging a customer."
    ),
    tools=[fetch_patient_record, charge_customer, send_notification, query_audit_log],
)
