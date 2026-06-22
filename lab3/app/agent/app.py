import os
import json
from typing import Annotated, Dict

import chainlit as cl
from autogen import ConversableAgent
from autogen.events.agent_events import ExecuteFunctionEvent, ExecutedFunctionEvent


# ---------------------------
# Tool: classify login event
# ---------------------------

def classify_login_event(
    hour: Annotated[int, "Login hour in 24-hour format, from 0 to 23."],
    failed_attempts: Annotated[int, "Number of failed login attempts before this login event."],
    user: Annotated[str, "Username involved in the login event."],
    country: Annotated[str, "Country where the login attempt originated."],
    device: Annotated[str, "Device or client type used for the login attempt."],
) -> Dict:
    """
    Classify a login event as low, medium, or high risk.

    This is a simple rule-based cybersecurity tool.
    The LLM agent is responsible for explaining the result to the user.
    """
    risk_score = 0
    reasons = []
    mitre_mapping = []

    suspicious_users = {"admin", "root", "administrator", "service_account"}
    rare_countries = {"russia", "china", "iran", "north korea"}
    suspicious_devices = {"unknown", "headless", "oldbrowser", "unknown device"}

    # Time-based risk
    if hour < 6 or hour > 22:
        risk_score += 2
        reasons.append("Login occurred outside normal working hours.")

    # Failed attempts risk
    if failed_attempts >= 10:
        risk_score += 3
        reasons.append("High number of failed login attempts before the event.")
        mitre_mapping.append({
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "reason": "Many failed login attempts may indicate brute-force activity."
        })
    elif failed_attempts >= 3:
        risk_score += 1
        reasons.append("Several failed login attempts were observed.")

    # Privileged account risk
    if user.lower() in suspicious_users:
        risk_score += 2
        reasons.append("The login involved a privileged or service account.")
        mitre_mapping.append({
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "reason": "Use of privileged accounts may indicate abuse of valid credentials."
        })

    # Country risk
    if country.lower() in rare_countries:
        risk_score += 2
        reasons.append("The login originated from a rare country in this demo scenario.")

    # Device risk
    if device.lower() in suspicious_devices:
        risk_score += 2
        reasons.append("The login used an unknown or suspicious device type.")

    if risk_score >= 7:
        risk_level = "high"
        recommended_action = "Investigate immediately, verify the account owner, and review surrounding authentication logs."
    elif risk_score >= 3:
        risk_level = "medium"
        recommended_action = "Review the event, compare it with normal user behavior, and monitor for repeated activity."
    else:
        risk_level = "low"
        recommended_action = "No immediate action required, but keep the event in normal monitoring."

    if not reasons:
        reasons.append("No strong suspicious indicators were found by the rule-based tool.")

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasons": reasons,
        "mitre_mapping": mitre_mapping,
        "recommended_action": recommended_action,
        "input_event": {
            "hour": hour,
            "failed_attempts": failed_attempts,
            "user": user,
            "country": country,
            "device": device,
        }
    }


# ---------------------------
# LLM configuration
# ---------------------------

api_base_url = os.getenv("API_BASE_URL")
api_key = os.getenv("API_KEY")
model = os.getenv("MODEL", "qwen/qwen3-32b")

if not api_key:
    raise RuntimeError(
        "API_KEY is not set. "
        "Set it in your .env file or docker compose environment."
    )

llm_config = {
    "config_list": [
        {
            "model": model,
            "api_key": api_key,
            "base_url": api_base_url,
            "price": [0, 0],
        }
    ],
}


# ---------------------------
# System prompt
# ---------------------------

SYSTEM_PROMPT = """
You are a Login Risk Explainer Agent for an introductory LLM agents lab.

Your task is to help users interpret suspicious login events.
You have one tool:

- classify_login_event(hour, failed_attempts, user, country, device):
  Classifies a login event as low, medium, or high risk using simple rule-based logic.

Rules:
1. If the user asks you to analyze, classify, evaluate, or explain a login event, you must call classify_login_event.
2. Extract the required fields from the user's message:
   - hour
   - failed_attempts
   - user
   - country
   - device
3. If any required field is missing, ask the user for the missing field instead of guessing.
4. After using the tool, explain the result in clear English:
   - risk level
   - main reasons
   - relevant MITRE ATT&CK techniques, if any
   - recommended next action
5. Do not claim this is a production security system. Explain that it is a simplified educational demo.
6. Always answer in English.
"""

WELCOME_MESSAGE = """
Hello. I am the Login Risk Explainer Agent.

I can analyze a login event using a Python tool and explain the risk level in plain English.

Try this example:

Analyze this login event: hour=3, failed_attempts=14, user=admin, country=Russia, device=Unknown

When I use the tool, Chainlit will show the function call as an expandable step.
"""


def _format_content(content: object) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, (dict, list, tuple)):
        return json.dumps(content, ensure_ascii=True, indent=2)
    return str(content)


# ---------------------------
# Chainlit event handlers
# ---------------------------

@cl.on_chat_start
async def on_chat_start():
    """Create the AG2 assistant and store it in the user session."""
    assistant = ConversableAgent(
        name="login_risk_explainer_agent",
        system_message=SYSTEM_PROMPT,
        llm_config=llm_config,
        human_input_mode="NEVER",
        functions=[classify_login_event],
    )

    cl.user_session.set("assistant", assistant)

    await cl.Message(
        content=WELCOME_MESSAGE,
        author="login_risk_explainer_agent"
    ).send()


@cl.on_message
async def on_message(message: cl.Message):
    """Handle each user message using AG2 async single-agent execution."""
    assistant: ConversableAgent = cl.user_session.get("assistant")

    response = await assistant.a_run(
        message=message.content,
        clear_history=False,
        max_turns=6,
        summary_method="last_msg",
        user_input=False,
    )

    tool_inputs: dict[str, dict[str, str]] = {}

    async for event in response.events:
        if isinstance(event, ExecuteFunctionEvent):
            event_data = event.content
            tool_key = getattr(event_data, "call_id", None) or event_data.func_name

            tool_inputs[tool_key] = {
                "name": event_data.func_name,
                "input": _format_content(event_data.arguments) or "(no arguments)",
            }
            continue

        if not isinstance(event, ExecutedFunctionEvent):
            continue

        event_data = event.content
        tool_key = getattr(event_data, "call_id", None) or event_data.func_name

        step_data = tool_inputs.get(
            tool_key,
            {
                "name": event_data.func_name,
                "input": "(no arguments)",
            },
        )

        async with cl.Step(name=step_data["name"], type="tool") as step:
            step.input = step_data["input"]
            step.output = _format_content(event_data.content)

    summary = await response.summary
    final_text = _format_content(summary)

    await cl.Message(content=final_text).send()