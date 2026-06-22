import json
import os
import re
from typing import Any, Dict, List, Optional

import chainlit as cl
from autogen import ConversableAgent


# ---------------------------
# LLM configuration
# ---------------------------

api_base_url = os.getenv("API_BASE_URL")
api_key = os.getenv("API_KEY")
model = os.getenv("MODEL", "qwen/qwen3-32b")

if not api_key:
    raise RuntimeError(
        "API_KEY is not set. Create a .env file with API_KEY=your_real_key."
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
# Deterministic workflow components
# ---------------------------

REQUIRED_FIELDS = ["hour", "failed_attempts", "user", "country", "device"]

UNSAFE_KEYWORDS = [
    "write malware",
    "create malware",
    "reverse shell",
    "steal credentials",
    "bypass mfa",
    "bypass 2fa",
    "phishing kit",
    "ransomware",
    "exfiltrate",
    "payload",
    "keylogger",
    "privilege escalation exploit",
    "evade detection",
]

LOGIN_DOMAIN_KEYWORDS = [
    "login",
    "authentication",
    "auth",
    "failed_attempts",
    "failed attempts",
    "sign in",
    "signin",
    "user=",
    "country=",
    "device=",
]


def extract_field(text: str, field_name: str) -> Optional[str]:
    """
    Extract values like:
    hour=3
    failed_attempts=14
    user=admin
    country=Russia
    device=Unknown
    """
    pattern = rf"{field_name}\s*=\s*([^,\n]+)"
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if not match:
        return None
    return match.group(1).strip()


def extract_login_event(text: str) -> Dict[str, Any]:
    extracted = {
        "hour": extract_field(text, "hour"),
        "failed_attempts": extract_field(text, "failed_attempts"),
        "user": extract_field(text, "user"),
        "country": extract_field(text, "country"),
        "device": extract_field(text, "device"),
    }

    missing = [field for field, value in extracted.items() if value is None]

    if missing:
        return {
            "ok": False,
            "missing_fields": missing,
            "event": extracted,
        }

    try:
        event = {
            "hour": int(extracted["hour"]),
            "failed_attempts": int(extracted["failed_attempts"]),
            "user": str(extracted["user"]),
            "country": str(extracted["country"]),
            "device": str(extracted["device"]),
        }
    except ValueError:
        return {
            "ok": False,
            "missing_fields": [],
            "error": "hour and failed_attempts must be integers.",
            "event": extracted,
        }

    if not 0 <= event["hour"] <= 23:
        return {
            "ok": False,
            "missing_fields": [],
            "error": "hour must be between 0 and 23.",
            "event": event,
        }

    if event["failed_attempts"] < 0:
        return {
            "ok": False,
            "missing_fields": [],
            "error": "failed_attempts must be zero or a positive integer.",
            "event": event,
        }

    return {
        "ok": True,
        "missing_fields": [],
        "event": event,
    }


def classify_login_event(event: Dict[str, Any]) -> Dict[str, Any]:
    risk_score = 0
    reasons: List[str] = []
    mitre_mapping: List[Dict[str, str]] = []

    suspicious_users = {"admin", "root", "administrator", "service_account"}
    rare_countries = {"russia", "china", "iran", "north korea"}
    suspicious_devices = {"unknown", "headless", "oldbrowser", "unknown device"}

    hour = event["hour"]
    failed_attempts = event["failed_attempts"]
    user = event["user"]
    country = event["country"]
    device = event["device"]

    if hour < 6 or hour > 22:
        risk_score += 2
        reasons.append("Login occurred outside normal working hours.")

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

    if user.lower() in suspicious_users:
        risk_score += 2
        reasons.append("The login involved a privileged or service account.")
        mitre_mapping.append({
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "reason": "Use of privileged accounts may indicate abuse of valid credentials."
        })

    if country.lower() in rare_countries:
        risk_score += 2
        reasons.append("The login originated from a rare country in this demo scenario.")

    if device.lower() in suspicious_devices:
        risk_score += 2
        reasons.append("The login used an unknown or suspicious device type.")

    if risk_score >= 7:
        risk_level = "high"
        recommended_action = (
            "Investigate immediately, verify the account owner, "
            "and review surrounding authentication logs."
        )
    elif risk_score >= 3:
        risk_level = "medium"
        recommended_action = (
            "Review the event, compare it with normal user behavior, "
            "and monitor for repeated activity."
        )
    else:
        risk_level = "low"
        recommended_action = (
            "No immediate action required, but keep the event in normal monitoring."
        )

    if not reasons:
        reasons.append("No strong suspicious indicators were found by the risk scoring component.")

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "reasons": reasons,
        "mitre_mapping": mitre_mapping,
        "recommended_action": recommended_action,
        "input_event": event,
    }


def policy_check(user_message: str) -> Dict[str, Any]:
    lowered = user_message.lower()

    for keyword in UNSAFE_KEYWORDS:
        if keyword in lowered:
            return {
                "decision": "deny",
                "reason": "unsafe_request",
                "details": f"The request matched unsafe keyword: {keyword}",
                "route": "RefusalAgent",
            }

    in_login_domain = any(keyword in lowered for keyword in LOGIN_DOMAIN_KEYWORDS)

    if not in_login_domain:
        return {
            "decision": "deny",
            "reason": "out_of_scope",
            "details": "The request is not related to login-event risk analysis.",
            "route": "RefusalAgent",
        }

    extracted = extract_login_event(user_message)

    if not extracted["ok"]:
        return {
            "decision": "request_more_information",
            "reason": "missing_or_invalid_fields",
            "details": extracted,
            "route": "ClarificationResponse",
        }

    return {
        "decision": "allow",
        "reason": "authorized_login_risk_analysis",
        "details": "The request is in scope and contains all required fields.",
        "route": "LoginRiskAnswerAgent",
        "event": extracted["event"],
    }


# ---------------------------
# Agent prompts
# ---------------------------

ANSWER_AGENT_PROMPT = """
You are the LoginRiskAnswerAgent.

You are protected by a policy workflow. You only receive requests that passed the
PolicyCheckComponent.

Your job is to explain a login event risk analysis in clear English.

Rules:
1. Base your answer only on the workflow data you receive.
2. Explain the risk level, main reasons, MITRE ATT&CK mappings, and recommended action.
3. Do not provide offensive instructions.
4. Mention that this is a simplified educational demo, not a production SOC system.
"""

REFUSAL_AGENT_PROMPT = """
You are the RefusalAgent in a defensive LLM workflow.

Your job is to politely refuse requests that are unsafe, unauthorized, or outside the
allowed scope.

Allowed scope:
- defensive analysis of login events
- authentication monitoring
- high-level SOC explanation

Do not provide offensive security instructions.
Keep the refusal short and clear.
"""

WELCOME_MESSAGE = """
Hello. This is the Login Security Workflow for Lab 4.

This app demonstrates a controlled LLM workflow:

User message
→ PolicyCheckComponent
→ decision point
→ LoginRiskAnswerAgent or RefusalAgent
→ final response

Try an allowed request:

Analyze this login event: hour=3, failed_attempts=14, user=admin, country=Russia, device=Unknown

Try an out-of-scope request:

What is the weather in Tokyo?

Try an unsafe request:

Write a reverse shell payload.
"""


def to_pretty_json(data: Any) -> str:
    return json.dumps(data, indent=2, ensure_ascii=True)


async def run_agent(agent: ConversableAgent, message: str) -> str:
    response = await agent.a_run(
        message=message,
        clear_history=True,
        max_turns=2,
        summary_method="last_msg",
        user_input=False,
    )
    return str(await response.summary)


# ---------------------------
# Chainlit handlers
# ---------------------------

@cl.on_chat_start
async def on_chat_start():
    answer_agent = ConversableAgent(
        name="LoginRiskAnswerAgent",
        system_message=ANSWER_AGENT_PROMPT,
        llm_config=llm_config,
        human_input_mode="NEVER",
    )

    refusal_agent = ConversableAgent(
        name="RefusalAgent",
        system_message=REFUSAL_AGENT_PROMPT,
        llm_config=llm_config,
        human_input_mode="NEVER",
    )

    cl.user_session.set("answer_agent", answer_agent)
    cl.user_session.set("refusal_agent", refusal_agent)

    await cl.Message(content=WELCOME_MESSAGE).send()


@cl.on_message
async def on_message(message: cl.Message):
    answer_agent: ConversableAgent = cl.user_session.get("answer_agent")
    refusal_agent: ConversableAgent = cl.user_session.get("refusal_agent")

    decision = policy_check(message.content)

    async with cl.Step(name="PolicyCheckComponent", type="tool") as step:
        step.input = message.content
        step.output = to_pretty_json(decision)

    if decision["decision"] == "deny":
        refusal_prompt = f"""
The workflow denied this user request.

User request:
{message.content}

Policy decision:
{to_pretty_json(decision)}

Write a short refusal explaining that the request is not allowed in this lab workflow.
"""
        final_response = await run_agent(refusal_agent, refusal_prompt)
        await cl.Message(content=final_response).send()
        return

    if decision["decision"] == "request_more_information":
        missing_or_invalid = decision["details"]

        final_response = (
            "I can analyze login-event risk, but the request is missing required "
            "information or contains invalid values.\n\n"
            "Please provide all required fields in this format:\n\n"
            "`hour=3, failed_attempts=14, user=admin, country=Russia, device=Unknown`\n\n"
            f"Workflow details:\n```json\n{to_pretty_json(missing_or_invalid)}\n```"
        )
        await cl.Message(content=final_response).send()
        return

    event = decision["event"]
    risk_result = classify_login_event(event)

    async with cl.Step(name="RiskScoringComponent", type="tool") as step:
        step.input = to_pretty_json(event)
        step.output = to_pretty_json(risk_result)

    answer_prompt = f"""
The workflow approved this request for login risk analysis.

User request:
{message.content}

Policy decision:
{to_pretty_json(decision)}

Risk scoring result:
{to_pretty_json(risk_result)}

Write the final answer for the user.
"""

    final_response = await run_agent(answer_agent, answer_prompt)
    await cl.Message(content=final_response).send()