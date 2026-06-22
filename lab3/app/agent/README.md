# Login Risk Explainer Agent

## 1. Agent Name

**Login Risk Explainer Agent**

---

## 2. Agent Purpose

The purpose of this agent is to demonstrate basic LLM agent behavior with tool usage.

The agent is designed to analyze simple login events and explain whether they look low risk, medium risk, or high risk. It does not perform real production-grade threat detection. Instead, it uses a small rule-based Python tool to classify a login event, and then the LLM explains the result in natural language.

This agent is connected to cybersecurity concepts from authentication monitoring and anomaly detection. It can help explain suspicious login indicators such as unusual login hours, many failed login attempts, privileged account usage, rare countries, and unknown devices.

The system prompt instructs the agent to call its tool whenever the user asks it to analyze, classify, evaluate, or explain a login event.

---

## 3. Agent Tools

### `classify_login_event(hour, failed_attempts, user, country, device)`

**Purpose:**
Classifies a login event as `low`, `medium`, or `high` risk using simple rule-based logic.

**Input:**

* `hour` — login hour in 24-hour format, from 0 to 23.
* `failed_attempts` — number of failed login attempts before the event.
* `user` — username involved in the login event.
* `country` — country where the login originated.
* `device` — device or client type used for the login.

**Output:**

The tool returns a structured dictionary containing:

* `risk_level` — low, medium, or high.
* `risk_score` — numeric score calculated from the suspicious indicators.
* `reasons` — list of reasons that contributed to the risk level.
* `mitre_mapping` — relevant MITRE ATT&CK techniques when applicable.
* `recommended_action` — suggested next action for a SOC analyst.
* `input_event` — the original event fields.

Example MITRE mappings used by the tool:

* `T1110 — Brute Force`
* `T1078 — Valid Accounts`

---

## 4. Example Interaction

**User:**

```text
Analyze this login event: hour=3, failed_attempts=14, user=admin, country=Russia, device=Unknown
```

**Agent behavior:**

The agent calls the `classify_login_event` tool with the extracted fields:

```json
{
  "hour": 3,
  "failed_attempts": 14,
  "user": "admin",
  "country": "Russia",
  "device": "Unknown"
}
```

**Expected tool result:**

```json
{
  "risk_level": "high",
  "risk_score": 11,
  "reasons": [
    "Login occurred outside normal working hours.",
    "High number of failed login attempts before the event.",
    "The login involved a privileged or service account.",
    "The login originated from a rare country in this demo scenario.",
    "The login used an unknown or suspicious device type."
  ],
  "mitre_mapping": [
    {
      "technique_id": "T1110",
      "technique_name": "Brute Force"
    },
    {
      "technique_id": "T1078",
      "technique_name": "Valid Accounts"
    }
  ],
  "recommended_action": "Investigate immediately, verify the account owner, and review surrounding authentication logs."
}
```

**Example final response:**

```text
This login event is high risk.

The main reasons are that it happened at 03:00, included 14 failed login attempts, involved the privileged user admin, came from Russia, and used an Unknown device.

The relevant MITRE ATT&CK mappings are T1110 Brute Force and T1078 Valid Accounts.

Recommended action: investigate immediately, verify the account owner, and review surrounding authentication logs.

This is a simplified educational demo and not a production security system.
```

---

## 5. Limitations

This agent is intentionally simple. It uses fixed rules and does not learn from historical user behavior. In a real SOC environment, login risk scoring would require more context, such as user baseline behavior, IP reputation, geolocation history, device fingerprints, MFA status, and surrounding logs.

The goal of this lab is to demonstrate LLM agent mechanics and tool invocation, not to build a complete cybersecurity detection system.
