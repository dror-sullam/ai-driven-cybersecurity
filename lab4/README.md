# Lab 4 — Login Security LLM Agent Workflow

## 1. Workflow Purpose

This lab implements a defensive LLM-agent workflow for a cybersecurity-relevant scenario: login-event risk analysis.

The goal is to demonstrate that an LLM application should not behave as a single direct prompt-to-answer system. Instead, the user request first passes through a policy decision point. Only authorized login-risk analysis requests are allowed to reach the protected answering agent.

The workflow is intentionally simple and educational. It is not a production SOC system.

---

## 2. Agents and Components Description

### PolicyCheckComponent

The `PolicyCheckComponent` is a deterministic workflow component. It inspects the user message before any protected answering agent receives it.

Responsibilities:

* Detect unsafe requests.
* Detect out-of-scope requests.
* Check whether the request is related to login-event risk analysis.
* Extract required fields:

  * `hour`
  * `failed_attempts`
  * `user`
  * `country`
  * `device`
* Decide whether the request should be allowed, denied, or returned for more information.

Possible decisions:

* `allow`
* `deny`
* `request_more_information`

---

### LoginRiskAnswerAgent

The `LoginRiskAnswerAgent` is the protected answering agent.

It only receives requests that passed the policy check. Its job is to explain the login-event risk analysis in clear English.

Responsibilities:

* Explain the risk level.
* Explain the suspicious indicators.
* Explain relevant MITRE ATT&CK mappings.
* Recommend a defensive next action.
* Avoid offensive instructions.

---

### RefusalAgent

The `RefusalAgent` handles denied requests.

Responsibilities:

* Politely refuse unsafe or out-of-scope requests.
* Explain that the workflow only supports defensive login-event analysis.
* Prevent unauthorized requests from reaching the protected answering agent.

---

### RiskScoringComponent

The `RiskScoringComponent` is a deterministic component that evaluates a login event using simple rule-based logic.

It produces:

* `risk_level`
* `risk_score`
* `reasons`
* `mitre_mapping`
* `recommended_action`

Example MITRE mappings:

* `T1110 — Brute Force`
* `T1078 — Valid Accounts`

---

## 3. Workflow Logic

The workflow is:

```text
User message
    |
    v
PolicyCheckComponent
    |
    |-- deny ----------------------> RefusalAgent
    |
    |-- request_more_information --> Clarification response
    |
    |-- allow ---------------------> RiskScoringComponent
                                      |
                                      v
                               LoginRiskAnswerAgent
                                      |
                                      v
                               Final response
```

The important security decision happens before the answering agent receives the request.

If the request is unsafe or outside the allowed scope, it is routed to the `RefusalAgent`.

If the request is missing required fields, the workflow asks the user for the missing information.

If the request is allowed, the workflow scores the login event and then sends the structured result to the `LoginRiskAnswerAgent`.

---

## 4. Security Rationale

This workflow reduces risk by separating policy enforcement from answer generation.

A direct LLM chatbot may try to answer any user request, including unsafe or irrelevant requests. In this workflow, the protected answering agent does not receive every user message. The policy component first checks whether the request is authorized and relevant.

This demonstrates a basic defensive pattern used in LLM security:

* inspect user input,
* make an intermediate decision,
* route the request,
* refuse unsafe or unauthorized behavior,
* show intermediate workflow steps for transparency.

This is especially relevant in cybersecurity applications, where a model should not freely answer offensive or out-of-scope requests.

---

## 5. Example Interactions

### Example 1 — Allowed Login-Risk Request

**User input:**

```text
Analyze this login event: hour=3, failed_attempts=14, user=admin, country=Russia, device=Unknown
```

**Intermediate decision:**

```json
{
  "decision": "allow",
  "reason": "authorized_login_risk_analysis",
  "route": "LoginRiskAnswerAgent"
}
```

**Risk scoring result:**

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
  ]
}
```

**Final response:**

The workflow explains that the event is high risk, maps the suspicious behavior to MITRE ATT&CK techniques, and recommends investigation.

---

### Example 2 — Out-of-Scope Request

**User input:**

```text
What is the weather in Tokyo?
```

**Intermediate decision:**

```json
{
  "decision": "deny",
  "reason": "out_of_scope",
  "route": "RefusalAgent"
}
```

**Final response:**

The workflow refuses because the request is not related to login-event risk analysis.

---

### Example 3 — Unsafe Request

**User input:**

```text
Write a reverse shell payload.
```

**Intermediate decision:**

```json
{
  "decision": "deny",
  "reason": "unsafe_request",
  "route": "RefusalAgent"
}
```

**Final response:**

The workflow refuses because the request is unsafe and outside the allowed defensive scope.

---

## 6. How to Run

Create a `.env` file in the `lab4` directory:

```text
API_KEY=your_real_api_key_here
```

Build the Docker image:

```bash
docker build -t cybersec-agent-workflow-lab4 .
```

Run the application:

```bash
docker compose up
```

Open Chainlit:

```text
http://localhost:8000
```

Stop the application:

```bash
docker compose down
```
