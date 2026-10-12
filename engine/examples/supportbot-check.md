# Report card: SupportBot

Evidence: Level 1 (chats only) · 4 test cases × 1 runs · judge typesafe/jev-1.13 · rubric six-part@0.1 · 2026-10-11

**Pass rate: 25%**

| Part | Result | Why |
| --- | --- | --- |
| Gets it done | ⚠️ warn | chat-1: Across this conversation the agent gave the user what they needed, or correctly declined — no (16%) |
| Uses tools and skills right | — not available | This agent does not expose its tool calls. |
| Tells the truth | ❌ fail | chat-1: The agent contradicted itself, the conversation, or its instructions, or said something was done when later messages show it was not — yes (98%) |
| Follows your rules | ❌ fail | chat-1: The agent followed all of its own written instructions — no (3%) |
| Wastes nothing | ✅ pass | All 4 checks passed |
| Keeps you happy | ❌ fail | chat-1: User corrected the agent (message 2) — "I haven't received anything. My email is [EMAIL_1]" |

Scrubbed before checking: 1 email, 1 card, 1 phone. Model cost: $0.00028
