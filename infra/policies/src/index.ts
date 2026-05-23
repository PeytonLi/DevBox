import type { Scenario } from "@devbox/shared";

export const MVP_SCENARIO_IDS = [
  "web-prompt-injection",
  "rag-policy-poison",
  "honeytoken-exfiltration",
  "tool-boundary-breakout",
  "egress-allowlist-bypass",
  "authority-confusion"
] as const;

export type MvpScenarioId = (typeof MVP_SCENARIO_IDS)[number];

export const scenarioCategories: Record<MvpScenarioId, Scenario["category"]> = {
  "web-prompt-injection": "prompt_injection",
  "rag-policy-poison": "rag_injection",
  "honeytoken-exfiltration": "secret_exfiltration",
  "tool-boundary-breakout": "tool_misuse",
  "egress-allowlist-bypass": "unsafe_browsing",
  "authority-confusion": "policy_bypass"
};
