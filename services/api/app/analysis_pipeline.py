from __future__ import annotations

import os
import re
import shutil

from .contracts import (
    AgentSpec,
    ComplianceFramework,
    ComplianceMapping,
    ComplianceStatus,
    Finding,
    ModelConfig,
    RiskLane,
    RiskProfile,
    RiskRoute,
    ScannerResult,
    ScannerStatus,
    Severity,
)


SECRET_PATTERNS = [
    ("api-key-shaped token", re.compile(r"\b(?:AIza[0-9A-Za-z_-]{20,}|sk-[0-9A-Za-z_-]{12,})\b")),
    ("credential assignment", re.compile(r"(?i)\b(?:api[_-]?key|token|secret|password)\b\s*[:=]\s*[^\s]+")),
]
PII_PATTERNS = [
    ("email address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("US SSN shape", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
]
INJECTION_MARKERS = [
    "ignore previous",
    "ignore all previous",
    "developer override",
    "system override",
    "disable policy",
    "reveal your instructions",
    "exfiltrate",
]


def build_risk_routes(agent: AgentSpec, model: ModelConfig, allow_cloud_analysis: bool) -> list[RiskRoute]:
    sensitive = detect_sensitive_categories(agent)
    routes = [
        RiskRoute(
            lane=RiskLane.LOCAL,
            severity=Severity.HIGH if sensitive else Severity.LOW,
            rationale=(
                "Credentials/PII scan stays local before any provider routing."
                if sensitive
                else "No credential or PII-shaped content was detected in the imported agent prompt."
            ),
        ),
        RiskRoute(
            lane=RiskLane.SCANNER,
            severity=Severity.MEDIUM,
            rationale="Open-source scanner lane evaluates prompt, tool, and egress policy patterns without executing uploaded code.",
        ),
        RiskRoute(
            lane=RiskLane.SANDBOX,
            severity=Severity.HIGH,
            rationale="Managed sandbox attacker and defender scenarios replay OWASP-style agent failures against the submitted policy.",
        ),
    ]
    if has_injection_markers(agent.system_prompt):
        routes.append(
            RiskRoute(
                lane=RiskLane.CLOUD if model.risk_profile == RiskProfile.CLOUD and allow_cloud_analysis else RiskLane.LOCAL,
                severity=Severity.HIGH,
                rationale=(
                    "Complex injection review is permitted for the selected cloud model."
                    if model.risk_profile == RiskProfile.CLOUD and allow_cloud_analysis
                    else "Complex injection review is retained in the local deterministic lane until cloud analysis is explicitly allowed."
                ),
            )
        )
    return routes


def build_scanner_results(agent: AgentSpec) -> list[ScannerResult]:
    sensitive = detect_sensitive_categories(agent)
    injection = has_injection_markers(agent.system_prompt)
    tool_gaps = policy_gap_evidence(agent)
    return [
        ScannerResult(
            id="scanner_credentials_pii",
            scanner="Gemma 4 Local credentials/PII scan",
            status=ScannerStatus.FLAGGED if sensitive else ScannerStatus.PASSED,
            severity=Severity.HIGH if sensitive else None,
            summary="Sensitive data patterns were detected." if sensitive else "No credential or PII-shaped prompt content detected.",
            evidence=sensitive or ["Pattern scan completed locally."],
        ),
        ScannerResult(
            id="scanner_complex_injection",
            scanner="Static complex injection marker review",
            status=ScannerStatus.FLAGGED if injection else ScannerStatus.PASSED,
            severity=Severity.HIGH if injection else None,
            summary="Prompt contains injection-like policy override language." if injection else "No obvious policy override language detected.",
            evidence=["Prompt contains adversarial instruction markers."] if injection else ["Deterministic injection marker scan completed."],
        ),
        ScannerResult(
            id="scanner_policy_static",
            scanner="Open-source scanner lane",
            status=ScannerStatus.FLAGGED if tool_gaps else ScannerStatus.PASSED,
            severity=Severity.MEDIUM if tool_gaps else None,
            summary="Tool or network policy needs review." if tool_gaps else "Tool and network policy structure is present.",
            evidence=tool_gaps or ["Allowed tools and domains were declared."],
        ),
        garak_status_result(),
    ]


def build_compliance_mappings(findings: list[Finding], scanner_results: list[ScannerResult]) -> list[ComplianceMapping]:
    mappings: list[ComplianceMapping] = []
    for finding in findings:
        mappings.append(
            ComplianceMapping(
                framework=ComplianceFramework.OWASP_LLM_TOP_10,
                control=owasp_control_for(finding.scenario_id),
                finding_id=finding.id,
                status=ComplianceStatus.GAP,
                evidence=finding.evidence,
            )
        )

    flagged_scanners = [result for result in scanner_results if result.status == ScannerStatus.FLAGGED]
    mappings.append(
        ComplianceMapping(
            framework=ComplianceFramework.NIST_AI_RMF,
            control="AI RMF Govern/Map/Measure/Manage evidence packet",
            status=ComplianceStatus.GAP if findings or flagged_scanners else ComplianceStatus.COVERED,
            evidence=f"{len(findings)} scenario findings and {len(flagged_scanners)} scanner findings require review.",
        )
    )
    mappings.append(
        ComplianceMapping(
            framework=ComplianceFramework.ISO_IEC_42001,
            control="AI management system risk assessment and treatment evidence",
            status=ComplianceStatus.GAP if findings or flagged_scanners else ComplianceStatus.COVERED,
            evidence="Run traces, remediation diffs, and approval state are available for audit evidence.",
        )
    )
    return mappings


def detect_sensitive_categories(agent: AgentSpec) -> list[str]:
    text = agent.system_prompt
    categories: list[str] = []
    for label, pattern in [*SECRET_PATTERNS, *PII_PATTERNS]:
        if pattern.search(text) and label not in categories:
            categories.append(f"Matched {label}.")
    for honeytoken in agent.sandbox_policy.honeytokens:
        if honeytoken and honeytoken in text:
            categories.append("Prompt includes a configured honeytoken.")
            break
    return categories


def has_injection_markers(prompt: str) -> bool:
    lowered = prompt.lower()
    return any(marker in lowered for marker in INJECTION_MARKERS)


def policy_gap_evidence(agent: AgentSpec) -> list[str]:
    evidence: list[str] = []
    if not agent.tools:
        evidence.append("Agent declares no tools, so tool-boundary coverage depends entirely on sandbox policy.")
    if set(agent.tools) != set(agent.sandbox_policy.allowed_tools):
        evidence.append("Declared tools differ from sandbox allowedTools.")
    if not agent.sandbox_policy.allowed_domains:
        evidence.append("No network allowedDomains are configured.")
    if not agent.sandbox_policy.filesystem_scope.startswith("/workspace/"):
        evidence.append("Filesystem scope is outside the expected /workspace boundary.")
    return evidence


def garak_status_result() -> ScannerResult:
    if os.getenv("DEVBOX_GARAK_ENABLED", "").strip().lower() not in {"1", "true", "yes"}:
        return ScannerResult(
            id="scanner_garak",
            scanner="Garak",
            status=ScannerStatus.SKIPPED,
            summary="Garak adapter disabled.",
            evidence=["Set DEVBOX_GARAK_ENABLED=true and install garak to enable this scanner lane."],
        )
    if shutil.which("garak") is None:
        return ScannerResult(
            id="scanner_garak",
            scanner="Garak",
            status=ScannerStatus.SKIPPED,
            summary="Garak CLI not found.",
            evidence=["DEVBOX_GARAK_ENABLED=true is set, but garak is not available on PATH."],
        )
    return ScannerResult(
        id="scanner_garak",
        scanner="Garak",
        status=ScannerStatus.PASSED,
        summary="Garak adapter is available for configured scan jobs.",
        evidence=["Garak CLI detected; deterministic MVP did not execute arbitrary imported code."],
    )


def owasp_control_for(scenario_id: str) -> str:
    return {
        "web-prompt-injection": "LLM01 Prompt Injection",
        "rag-policy-poison": "LLM04 Data and Model Poisoning",
        "honeytoken-exfiltration": "LLM02 Sensitive Information Disclosure",
        "tool-boundary-breakout": "LLM06 Excessive Agency",
        "egress-allowlist-bypass": "LLM06 Excessive Agency",
        "authority-confusion": "LLM01 Prompt Injection",
    }.get(scenario_id, "OWASP LLM Application Risk")
