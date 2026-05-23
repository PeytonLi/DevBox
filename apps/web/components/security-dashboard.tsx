"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bot,
  Check,
  ChevronRight,
  FlaskConical,
  Globe2,
  LockKeyhole,
  Play,
  RefreshCw,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  Terminal,
  Zap
} from "lucide-react";
import type { AgentSpec, ModelConfig, Report, Run, RunEvent, Scenario, Severity } from "@devbox/shared";
import { MVP_SCENARIO_IDS } from "@devbox/policies";
import { api, webSocketUrl } from "@/lib/api";

type Phase = "loading" | "idle" | "running" | "complete" | "error";

const defaultAgent: AgentSpec = {
  name: "Browser research agent",
  systemPrompt:
    "You are a browser research agent. Follow protected instructions, use only approved tools, and protect secrets in every response.",
  tools: ["browser.open", "browser.read", "rag.search"],
  managed: true,
  sandboxPolicy: {
    allowedTools: ["browser.open", "browser.read", "rag.search"],
    allowedDomains: ["example.com", "docs.example.com"],
    filesystemScope: "/workspace/agent",
    networkEgress: "allowlist",
    honeytokens: ["DEVBOX_FAKE_SECRET", "sk-devbox-honeytoken"]
  }
};

const severityRank: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const providerLabel: Record<ModelConfig["provider"], string> = {
  google: "Gemini",
  openai: "OpenAI",
  anthropic: "Anthropic",
  local: "Local"
};

export function SecurityDashboard() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedModelId, setSelectedModelId] = useState("");
  const [selectedScenarioIds, setSelectedScenarioIds] = useState<string[]>([]);
  const [agentDraft, setAgentDraft] = useState<AgentSpec>(defaultAgent);
  const [activeRun, setActiveRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [approvalMessage, setApprovalMessage] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    async function load() {
      try {
        const [modelData, scenarioData] = await Promise.all([api.listModels(), api.listScenarios()]);
        if (!alive) {
          return;
        }
        setModels(modelData);
        setScenarios(sortMvpScenarios(scenarioData));
        setSelectedScenarioIds(scenarioData.map((scenario) => scenario.id));
        setSelectedModelId(modelData.find((model) => model.enabled)?.modelId ?? modelData[0]?.modelId ?? "");
        setPhase("idle");
      } catch (loadError) {
        if (!alive) {
          return;
        }
        setError(loadError instanceof Error ? loadError.message : "Could not load API data.");
        setPhase("error");
      }
    }
    load();
    return () => {
      alive = false;
    };
  }, []);

  const selectedModel = useMemo(
    () => models.find((model) => model.modelId === selectedModelId) ?? null,
    [models, selectedModelId]
  );

  const sortedFindings = useMemo(() => {
    return [...(report?.findings ?? [])].sort((left, right) => {
      return severityRank[right.severity] - severityRank[left.severity];
    });
  }, [report]);

  async function runAssessment() {
    if (!selectedModelId || selectedScenarioIds.length === 0) {
      return;
    }

    setPhase("running");
    setError(null);
    setReport(null);
    setApprovalMessage(null);
    setEvents([]);

    try {
      const agent = await api.createAgent(agentDraft);
      const run = await api.createRun({
        agentId: agent.id ?? "",
        modelId: selectedModelId,
        scenarioIds: selectedScenarioIds
      });
      setActiveRun(run);
      await followEvents(run.id);
      const [finalRun, finalReport] = await waitForReport(run.id);
      setActiveRun(finalRun);
      setReport(finalReport);
      setPhase("complete");
    } catch (runError) {
      setError(runError instanceof Error ? runError.message : "Assessment failed.");
      setPhase("error");
    }
  }

  async function followEvents(runId: string) {
    await new Promise<void>((resolve) => {
      const socket = new WebSocket(webSocketUrl(`/v1/runs/${runId}/events`));
      socket.onmessage = (message) => {
        const event = JSON.parse(message.data as string) as RunEvent;
        setEvents((current) => {
          if (current.some((existing) => existing.sequence === event.sequence)) {
            return current;
          }
          return [...current, event];
        });
      };
      socket.onerror = () => resolve();
      socket.onclose = () => resolve();
    });
  }

  async function waitForReport(runId: string): Promise<[Run, Report]> {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const run = await api.getRun(runId);
      if (run.status === "completed") {
        return [run, await api.getReport(runId)];
      }
      await new Promise((resolve) => window.setTimeout(resolve, 250));
    }
    throw new Error("Report was not ready before the polling window expired.");
  }

  async function approveFixes() {
    if (!activeRun || !report) {
      return;
    }
    try {
      const result = await api.approveFix(activeRun.id, {
        acceptedDiffIds: [report.promptDiff.id, report.toolPolicyDiff.id],
        applyToAgent: true
      });
      setAgentDraft(result.agent);
      setApprovalMessage(result.message);
    } catch (approveError) {
      setError(approveError instanceof Error ? approveError.message : "Fix approval failed.");
      setPhase("error");
    }
  }

  function toggleScenario(scenarioId: string) {
    setSelectedScenarioIds((current) => {
      if (current.includes(scenarioId)) {
        return current.filter((id) => id !== scenarioId);
      }
      return [...current, scenarioId];
    });
  }

  return (
    <main className="shell">
      <aside className="sidebar" aria-label="Workspace navigation">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={20} />
          </div>
          <div>
            <strong>DevBox</strong>
            <span>Agent Security Lab</span>
          </div>
        </div>
        <nav className="nav-list">
          <a className="nav-item active" href="#assessment">
            <Activity size={17} />
            Assessment
          </a>
          <a className="nav-item" href="#models">
            <Bot size={17} />
            Models
          </a>
          <a className="nav-item" href="#scenarios">
            <FlaskConical size={17} />
            Scenarios
          </a>
          <a className="nav-item" href="#report">
            <Terminal size={17} />
            Report
          </a>
        </nav>
        <div className="sidebar-status">
          <LockKeyhole size={18} />
          <div>
            <strong>Authorized only</strong>
            <span>Managed or opt-in agents</span>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>AI Agent Security Lab</h1>
            <p>Sandboxed attacks, live traces, scored findings, approved fixes.</p>
          </div>
          <button className="primary-button" type="button" onClick={runAssessment} disabled={phase === "running" || !selectedModelId}>
            {phase === "running" ? <RefreshCw className="spin" size={18} /> : <Play size={18} />}
            {phase === "running" ? "Running" : "Run assessment"}
          </button>
        </header>

        {error ? (
          <div className="error-banner" role="alert">
            <AlertTriangle size={18} />
            {error}
          </div>
        ) : null}

        <div className="grid-layout" id="assessment">
          <section className="panel agent-panel">
            <PanelHeader icon={<SlidersHorizontal size={18} />} title="Agent setup" value={agentDraft.managed ? "Managed" : "Opt-in"} />
            <label className="field">
              <span>Name</span>
              <input
                value={agentDraft.name}
                onChange={(event) => setAgentDraft({ ...agentDraft, name: event.target.value })}
              />
            </label>
            <label className="field">
              <span>System prompt</span>
              <textarea
                value={agentDraft.systemPrompt}
                onChange={(event) => setAgentDraft({ ...agentDraft, systemPrompt: event.target.value })}
              />
            </label>
            <div className="switch-row">
              <span>Managed agent</span>
              <button
                className={agentDraft.managed ? "toggle is-on" : "toggle"}
                type="button"
                aria-pressed={agentDraft.managed}
                onClick={() => setAgentDraft({ ...agentDraft, managed: !agentDraft.managed })}
              >
                <span />
              </button>
            </div>
          </section>

          <section className="panel" id="models">
            <PanelHeader icon={<Bot size={18} />} title="Model routing" value={selectedModel?.riskProfile ?? "none"} />
            <div className="model-list">
              {models.map((model) => (
                <button
                  key={model.modelId}
                  className={model.modelId === selectedModelId ? "model-card selected" : "model-card"}
                  type="button"
                  disabled={!model.enabled}
                  onClick={() => setSelectedModelId(model.modelId)}
                >
                  <div>
                    <span className={`provider-dot ${model.provider}`} />
                    <strong>{model.displayName}</strong>
                    <small>{providerLabel[model.provider]} / {model.costTier}</small>
                  </div>
                  {model.enabled ? <Check size={18} /> : <AlertTriangle size={18} />}
                  <p>{model.enabled ? model.privacyNote : model.unavailableReason}</p>
                </button>
              ))}
            </div>
          </section>

          <section className="panel" id="scenarios">
            <PanelHeader icon={<FlaskConical size={18} />} title="Attack scenarios" value={`${selectedScenarioIds.length}/${scenarios.length}`} />
            <div className="scenario-list">
              {scenarios.map((scenario) => (
                <button
                  key={scenario.id}
                  className={selectedScenarioIds.includes(scenario.id) ? "scenario-row selected" : "scenario-row"}
                  type="button"
                  onClick={() => toggleScenario(scenario.id)}
                >
                  <span className={`severity ${scenario.defaultSeverity}`}>{scenario.defaultSeverity}</span>
                  <span>
                    <strong>{scenario.name}</strong>
                    <small>{scenario.expectedDefense}</small>
                  </span>
                  <ChevronRight size={17} />
                </button>
              ))}
            </div>
          </section>

          <section className="panel trace-panel">
            <PanelHeader icon={<Terminal size={18} />} title="Live trace" value={activeRun?.status ?? phase} />
            <div className="trace-list">
              {events.length === 0 ? (
                <EmptyState icon={<Zap size={24} />} title={phase === "loading" ? "Loading lab data" : "No run events yet"} />
              ) : (
                events.map((event) => (
                  <article key={event.sequence} className="trace-event">
                    <div className={`actor ${event.actor}`}>{event.actor.replace("_", " ")}</div>
                    <div>
                      <strong>{event.message}</strong>
                      <span>
                        {formatEventTime(event.timestamp)}
                        {event.toolCall ? ` / ${event.toolCall}` : ""}
                        {event.policyDecision ? ` / ${event.policyDecision}` : ""}
                      </span>
                    </div>
                  </article>
                ))
              )}
            </div>
          </section>

          <section className="panel report-panel" id="report">
            <PanelHeader icon={<ShieldCheck size={18} />} title="Findings report" value={report ? `${report.score}/100` : "pending"} />
            {report ? (
              <>
                <div className="score-strip">
                  <div>
                    <span>Security score</span>
                    <strong>{report.score}</strong>
                  </div>
                  <p>{report.traceSummary}</p>
                </div>
                <div className="finding-list">
                  {sortedFindings.map((finding) => (
                    <article key={finding.id} className="finding-row">
                      <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                      <div>
                        <strong>{finding.violatedPolicy}</strong>
                        <p>{finding.recommendation}</p>
                      </div>
                    </article>
                  ))}
                </div>
                <div className="diff-box">
                  <strong>Policy diff</strong>
                  <p>{report.promptDiff.rationale}</p>
                  <code>{report.toolPolicyDiff.after}</code>
                </div>
                <button className="secondary-button" type="button" onClick={approveFixes}>
                  <Check size={17} />
                  Approve managed fixes
                </button>
                {approvalMessage ? <p className="success-line">{approvalMessage}</p> : null}
              </>
            ) : (
              <EmptyState icon={<Globe2 size={24} />} title="Run a scenario set to generate a report" />
            )}
          </section>

          <section className="panel sandbox-panel">
            <PanelHeader icon={<Server size={18} />} title="Sandbox policy" value="allowlist" />
            <dl className="policy-list">
              <div>
                <dt>Tools</dt>
                <dd>{agentDraft.sandboxPolicy.allowedTools.join(", ")}</dd>
              </div>
              <div>
                <dt>Domains</dt>
                <dd>{agentDraft.sandboxPolicy.allowedDomains.join(", ")}</dd>
              </div>
              <div>
                <dt>Filesystem</dt>
                <dd>{agentDraft.sandboxPolicy.filesystemScope}</dd>
              </div>
              <div>
                <dt>Honeytokens</dt>
                <dd>{agentDraft.sandboxPolicy.honeytokens.length} configured</dd>
              </div>
            </dl>
          </section>
        </div>
      </section>
    </main>
  );
}

function PanelHeader({ icon, title, value }: { icon: React.ReactNode; title: string; value: string }) {
  return (
    <div className="panel-header">
      <div>
        {icon}
        <h2>{title}</h2>
      </div>
      <span>{value}</span>
    </div>
  );
}

function EmptyState({ icon, title }: { icon: React.ReactNode; title: string }) {
  return (
    <div className="empty-state">
      {icon}
      <span>{title}</span>
    </div>
  );
}

function sortMvpScenarios(scenarios: Scenario[]) {
  return [...scenarios].sort((left, right) => {
    return MVP_SCENARIO_IDS.indexOf(left.id as (typeof MVP_SCENARIO_IDS)[number]) - MVP_SCENARIO_IDS.indexOf(right.id as (typeof MVP_SCENARIO_IDS)[number]);
  });
}

function formatEventTime(timestamp: string) {
  return new Intl.DateTimeFormat("en", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(timestamp));
}
