"use client";

import { type ReactNode, useEffect, useMemo, useState } from "react";
import * as Progress from "@radix-ui/react-progress";
import * as Switch from "@radix-ui/react-switch";
import * as Tooltip from "@radix-ui/react-tooltip";
import { motion } from "motion/react";
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

const panelMotion = {
  initial: { opacity: 0, y: 18 },
  animate: { opacity: 1, y: 0 }
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

  const scenarioProgress = scenarios.length === 0 ? 0 : Math.round((selectedScenarioIds.length / scenarios.length) * 100);
  const runDisabled = phase === "running" || !selectedModelId;

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
    <Tooltip.Provider delayDuration={140} skipDelayDuration={120}>
      <main className="shell">
        <aside className="sidebar" aria-label="Workspace navigation">
          <div className="brand">
            <div className="brand-mark">
              <ShieldCheck size={21} />
            </div>
            <div>
              <span className="brand-kicker">DevBox</span>
              <strong>Security Lab</strong>
            </div>
          </div>
          <nav className="nav-list">
            <NavItem href="#assessment" label="Assessment" icon={<Activity size={17} />} active />
            <NavItem href="#models" label="Models" icon={<Bot size={17} />} />
            <NavItem href="#scenarios" label="Scenarios" icon={<FlaskConical size={17} />} />
            <NavItem href="#report" label="Report" icon={<Terminal size={17} />} />
          </nav>
          <div className="sidebar-card">
            <div className="sidebar-status">
              <LockKeyhole size={18} />
              <div>
                <strong>Authorized only</strong>
                <span>Managed or opt-in agents</span>
              </div>
            </div>
            <div className="sidebar-metric">
              <span>Guardrail mode</span>
              <strong>{agentDraft.managed ? "Managed" : "Opt-in"}</strong>
            </div>
          </div>
        </aside>

        <section className="workspace">
          <motion.header
            className="topbar"
            initial={{ opacity: 0, y: -14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease: "easeOut" }}
          >
            <div>
              <span className="eyebrow">Controlled red-team workspace</span>
              <h1>AI Agent Security Lab</h1>
              <p>Sandboxed attacks, live traces, scored findings, approved fixes.</p>
            </div>
            <button className="primary-button" type="button" onClick={runAssessment} disabled={runDisabled}>
              {phase === "running" ? <RefreshCw className="spin" size={18} /> : <Play size={18} />}
              {phase === "running" ? "Running" : "Run assessment"}
            </button>
          </motion.header>

          <div className="status-strip" aria-label="Lab status">
            <StatCard label="Model route" value={selectedModel?.displayName ?? "Loading"} detail={selectedModel?.riskProfile ?? phase} />
            <StatCard label="Scenarios" value={`${selectedScenarioIds.length}/${scenarios.length || "-"}`} detail={`${scenarioProgress}% selected`} />
            <StatCard label="Run events" value={`${events.length}`} detail={activeRun?.status ?? phase} />
            <StatCard label="Score" value={report ? `${report.score}` : "--"} detail={report ? "latest report" : "pending"} />
          </div>

          {error ? (
            <motion.div className="error-banner" role="alert" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
              <AlertTriangle size={18} />
              {error}
            </motion.div>
          ) : null}

          <div className="grid-layout" id="assessment">
            <PanelFrame className="agent-panel" delay={0}>
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
                <label htmlFor="managed-agent">Managed agent</label>
                <Switch.Root
                  className="switch-root"
                  id="managed-agent"
                  checked={agentDraft.managed}
                  aria-label="Managed agent"
                  onCheckedChange={(checked) => setAgentDraft({ ...agentDraft, managed: checked })}
                >
                  <Switch.Thumb className="switch-thumb" />
                </Switch.Root>
              </div>
            </PanelFrame>

            <PanelFrame id="models" delay={0.04}>
              <PanelHeader icon={<Bot size={18} />} title="Model routing" value={selectedModel?.riskProfile ?? "none"} />
              <div className="model-list">
                {models.map((model) => (
                  <motion.button
                    key={model.modelId}
                    className={model.modelId === selectedModelId ? "model-card selected" : "model-card"}
                    type="button"
                    disabled={!model.enabled}
                    onClick={() => setSelectedModelId(model.modelId)}
                    whileHover={model.enabled ? { y: -2 } : undefined}
                    whileTap={model.enabled ? { scale: 0.99 } : undefined}
                  >
                    <div>
                      <span className={`provider-dot ${model.provider}`} />
                      <strong>{model.displayName}</strong>
                      <small>
                        {providerLabel[model.provider]} / {model.costTier}
                      </small>
                    </div>
                    <span className="model-state">{model.enabled ? <Check size={18} /> : <AlertTriangle size={18} />}</span>
                    <p>{model.enabled ? model.privacyNote : model.unavailableReason}</p>
                  </motion.button>
                ))}
              </div>
            </PanelFrame>

            <PanelFrame id="scenarios" delay={0.08}>
              <PanelHeader icon={<FlaskConical size={18} />} title="Attack scenarios" value={`${selectedScenarioIds.length}/${scenarios.length}`} />
              <Progress.Root className="mini-progress" value={scenarioProgress}>
                <Progress.Indicator
                  className="mini-progress-indicator"
                  style={{ transform: `translateX(-${100 - scenarioProgress}%)` }}
                />
              </Progress.Root>
              <div className="scenario-list">
                {scenarios.map((scenario) => (
                  <motion.button
                    key={scenario.id}
                    className={selectedScenarioIds.includes(scenario.id) ? "scenario-row selected" : "scenario-row"}
                    type="button"
                    onClick={() => toggleScenario(scenario.id)}
                    whileHover={{ x: 3 }}
                    whileTap={{ scale: 0.99 }}
                  >
                    <span className={`severity ${scenario.defaultSeverity}`}>{scenario.defaultSeverity}</span>
                    <span>
                      <strong>{scenario.name}</strong>
                      <small>{scenario.expectedDefense}</small>
                    </span>
                    <ChevronRight size={17} />
                  </motion.button>
                ))}
              </div>
            </PanelFrame>

            <PanelFrame className="trace-panel" delay={0.12}>
              <PanelHeader icon={<Terminal size={18} />} title="Live trace" value={activeRun?.status ?? phase} />
              <div className="trace-list">
                {events.length === 0 ? (
                  <EmptyState icon={<Zap size={24} />} title={phase === "loading" ? "Loading lab data" : "No run events yet"} />
                ) : (
                  events.map((event) => (
                    <motion.article
                      key={event.sequence}
                      className="trace-event"
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.22 }}
                    >
                      <div className={`actor ${event.actor}`}>{event.actor.replace("_", " ")}</div>
                      <div>
                        <strong>{event.message}</strong>
                        <span>
                          {formatEventTime(event.timestamp)}
                          {event.toolCall ? ` / ${event.toolCall}` : ""}
                          {event.policyDecision ? ` / ${event.policyDecision}` : ""}
                        </span>
                      </div>
                    </motion.article>
                  ))
                )}
              </div>
            </PanelFrame>

            <PanelFrame className="report-panel" id="report" delay={0.16}>
              <PanelHeader icon={<ShieldCheck size={18} />} title="Findings report" value={report ? `${report.score}/100` : "pending"} />
              {report ? (
                <>
                  <div className="score-strip">
                    <div>
                      <span>Security score</span>
                      <strong>{report.score}</strong>
                    </div>
                    <div>
                      <p>{report.traceSummary}</p>
                      <Progress.Root className="score-progress" value={report.score}>
                        <Progress.Indicator
                          className="score-progress-indicator"
                          style={{ transform: `translateX(-${100 - report.score}%)` }}
                        />
                      </Progress.Root>
                    </div>
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
            </PanelFrame>

            <PanelFrame className="sandbox-panel" delay={0.2}>
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
            </PanelFrame>
          </div>
        </section>
      </main>
    </Tooltip.Provider>
  );
}

function PanelFrame({
  children,
  className,
  delay,
  id
}: {
  children: ReactNode;
  className?: string;
  delay: number;
  id?: string;
}) {
  return (
    <motion.section
      className={className ? `panel ${className}` : "panel"}
      id={id}
      initial={panelMotion.initial}
      animate={panelMotion.animate}
      transition={{ duration: 0.42, delay, ease: "easeOut" }}
    >
      {children}
    </motion.section>
  );
}

function NavItem({ active, href, icon, label }: { active?: boolean; href: string; icon: ReactNode; label: string }) {
  return (
    <Tooltip.Root>
      <Tooltip.Trigger asChild>
        <a className={active ? "nav-item active" : "nav-item"} href={href}>
          {icon}
          <span>{label}</span>
        </a>
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content className="tooltip-content" side="right" sideOffset={10}>
          {label}
          <Tooltip.Arrow className="tooltip-arrow" />
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

function StatCard({ detail, label, value }: { detail: string; label: string; value: string }) {
  return (
    <div className="stat-card">
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function PanelHeader({ icon, title, value }: { icon: ReactNode; title: string; value: string }) {
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

function EmptyState({ icon, title }: { icon: ReactNode; title: string }) {
  return (
    <div className="empty-state">
      {icon}
      <span>{title}</span>
    </div>
  );
}

function sortMvpScenarios(scenarios: Scenario[]) {
  return [...scenarios].sort((left, right) => {
    return (
      MVP_SCENARIO_IDS.indexOf(left.id as (typeof MVP_SCENARIO_IDS)[number]) -
      MVP_SCENARIO_IDS.indexOf(right.id as (typeof MVP_SCENARIO_IDS)[number])
    );
  });
}

function formatEventTime(timestamp: string) {
  return new Intl.DateTimeFormat("en", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit"
  }).format(new Date(timestamp));
}
