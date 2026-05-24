"use client";

import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  Check,
  ChevronRight,
  Cpu,
  Database,
  FileSearch,
  GitBranch,
  Layers,
  ListChecks,
  LockKeyhole,
  Play,
  RefreshCw,
  ScanSearch,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Upload,
  Wrench,
  Zap
} from "lucide-react";
import type {
  AdminSessionResponse,
  AgentImportRecord,
  AgentSpec,
  ComplianceMapping,
  GitHubImportSource,
  ModelConfig,
  Report,
  RequestPrResponse,
  Run,
  RunEvent,
  ScannerResult,
  Scenario,
  TargetAgentTemplate
} from "@devbox/shared";
import { api, webSocketUrl } from "@/lib/api";

type Phase =
  | "idle"
  | "loading"
  | "importing"
  | "registering"
  | "running"
  | "approving"
  | "creating-pr"
  | "error";

type ImportTab = "template" | "github" | "local";
type PipelineStageId = "router" | "engines" | "sandbox" | "compliance";
type StageStatus = "pending" | "active" | "done" | "error";

const defaultImportManifest = JSON.stringify(
  {
    name: "Imported Browser Agent",
    systemPrompt:
      "You are an imported browser research agent. Follow protected instructions, use only approved tools, and protect secrets in every response.",
    systemPromptPath: ".agents/imported-agent.md",
    tools: ["browser.open", "browser.read"],
    allowedDomains: ["example.com", "docs.example.com"],
    filesystemScope: "/workspace/imported-agent",
    honeytokens: ["AGENTSECURE_FAKE_SECRET", "sk-agentsecure-honeytoken"]
  },
  null,
  2
);

const PIPELINE_STAGES: { id: PipelineStageId; label: string; highlight: string; icon: ReactNode }[] = [
  {
    id: "router",
    label: "Risk Router",
    highlight: "Gemini 3.5 Flash intercepts input, scores threat severity, and splits workloads.",
    icon: <Zap size={16} />
  },
  {
    id: "engines",
    label: "Multi-Engine Scan",
    highlight: "Gemma 4 local · Gemini Pro · Garak / Llama Guard run in parallel.",
    icon: <Layers size={16} />
  },
  {
    id: "sandbox",
    label: "Attack & Defend",
    highlight: "Managed Agent sandbox runs OWASP LLM Top 10 adversarial duet.",
    icon: <ShieldAlert size={16} />
  },
  {
    id: "compliance",
    label: "Compliance Report",
    highlight: "Findings mapped to NIST AI RMF and ISO/IEC 42001 controls.",
    icon: <ShieldCheck size={16} />
  }
];

export function SecurityDashboard() {
  const [phase, setPhase] = useState<Phase>("loading");
  const [session, setSession] = useState<AdminSessionResponse | null>(null);
  const [importTab, setImportTab] = useState<ImportTab>("template");
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [targetAgents, setTargetAgents] = useState<TargetAgentTemplate[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [selectedModelId, setSelectedModelId] = useState("");
  const [selectedScenarioIds, setSelectedScenarioIds] = useState<string[]>([]);
  const [registeredAgent, setRegisteredAgent] = useState<AgentSpec | null>(null);
  const [githubSource, setGithubSource] = useState<GitHubImportSource>({
    owner: "PeytonLi",
    repo: "AgentSecure",
    ref: "main",
    promptPath: ".agents/AGENTS.md",
    manifestPath: ".devbox/agent.json"
  });
  const [githubImport, setGithubImport] = useState<AgentImportRecord | null>(null);
  const [importManifest, setImportManifest] = useState(defaultImportManifest);
  const [manifestFileName, setManifestFileName] = useState("agent.json");
  const [promptFile, setPromptFile] = useState<File | null>(null);
  const [importWarnings, setImportWarnings] = useState<string[]>([]);
  const [allowCloudAnalysis, setAllowCloudAnalysis] = useState(false);
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [prResult, setPrResult] = useState<RequestPrResponse | null>(null);
  const [approvalMessage, setApprovalMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let mounted = true;

    async function loadOptions() {
      setPhase("loading");
      setError(null);
      try {
        const sessionData = await api.getSession();
        if (!mounted) return;
        setSession(sessionData);
        if (!sessionData.authenticated) {
          setPhase("idle");
          return;
        }
        const [modelData, scenarioData, targetData] = await Promise.all([
          api.listModels(),
          api.listScenarios(),
          api.listTargetAgents()
        ]);
        if (!mounted) return;
        setModels(modelData);
        setScenarios(scenarioData);
        setTargetAgents(targetData);
        setSelectedModelId(
          modelData.find((model) => model.provider === "google" && model.enabled)?.modelId ??
            modelData.find((model) => model.enabled)?.modelId ??
            modelData[0]?.modelId ??
            ""
        );
        setSelectedTargetId(targetData[0]?.id ?? "");
        setSelectedScenarioIds(targetData[0]?.recommendedScenarioIds ?? scenarioData.map((scenario) => scenario.id));
        setPhase("idle");
      } catch (loadError) {
        if (!mounted) return;
        setError(loadError instanceof Error ? loadError.message : "Could not load AgentSecure options.");
        setPhase("error");
      }
    }

    loadOptions();
    return () => {
      mounted = false;
      socketRef.current?.close();
    };
  }, []);

  const selectedTarget = useMemo(
    () => targetAgents.find((target) => target.id === selectedTargetId) ?? null,
    [selectedTargetId, targetAgents]
  );
  const selectedModel = useMemo(
    () => models.find((model) => model.modelId === selectedModelId) ?? null,
    [selectedModelId, models]
  );
  const requiresCloudApproval = selectedModel?.riskProfile === "cloud";
  const missingCloudApproval = requiresCloudApproval && !allowCloudAnalysis;
  const activeAgent = registeredAgent ?? selectedTarget?.agentSpec ?? null;
  const agentLabel = selectedTarget?.name ?? registeredAgent?.name ?? "No agent selected";

  const stageStatuses = useMemo(() => deriveStageStatuses(phase, events, report), [phase, events, report]);

  async function runTargetAssessment() {
    if (!selectedModel || selectedScenarioIds.length === 0 || (!selectedTarget && !registeredAgent)) {
      setError("Select or import an agent, choose a model, and keep at least one scenario.");
      setPhase("error");
      return;
    }
    if (selectedModel.riskProfile === "cloud" && !allowCloudAnalysis) {
      setError(`Approve cloud analysis before using ${selectedModel.displayName}.`);
      setPhase("error");
      return;
    }

    socketRef.current?.close();
    setPhase("registering");
    setError(null);
    setEvents([]);
    setReport(null);
    setRun(null);
    setApprovalMessage(null);
    setPrResult(null);

    try {
      const agent = selectedTarget ? await api.registerTargetAgent(selectedTarget.id) : registeredAgent;
      if (!agent?.id) throw new Error("Imported agent is not ready.");
      setRegisteredAgent(agent);
      setPhase("running");
      const createdRun = await api.createRun({
        agentId: agent.id,
        modelId: selectedModel.modelId,
        scenarioIds: selectedScenarioIds,
        allowCloudAnalysis: selectedModel.riskProfile === "cloud" && allowCloudAnalysis
      });
      setRun(createdRun);
      if (selectedModel.riskProfile === "cloud") setAllowCloudAnalysis(false);
      await connectRunStream(createdRun.id);
    } catch (runError) {
      setError(runError instanceof Error ? runError.message : "Could not start agent scan.");
      setPhase("error");
    }
  }

  async function importAgentProject() {
    setPhase("importing");
    setError(null);
    setImportWarnings([]);
    try {
      const manifestText = importManifest.trim();
      if (!manifestText) throw new Error("Agent manifest is empty.");
      JSON.parse(manifestText);
      const manifest = new File([manifestText], manifestFileName.endsWith(".json") ? manifestFileName : "agent.json", {
        type: "application/json"
      });
      const imported = await api.importAgentProject(manifest, promptFile);
      setImportTab("local");
      setSelectedTargetId("");
      setRegisteredAgent(imported.agent);
      setSelectedScenarioIds(
        imported.recommendedScenarioIds.length > 0 ? imported.recommendedScenarioIds : scenarios.map((s) => s.id)
      );
      resetRunState();
      setGithubImport(null);
      setImportWarnings(imported.warnings);
      setPhase("idle");
    } catch (importError) {
      setError(importError instanceof Error ? importError.message : "Could not import agent project.");
      setPhase("error");
    }
  }

  async function importGitHubAgent() {
    setPhase("importing");
    setError(null);
    setImportWarnings([]);
    try {
      const imported = await api.importGitHubAgent(githubSource);
      setImportTab("github");
      setSelectedTargetId("");
      setRegisteredAgent(imported.agent);
      setGithubImport(imported);
      setSelectedScenarioIds(
        imported.recommendedScenarioIds.length > 0 ? imported.recommendedScenarioIds : scenarios.map((s) => s.id)
      );
      resetRunState();
      setImportWarnings(imported.warnings);
      setPhase("idle");
    } catch (importError) {
      setError(importError instanceof Error ? importError.message : "Could not import GitHub agent.");
      setPhase("error");
    }
  }

  function resetRunState() {
    setRun(null);
    setEvents([]);
    setReport(null);
    setApprovalMessage(null);
    setPrResult(null);
  }

  async function loadManifestFile(file: File | null) {
    if (!file) return;
    setManifestFileName(file.name);
    setImportManifest(await file.text());
  }

  async function connectRunStream(runId: string) {
    const streamToken = await api.getRunEventsToken(runId);
    const socket = new WebSocket(webSocketUrl(`/v1/runs/${runId}/events`, { token: streamToken.token }));
    socketRef.current = socket;
    let streamFailed = false;
    let fallbackStarted = false;

    const recoverRun = () => {
      if (socketRef.current !== socket || fallbackStarted) {
        return;
      }
      fallbackStarted = true;
      void fetchCompletedRun(runId, { pollUntilTerminal: streamFailed });
    };

    socket.onmessage = (event) => {
      if (socketRef.current !== socket) {
        return;
      }
      try {
        const payload = JSON.parse(event.data) as RunEvent;
        setEvents((current) => {
          if (current.some((item) => item.sequence === payload.sequence)) {
            return current;
          }
          return [...current, payload].sort((a, b) => a.sequence - b.sequence);
        });
      } catch {
        streamFailed = true;
        socket.close();
      }
    };

    socket.onclose = () => {
      recoverRun();
    };

    socket.onerror = () => {
      streamFailed = true;
      recoverRun();
      socket.close();
    };
  }

  async function fetchCompletedRun(runId: string, options: { pollUntilTerminal?: boolean } = {}) {
    try {
      const latestRun = await api.getRun(runId);
      setRun(latestRun);
      if (latestRun.status === "completed") {
        const latestReport = await api.getReport(runId);
        setReport(latestReport);
        setError(null);
        setPhase("idle");
        return;
      }
      if (latestRun.status === "failed") {
        setError("Assessment failed. Review the live trace for the backend error.");
        setPhase("error");
        return;
      }
      if (options.pollUntilTerminal) {
        setPhase("running");
        window.setTimeout(() => {
          void fetchCompletedRun(runId, options);
        }, 1500);
        return;
      }
      setPhase("idle");
    } catch (reportError) {
      setError(reportError instanceof Error ? reportError.message : "Could not load scan report.");
      setPhase("error");
    }
  }

  async function approveTargetFix() {
    if (!run || !report) return;
    setPhase("approving");
    setError(null);
    try {
      const response = await api.approveFix(run.id, {
        acceptedDiffIds: [report.promptDiff.id, report.toolPolicyDiff.id],
        applyToAgent: true
      });
      setRegisteredAgent(response.agent);
      setApprovalMessage(response.message);
      setPhase("idle");
    } catch (approvalError) {
      setError(approvalError instanceof Error ? approvalError.message : "Could not apply remediation.");
      setPhase("error");
    }
  }

  async function createGitHubPr() {
    if (!run || !report) return;
    setPhase("creating-pr");
    setError(null);
    try {
      const response = await api.approveRunPr(run.id, {
        acceptedDiffIds: [report.promptDiff.id],
        applyToAgent: false
      });
      setPrResult(response);
      setApprovalMessage("GitHub PR created from the approved prompt remediation.");
      setPhase("idle");
    } catch (prError) {
      setError(prError instanceof Error ? prError.message : "Could not create GitHub PR.");
      setPhase("error");
    }
  }

  function selectTarget(target: TargetAgentTemplate) {
    setImportTab("template");
    setSelectedTargetId(target.id);
    setSelectedScenarioIds(target.recommendedScenarioIds);
    setRegisteredAgent(null);
    resetRunState();
    setGithubImport(null);
    setImportWarnings([]);
  }

  function selectModel(model: ModelConfig) {
    setSelectedModelId(model.modelId);
    setAllowCloudAnalysis(false);
  }

  function toggleScenario(scenarioId: string) {
    setSelectedScenarioIds((current) =>
      current.includes(scenarioId) ? current.filter((id) => id !== scenarioId) : [...current, scenarioId]
    );
  }

  if (session && !session.authenticated) {
    return (
      <main className="login-shell">
        <section className="login-panel">
          <div className="brand-mark">
            <ShieldCheck size={24} />
          </div>
          <span className="eyebrow">AgentSecure</span>
          <h1>Admin login required</h1>
          <p>Use the allowlisted GitHub account before importing agents and running security scans.</p>
          <a className="primary-button login-button" href={session.loginUrl}>
            <GitBranch size={18} />
            Continue with GitHub
          </a>
        </section>
      </main>
    );
  }

  const isScanning = phase === "registering" || phase === "running";

  return (
    <main className="shell">
      <aside className="sidebar" aria-label="Workspace navigation">
        <div className="brand">
          <div className="brand-mark">
            <Shield size={21} />
          </div>
          <div>
            <span className="brand-kicker">AgentSecure</span>
            <strong>Agent Scan</strong>
          </div>
        </div>
        <nav className="nav-list">
          <NavAnchor href="#configure" icon={<Bot size={17} />} label="Configure agent" />
          <NavAnchor href="#engine" icon={<Cpu size={17} />} label="Scan engine" />
          <NavAnchor href="#scenarios" icon={<ListChecks size={17} />} label="Attack scenarios" />
          <NavAnchor href="#pipeline" icon={<ScanSearch size={17} />} label="Live pipeline" />
          <NavAnchor href="#results" icon={<ShieldCheck size={17} />} label="Security report" />
        </nav>
        <div className="sidebar-card">
          <div className="sidebar-status">
            <LockKeyhole size={18} />
            <div>
              <strong>Dual-engine security</strong>
              <span>Cloud router + local privacy sandbox</span>
            </div>
          </div>
          <div className="sidebar-metric">
            <span>Security score</span>
            <strong>{report ? `${report.score}/100` : isScanning ? "Scanning…" : "—"}</strong>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <span className="eyebrow">Hybrid multi-model agent security</span>
            <h1>Agent Scan</h1>
            <p>
              Route workloads through Gemini 3.5 Flash, scan with local Gemma 4 and open-source tools, run adversarial
              attack/defend in a Managed Agent sandbox, and generate compliance-ready reports.
            </p>
          </div>
          <button
            className="primary-button"
            type="button"
            onClick={runTargetAssessment}
            disabled={
              phase === "importing" ||
              phase === "registering" ||
              phase === "running" ||
              phase === "loading" ||
              phase === "approving" ||
              phase === "creating-pr" ||
              missingCloudApproval
            }
          >
            {isScanning ? <RefreshCw className="spin" size={18} /> : <Play size={18} />}
            {phase === "running" ? "Scanning…" : phase === "registering" ? "Initializing…" : "Run security scan"}
          </button>
        </header>

        <ScanPipeline stages={PIPELINE_STAGES} statuses={stageStatuses} />

        <div className="status-strip" aria-label="Scan status">
          <StatCard label="Agent" value={agentLabel} detail={selectedTarget?.category ?? githubImport?.repository.fullName ?? "configured"} />
          <StatCard label="Engine" value={selectedModel?.displayName ?? "None"} detail={selectedModel?.provider ?? "model"} />
          <StatCard label="Scan" value={run?.status ?? "Ready"} detail={run?.id ? run.id.slice(0, 12) : `${selectedScenarioIds.length} scenarios`} />
          <StatCard label="Findings" value={report ? String(report.findings.length) : isScanning ? "…" : "0"} detail={report ? `${report.scannerResults.length} scanner hits` : "awaiting scan"} />
        </div>

        {error ? (
          <div className="error-banner" role="alert">
            <AlertTriangle size={18} />
            {error}
          </div>
        ) : null}

        <div className="scan-flow">
          <section className="scan-section panel" id="configure">
            <SectionHeader
              step={1}
              icon={<Server size={18} />}
              title="Configure agent"
              subtitle="Select a template or import your agent project file"
              badge={agentLabel}
            />
            <div className="import-tabs">
              {(["template", "github", "local"] as ImportTab[]).map((tab) => (
                <button
                  key={tab}
                  type="button"
                  className={importTab === tab ? "import-tab active" : "import-tab"}
                  onClick={() => setImportTab(tab)}
                >
                  {tab === "template" ? "Templates" : tab === "github" ? "GitHub" : "Local file"}
                </button>
              ))}
            </div>

            {importTab === "template" ? (
              <div className="model-list compact">
                {targetAgents.map((target) => (
                  <button
                    key={target.id}
                    className={selectedTargetId === target.id ? "model-card selected" : "model-card"}
                    type="button"
                    onClick={() => selectTarget(target)}
                  >
                    <div>
                      <strong>{target.name}</strong>
                      <small>{target.category}</small>
                    </div>
                    {selectedTargetId === target.id ? <Check size={17} /> : null}
                    <p>{target.description}</p>
                  </button>
                ))}
              </div>
            ) : null}

            {importTab === "github" ? (
              <div className="import-body">
                <div className="github-import-grid">
                  <label className="field">
                    <span>Owner</span>
                    <input value={githubSource.owner} onChange={(e) => setGithubSource((c) => ({ ...c, owner: e.target.value }))} />
                  </label>
                  <label className="field">
                    <span>Repository</span>
                    <input value={githubSource.repo} onChange={(e) => setGithubSource((c) => ({ ...c, repo: e.target.value }))} />
                  </label>
                  <label className="field">
                    <span>Ref</span>
                    <input value={githubSource.ref ?? ""} onChange={(e) => setGithubSource((c) => ({ ...c, ref: e.target.value }))} />
                  </label>
                  <label className="field">
                    <span>Prompt path</span>
                    <input value={githubSource.promptPath} onChange={(e) => setGithubSource((c) => ({ ...c, promptPath: e.target.value }))} />
                  </label>
                  <label className="field">
                    <span>Manifest path</span>
                    <input
                      value={githubSource.manifestPath ?? ""}
                      onChange={(e) => setGithubSource((c) => ({ ...c, manifestPath: e.target.value || null }))}
                    />
                  </label>
                  <label className="field">
                    <span>Installation ID</span>
                    <input
                      value={githubSource.installationId ?? ""}
                      onChange={(e) =>
                        setGithubSource((c) => ({ ...c, installationId: e.target.value ? Number(e.target.value) : null }))
                      }
                    />
                  </label>
                </div>
                <button className="secondary-button inline" type="button" onClick={importGitHubAgent} disabled={phase === "importing"}>
                  {phase === "importing" ? <RefreshCw className="spin" size={17} /> : <GitBranch size={17} />}
                  Import from GitHub
                </button>
                {githubImport ? (
                  <div className="import-status">
                    <strong>{githubImport.repository.fullName}</strong>
                    <span>
                      {githubImport.source.promptPath} / {githubImport.commitSha ?? "latest ref"}
                    </span>
                  </div>
                ) : null}
              </div>
            ) : null}

            {importTab === "local" ? (
              <div className="import-body">
                <label className="field">
                  <span>Manifest JSON</span>
                  <textarea className="manifest-input compact" value={importManifest} onChange={(e) => setImportManifest(e.target.value)} />
                </label>
                <div className="file-grid">
                  <label className="file-field">
                    <span>Manifest file</span>
                    <input type="file" accept="application/json,.json" onChange={(e) => void loadManifestFile(e.target.files?.[0] ?? null)} />
                  </label>
                  <label className="file-field">
                    <span>Prompt file</span>
                    <input type="file" accept=".md,.txt,text/markdown,text/plain" onChange={(e) => setPromptFile(e.target.files?.[0] ?? null)} />
                  </label>
                </div>
                <button className="secondary-button inline" type="button" onClick={importAgentProject} disabled={phase === "importing"}>
                  {phase === "importing" ? <RefreshCw className="spin" size={17} /> : <Upload size={17} />}
                  Import agent
                </button>
                {registeredAgent && !selectedTarget ? (
                  <div className="import-status">
                    <strong>{registeredAgent.name}</strong>
                    <span>{registeredAgent.promptPath ?? "inline prompt"}</span>
                  </div>
                ) : null}
              </div>
            ) : null}

            {importWarnings.length > 0 ? (
              <ul className="warning-list">
                {importWarnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            ) : null}
          </section>

          <section className="scan-section panel" id="engine">
            <SectionHeader
              step={2}
              icon={<Database size={18} />}
              title="Scan engine"
              subtitle="High-speed router and analysis models for threat routing"
              badge={selectedModel?.provider ?? "engine"}
            />
            <div className="model-list compact">
              {models.map((model) => (
                <button
                  key={model.modelId}
                  className={selectedModelId === model.modelId ? "model-card selected" : "model-card"}
                  type="button"
                  disabled={!model.enabled}
                  onClick={() => selectModel(model)}
                >
                  <div>
                    <strong>
                      <span className={`provider-dot ${model.provider}`} />
                      {model.displayName}
                    </strong>
                    <small>{model.riskProfile} · {model.costTier}</small>
                  </div>
                  <span className="model-state">{model.enabled ? "ready" : "off"}</span>
                  <p>{model.enabled ? model.privacyNote : model.unavailableReason ?? "Unavailable"}</p>
                </button>
              ))}
            </div>
            {requiresCloudApproval ? (
              <div className="switch-row cloud-approval-row">
                <div>
                  <span>Approve cloud analysis</span>
                  <small>{selectedModel?.displayName} can process selected run data in the cloud.</small>
                </div>
                <button
                  className={allowCloudAnalysis ? "toggle is-on" : "toggle"}
                  type="button"
                  aria-pressed={allowCloudAnalysis}
                  onClick={() => setAllowCloudAnalysis((c) => !c)}
                >
                  <span />
                </button>
              </div>
            ) : null}
          </section>

          <section className="scan-section panel" id="scenarios">
            <SectionHeader
              step={3}
              icon={<ListChecks size={18} />}
              title="Attack scenarios"
              subtitle="OWASP LLM Top 10 mapped adversarial tests"
              badge={`${selectedScenarioIds.length} active`}
            />
            <div className="scenario-list compact">
              {scenarios.map((scenario) => (
                <button
                  key={scenario.id}
                  className={selectedScenarioIds.includes(scenario.id) ? "scenario-row selected" : "scenario-row"}
                  type="button"
                  onClick={() => toggleScenario(scenario.id)}
                >
                  {selectedScenarioIds.includes(scenario.id) ? <Check size={16} /> : <FileSearch size={16} />}
                  <div>
                    <strong>{scenario.name}</strong>
                    <small>{scenario.attackGoal}</small>
                  </div>
                  <span className={`severity ${scenario.defaultSeverity}`}>{scenario.defaultSeverity}</span>
                </button>
              ))}
            </div>
          </section>

          <section className="scan-section panel pipeline-panel" id="pipeline">
            <SectionHeader
              step={4}
              icon={<Terminal size={18} />}
              title="Live pipeline"
              subtitle="Real-time trace as workloads route through each security stage"
              badge={run?.status ?? "idle"}
            />
            <div className="stage-cards">
              {PIPELINE_STAGES.map((stage) => (
                <StageCard key={stage.id} stage={stage} status={stageStatuses[stage.id]} eventCount={countStageEvents(stage.id, events)} />
              ))}
            </div>
            {events.length > 0 ? (
              <div className="trace-list">
                {events.map((event) => (
                  <div className="trace-event" key={event.sequence}>
                    <span className={`actor ${event.actor}`}>{event.actor.replace("_", " ")}</span>
                    <div>
                      <strong>{event.message}</strong>
                      <span>
                        #{event.sequence}
                        {event.toolCall ? ` · ${event.toolCall}` : ""}
                        {event.policyDecision ? ` · ${event.policyDecision}` : ""}
                        {event.riskSignal ? ` · ${event.riskSignal}` : ""}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={<Sparkles size={24} />} title="Run a scan to watch the dual-engine pipeline in action" />
            )}
          </section>

          <section className="scan-section panel results-panel" id="results">
            <SectionHeader
              step={5}
              icon={<ShieldCheck size={18} />}
              title="Security report"
              subtitle="Findings, scanner output, risk routes, and compliance mappings"
              badge={report ? `${report.score}/100` : "pending"}
            />
            {report ? (
              <>
                <div className="score-strip">
                  <strong className={scoreClass(report.score)}>{report.score}</strong>
                  <div>
                    <span>Security score</span>
                    <p>{report.traceSummary}</p>
                    <div className="score-progress">
                      <div className="score-progress-indicator" style={{ transform: `translateX(-${100 - report.score}%)` }} />
                    </div>
                  </div>
                </div>

                {report.riskRoutes.length > 0 ? (
                  <div className="result-block">
                    <h3>Risk routing</h3>
                    <div className="route-cards">
                      {report.riskRoutes.map((route, i) => (
                        <div className="route-card" key={`${route.lane}-${i}`}>
                          <span className={`lane-badge ${route.lane}`}>{route.lane}</span>
                          <span className={`severity ${route.severity}`}>{route.severity}</span>
                          <p>{route.rationale}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : null}

                {report.scannerResults.length > 0 ? (
                  <div className="result-block">
                    <h3>Scanner results</h3>
                    <ScannerResultsList results={report.scannerResults} />
                  </div>
                ) : null}

                <div className="result-block">
                  <h3>Findings</h3>
                  {report.findings.length > 0 ? (
                    <div className="finding-list compact">
                      {report.findings.map((finding) => (
                        <div className="finding-row" key={finding.id}>
                          <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                          <div>
                            <strong>{finding.violatedPolicy}</strong>
                            <p>{finding.evidence}</p>
                            <small>{finding.recommendation}</small>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted-note">No critical findings detected in this scan.</p>
                  )}
                </div>

                {report.complianceMappings.length > 0 ? (
                  <div className="result-block">
                    <h3>Compliance layer</h3>
                    <ComplianceTable mappings={report.complianceMappings} />
                  </div>
                ) : null}

                <div className="remediation-box">
                  <Wrench size={18} />
                  <div>
                    <strong>Defender remediation available</strong>
                    <p>Review the proposed prompt and policy hardening, then apply fixes to your agent configuration.</p>
                  </div>
                  <button
                    className="secondary-button inline"
                    type="button"
                    onClick={approveTargetFix}
                    disabled={phase === "approving" || phase === "creating-pr"}
                  >
                    {phase === "approving" ? <RefreshCw className="spin" size={17} /> : <Wrench size={17} />}
                    Apply remediation
                  </button>
                  <button
                    className="secondary-button inline"
                    type="button"
                    onClick={createGitHubPr}
                    disabled={phase === "approving" || phase === "creating-pr"}
                  >
                    {phase === "creating-pr" ? <RefreshCw className="spin" size={17} /> : <GitBranch size={17} />}
                    Create GitHub PR
                  </button>
                </div>
                {approvalMessage ? <p className="success-line">{approvalMessage}</p> : null}
                {prResult?.prUrl ? (
                  <p className="success-line">
                    PR ready: <a href={prResult.prUrl}>{prResult.prUrl}</a>
                  </p>
                ) : null}
              </>
            ) : (
              <EmptyState icon={<ShieldCheck size={24} />} title="Complete a scan to generate your security scorecard and compliance report" />
            )}
          </section>

          {activeAgent ? (
            <section className="scan-section panel policy-panel">
              <SectionHeader
                step={6}
                icon={<LockKeyhole size={18} />}
                title="Sandbox policy"
                subtitle="Tool bindings, domain allowlist, and honeytoken traps"
                badge={activeAgent.runtime?.agentKey ?? "policy"}
              />
              <PolicySummary agent={activeAgent} />
            </section>
          ) : null}
        </div>
      </section>
    </main>
  );
}

function deriveStageStatuses(phase: Phase, events: RunEvent[], report: Report | null): Record<PipelineStageId, StageStatus> {
  if (phase === "error") {
    return { router: "error", engines: "pending", sandbox: "pending", compliance: "pending" };
  }
  if (report) {
    return { router: "done", engines: "done", sandbox: "done", compliance: "done" };
  }
  if (phase === "idle" || phase === "loading" || phase === "importing" || phase === "approving" || phase === "creating-pr") {
    return { router: "pending", engines: "pending", sandbox: "pending", compliance: "pending" };
  }
  if (phase === "registering") {
    return { router: "active", engines: "pending", sandbox: "pending", compliance: "pending" };
  }
  const hasAttacker = events.some((e) => e.actor === "attacker" || e.actor === "target_agent");
  const hasDefender = events.some((e) => e.actor === "defender");
  const hasScanner = events.some((e) => e.message.toLowerCase().includes("scanner") || e.message.toLowerCase().includes("garak"));
  if (hasDefender) {
    return { router: "done", engines: "done", sandbox: "done", compliance: "active" };
  }
  if (hasAttacker) {
    return { router: "done", engines: hasScanner ? "done" : "active", sandbox: "active", compliance: "pending" };
  }
  if (events.length > 0) {
    return { router: "done", engines: "active", sandbox: "pending", compliance: "pending" };
  }
  return { router: "active", engines: "pending", sandbox: "pending", compliance: "pending" };
}

function countStageEvents(stageId: PipelineStageId, events: RunEvent[]): number {
  const filters: Record<PipelineStageId, (e: RunEvent) => boolean> = {
    router: (e) => e.actor === "system" && (e.message.toLowerCase().includes("route") || e.message.toLowerCase().includes("risk")),
    engines: (e) => e.message.toLowerCase().includes("scanner") || e.message.toLowerCase().includes("local") || e.message.toLowerCase().includes("garak"),
    sandbox: (e) => e.actor === "attacker" || e.actor === "defender" || e.actor === "target_agent" || e.actor === "sandbox",
    compliance: (e) => e.message.toLowerCase().includes("compliance") || e.message.toLowerCase().includes("report") || e.actor === "defender"
  };
  return events.filter(filters[stageId]).length;
}

function scoreClass(score: number): string {
  if (score >= 80) return "score-good";
  if (score >= 60) return "score-warn";
  return "score-bad";
}

function ScanPipeline({
  stages,
  statuses
}: {
  stages: typeof PIPELINE_STAGES;
  statuses: Record<PipelineStageId, StageStatus>;
}) {
  return (
    <div className="scan-pipeline" aria-label="Security scan pipeline">
      {stages.map((stage, index) => (
        <div key={stage.id} className="pipeline-node-wrap">
          <div className={`pipeline-node ${statuses[stage.id]}`}>
            <div className="pipeline-node-icon">{stage.icon}</div>
            <div className="pipeline-node-text">
              <strong>{stage.label}</strong>
              <span>{stage.highlight}</span>
            </div>
            <PipelineStatusBadge status={statuses[stage.id]} />
          </div>
          {index < stages.length - 1 ? <ChevronRight className="pipeline-arrow" size={18} /> : null}
        </div>
      ))}
    </div>
  );
}

function PipelineStatusBadge({ status }: { status: StageStatus }) {
  const labels: Record<StageStatus, string> = {
    pending: "Waiting",
    active: "Running",
    done: "Complete",
    error: "Failed"
  };
  return <span className={`pipeline-badge ${status}`}>{labels[status]}</span>;
}

function StageCard({
  stage,
  status,
  eventCount
}: {
  stage: (typeof PIPELINE_STAGES)[number];
  status: StageStatus;
  eventCount: number;
}) {
  return (
    <div className={`stage-card ${status}`}>
      <div className="stage-card-head">
        {stage.icon}
        <strong>{stage.label}</strong>
        <PipelineStatusBadge status={status} />
      </div>
      <p>{stage.highlight}</p>
      {eventCount > 0 ? <span className="stage-event-count">{eventCount} events</span> : null}
    </div>
  );
}

function ScannerResultsList({ results }: { results: ScannerResult[] }) {
  return (
    <div className="scanner-grid">
      {results.map((result) => (
        <div className={`scanner-card ${result.status}`} key={result.id}>
          <div className="scanner-card-head">
            <strong>{result.scanner}</strong>
            <span className={`scanner-status ${result.status}`}>{result.status}</span>
          </div>
          <p>{result.summary}</p>
          {result.severity ? <span className={`severity ${result.severity}`}>{result.severity}</span> : null}
        </div>
      ))}
    </div>
  );
}

function ComplianceTable({ mappings }: { mappings: ComplianceMapping[] }) {
  const frameworkLabels: Record<string, string> = {
    nist_ai_rmf: "NIST AI RMF",
    iso_iec_42001: "ISO/IEC 42001",
    owasp_llm_top_10: "OWASP LLM Top 10"
  };
  return (
    <div className="compliance-table">
      {mappings.map((mapping, i) => (
        <div className={`compliance-row ${mapping.status}`} key={`${mapping.control}-${i}`}>
          <span className="compliance-framework">{frameworkLabels[mapping.framework] ?? mapping.framework}</span>
          <strong>{mapping.control}</strong>
          <span className={`compliance-status ${mapping.status}`}>{mapping.status.replace("_", " ")}</span>
          <p>{mapping.evidence}</p>
        </div>
      ))}
    </div>
  );
}

function NavAnchor({ href, icon, label }: { href: string; icon: ReactNode; label: string }) {
  return (
    <a className="nav-item" href={href}>
      {icon}
      <span>{label}</span>
    </a>
  );
}

function SectionHeader({
  step,
  icon,
  title,
  subtitle,
  badge
}: {
  step: number;
  icon: ReactNode;
  title: string;
  subtitle: string;
  badge: string;
}) {
  return (
    <div className="section-header">
      <div className="section-header-main">
        <span className="step-badge">{step}</span>
        {icon}
        <div>
          <h2>{title}</h2>
          <p>{subtitle}</p>
        </div>
      </div>
      <span className="section-badge">{badge}</span>
    </div>
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

function PolicySummary({ agent }: { agent: AgentSpec | null }) {
  if (!agent) {
    return <EmptyState icon={<LockKeyhole size={24} />} title="Configure an agent to inspect sandbox policy" />;
  }
  return (
    <dl className="policy-list">
      <div>
        <dt>Tools</dt>
        <dd>{agent.sandboxPolicy.allowedTools.join(", ")}</dd>
      </div>
      <div>
        <dt>Domains</dt>
        <dd>{agent.sandboxPolicy.allowedDomains.join(", ")}</dd>
      </div>
      <div>
        <dt>Filesystem</dt>
        <dd>{agent.sandboxPolicy.filesystemScope}</dd>
      </div>
      <div>
        <dt>Honeytokens</dt>
        <dd>{agent.sandboxPolicy.honeytokens.join(", ")}</dd>
      </div>
    </dl>
  );
}

function EmptyState({ icon, title }: { icon: ReactNode; title: string }) {
  return (
    <div className="empty-state compact">
      {icon}
      <span>{title}</span>
    </div>
  );
}
