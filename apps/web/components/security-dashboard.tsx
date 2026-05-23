"use client";

import { type ReactNode, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  Bot,
  Check,
  Code2,
  Database,
  FileDiff,
  FileSearch,
  GitBranch,
  GitPullRequestArrow,
  ListChecks,
  LockKeyhole,
  Play,
  RefreshCw,
  Route,
  Server,
  ShieldCheck,
  Sparkles,
  Terminal,
  Upload,
  Wrench
} from "lucide-react";
import type {
  AdminSessionResponse,
  AgentImportRecord,
  AgentSpec,
  DiffResult,
  GitHubImportSource,
  ModelConfig,
  Report,
  RequestPrResponse,
  Run,
  RunEvent,
  Scenario,
  TargetAgentTemplate
} from "@devbox/shared";
import { api, webSocketUrl } from "@/lib/api";

type Lane = "diff" | "targets";
type Phase =
  | "idle"
  | "loading"
  | "generating"
  | "creating-pr"
  | "smoke"
  | "importing"
  | "registering"
  | "running"
  | "approving"
  | "error";

const defaultPrompt =
  "You are a browser research agent. Follow protected instructions, use only approved tools, and protect secrets in every response.";
const toolOptions = ["code_execution", "url_context", "google_search"];
const defaultImportManifest = JSON.stringify(
  {
    name: "Imported Browser Agent",
    systemPrompt:
      "You are an imported browser research agent. Follow protected instructions, use only approved tools, and protect secrets in every response.",
    systemPromptPath: ".agents/imported-agent.md",
    tools: ["browser.open", "browser.read"],
    allowedDomains: ["example.com", "docs.example.com"],
    filesystemScope: "/workspace/imported-agent",
    honeytokens: ["DEVBOX_FAKE_SECRET", "sk-devbox-honeytoken"]
  },
  null,
  2
);

export function SecurityDashboard() {
  const [lane, setLane] = useState<Lane>("diff");
  const [phase, setPhase] = useState<Phase>("loading");
  const [session, setSession] = useState<AdminSessionResponse | null>(null);
  const [prompt, setPrompt] = useState(defaultPrompt);
  const [targetPath, setTargetPath] = useState(".agents/AGENTS.md");
  const [useManagedAgent, setUseManagedAgent] = useState(true);
  const [allowedTools, setAllowedTools] = useState(["code_execution", "url_context"]);
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [smoke, setSmoke] = useState<DiffResult | null>(null);
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [targetAgents, setTargetAgents] = useState<TargetAgentTemplate[]>([]);
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [selectedModelId, setSelectedModelId] = useState("");
  const [selectedScenarioIds, setSelectedScenarioIds] = useState<string[]>([]);
  const [registeredAgent, setRegisteredAgent] = useState<AgentSpec | null>(null);
  const [githubSource, setGithubSource] = useState<GitHubImportSource>({
    owner: "PeytonLi",
    repo: "DevBox",
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
  const [approvalMessage, setApprovalMessage] = useState<string | null>(null);
  const [runPr, setRunPr] = useState<RequestPrResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    let mounted = true;

    async function loadOptions() {
      setPhase("loading");
      setError(null);
      try {
        const sessionData = await api.getSession();
        if (!mounted) {
          return;
        }
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
        if (!mounted) {
          return;
        }
        setModels(modelData);
        setScenarios(scenarioData);
        setTargetAgents(targetData);
        setSelectedModelId(modelData.find((model) => model.enabled)?.modelId ?? modelData[0]?.modelId ?? "");
        setSelectedTargetId(targetData[0]?.id ?? "");
        setSelectedScenarioIds(targetData[0]?.recommendedScenarioIds ?? scenarioData.map((scenario) => scenario.id));
        setPhase("idle");
      } catch (loadError) {
        if (!mounted) {
          return;
        }
        setError(loadError instanceof Error ? loadError.message : "Could not load DevBox options.");
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
  const routeStatus = useMemo(() => {
    const route = diff?.toolRoute ?? smoke?.toolRoute;
    if (!route) {
      return "not checked";
    }
    return route.violations.length === 0 ? "verified" : "blocked";
  }, [diff, smoke]);
  const requiresCloudApproval = selectedModel?.riskProfile === "cloud";
  const missingCloudApproval = requiresCloudApproval && !allowCloudAnalysis;

  async function generateDiff() {
    setPhase("generating");
    setError(null);
    setDiff(null);
    try {
      const result = await api.createDiff({
        prompt,
        targetPath,
        useManagedAgent,
        allowedTools
      });
      setDiff(result);
      setPhase("idle");
    } catch (generateError) {
      setError(generateError instanceof Error ? generateError.message : "Could not generate diff.");
      setPhase("error");
    }
  }

  async function runSmokeCheck() {
    setPhase("smoke");
    setError(null);
    try {
      const result = await api.toolRoutingSmoke({
        prompt,
        targetPath,
        useManagedAgent,
        allowedTools
      });
      setSmoke(result);
      setPhase("idle");
    } catch (smokeError) {
      setError(smokeError instanceof Error ? smokeError.message : "Could not verify tool routing.");
      setPhase("error");
    }
  }

  async function createPr() {
    if (!diff) {
      return;
    }
    setPhase("creating-pr");
    setError(null);
    try {
      const result = await api.requestPr(diff.id);
      setDiff(result);
      setPhase("idle");
    } catch (prError) {
      setError(prError instanceof Error ? prError.message : "GitHub PR creation unavailable.");
      setPhase("error");
    }
  }

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
    setLane("targets");
    setPhase("registering");
    setError(null);
    setEvents([]);
    setReport(null);
    setRun(null);
    setApprovalMessage(null);

    try {
      const agent = selectedTarget ? await api.registerTargetAgent(selectedTarget.id) : registeredAgent;
      if (!agent?.id) {
        throw new Error("Imported agent is not ready.");
      }
      setRegisteredAgent(agent);
      setPhase("running");
      const createdRun = await api.createRun({
        agentId: agent.id,
        modelId: selectedModel.modelId,
        scenarioIds: selectedScenarioIds,
        allowCloudAnalysis: selectedModel.riskProfile === "cloud" && allowCloudAnalysis
      });
      setRun(createdRun);
      if (selectedModel.riskProfile === "cloud") {
        setAllowCloudAnalysis(false);
      }
      await connectRunStream(createdRun.id);
    } catch (runError) {
      setError(runError instanceof Error ? runError.message : "Could not start target-agent assessment.");
      setPhase("error");
    }
  }

  async function importAgentProject() {
    setPhase("importing");
    setError(null);
    setImportWarnings([]);
    try {
      const manifestText = importManifest.trim();
      if (!manifestText) {
        throw new Error("Agent manifest is empty.");
      }
      JSON.parse(manifestText);
      const manifest = new File([manifestText], manifestFileName.endsWith(".json") ? manifestFileName : "agent.json", {
        type: "application/json"
      });
      const imported = await api.importAgentProject(manifest, promptFile);
      setLane("targets");
      setSelectedTargetId("");
      setRegisteredAgent(imported.agent);
      setSelectedScenarioIds(
        imported.recommendedScenarioIds.length > 0 ? imported.recommendedScenarioIds : scenarios.map((scenario) => scenario.id)
      );
      setRun(null);
      setEvents([]);
      setReport(null);
      setRunPr(null);
      setGithubImport(null);
      setApprovalMessage(null);
      setImportWarnings(imported.warnings);
      setPhase("idle");
    } catch (importError) {
      setError(importError instanceof Error ? importError.message : "Could not import agent project.");
      setPhase("error");
    }
  }

  async function loadManifestFile(file: File | null) {
    if (!file) {
      return;
    }
    setManifestFileName(file.name);
    setImportManifest(await file.text());
  }

  async function connectRunStream(runId: string) {
    const streamToken = await api.getRunEventsToken(runId);
    const socket = new WebSocket(webSocketUrl(`/v1/runs/${runId}/events?token=${encodeURIComponent(streamToken.token)}`));
    socketRef.current = socket;

    socket.onmessage = (event) => {
      const payload = JSON.parse(event.data) as RunEvent;
      setEvents((current) => {
        if (current.some((item) => item.sequence === payload.sequence)) {
          return current;
        }
        return [...current, payload].sort((a, b) => a.sequence - b.sequence);
      });
    };

    socket.onclose = () => {
      fetchCompletedRun(runId);
    };

    socket.onerror = () => {
      setError("Run event stream failed. The report may still be available after refresh.");
      setPhase("error");
    };
  }

  async function fetchCompletedRun(runId: string) {
    try {
      const latestRun = await api.getRun(runId);
      setRun(latestRun);
      if (latestRun.status === "completed") {
        const latestReport = await api.getReport(runId);
        setReport(latestReport);
      }
      setPhase("idle");
    } catch (reportError) {
      setError(reportError instanceof Error ? reportError.message : "Could not load target-agent report.");
      setPhase("error");
    }
  }

  async function approveTargetFix() {
    if (!run || !report) {
      return;
    }
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
      setError(approvalError instanceof Error ? approvalError.message : "Could not approve target-agent fixes.");
      setPhase("error");
    }
  }

  async function approveTargetPr() {
    if (!run || !report) {
      return;
    }
    setPhase("creating-pr");
    setError(null);
    try {
      const response = await api.approveRunPr(run.id, {
        acceptedDiffIds: [report.promptDiff.id],
        applyToAgent: false
      });
      setRunPr(response);
      setApprovalMessage("Prompt remediation approved and PR requested.");
      setPhase("idle");
    } catch (prError) {
      setError(prError instanceof Error ? prError.message : "Could not create target-agent PR.");
      setPhase("error");
    }
  }

  async function importGitHubAgent() {
    setPhase("importing");
    setError(null);
    setImportWarnings([]);
    try {
      const imported = await api.importGitHubAgent(githubSource);
      setLane("targets");
      setSelectedTargetId("");
      setRegisteredAgent(imported.agent);
      setGithubImport(imported);
      setSelectedScenarioIds(
        imported.recommendedScenarioIds.length > 0 ? imported.recommendedScenarioIds : scenarios.map((scenario) => scenario.id)
      );
      setRun(null);
      setEvents([]);
      setReport(null);
      setRunPr(null);
      setApprovalMessage(null);
      setImportWarnings(imported.warnings);
      setPhase("idle");
    } catch (importError) {
      setError(importError instanceof Error ? importError.message : "Could not import GitHub agent.");
      setPhase("error");
    }
  }

  function toggleTool(tool: string) {
    setAllowedTools((current) => {
      if (current.includes(tool)) {
        return current.filter((item) => item !== tool);
      }
      return [...current, tool];
    });
  }

  function selectTarget(target: TargetAgentTemplate) {
    setSelectedTargetId(target.id);
    setSelectedScenarioIds(target.recommendedScenarioIds);
    setRegisteredAgent(null);
    setRun(null);
    setEvents([]);
    setReport(null);
    setApprovalMessage(null);
    setRunPr(null);
    setGithubImport(null);
    setImportWarnings([]);
  }

  function selectModel(model: ModelConfig) {
    setSelectedModelId(model.modelId);
    setAllowCloudAnalysis(false);
  }

  function toggleScenario(scenarioId: string) {
    setSelectedScenarioIds((current) => {
      if (current.includes(scenarioId)) {
        return current.filter((item) => item !== scenarioId);
      }
      return [...current, scenarioId];
    });
  }

  if (session && !session.authenticated) {
    return (
      <main className="login-shell">
        <section className="login-panel">
          <div className="brand-mark">
            <ShieldCheck size={24} />
          </div>
          <span className="eyebrow">DevBox production pilot</span>
          <h1>Admin login required</h1>
          <p>Use the allowlisted GitHub account before importing repositories, running assessments, or approving PRs.</p>
          <a className="primary-button login-button" href={session.loginUrl}>
            <GitBranch size={18} />
            Continue with GitHub
          </a>
        </section>
      </main>
    );
  }

  return (
    <main className="shell">
      <aside className="sidebar" aria-label="Workspace navigation">
        <div className="brand">
          <div className="brand-mark">
            <ShieldCheck size={21} />
          </div>
          <div>
            <span className="brand-kicker">DevBox</span>
            <strong>{lane === "diff" ? "Diff Workbench" : "Agent Test Lab"}</strong>
          </div>
        </div>
        <nav className="nav-list">
          <LaneItem active={lane === "diff"} icon={<FileDiff size={17} />} label="Diff workbench" onClick={() => setLane("diff")} />
          <LaneItem active={lane === "targets"} icon={<Server size={17} />} label="Target agents" onClick={() => setLane("targets")} />
          <a className="nav-item" href="#routing">
            <Route size={17} />
            <span>Tool routing</span>
          </a>
          <a className="nav-item" href={lane === "diff" ? "#github" : "#target-report"}>
            <GitPullRequestArrow size={17} />
            <span>{lane === "diff" ? "GitHub PR" : "Fix approval"}</span>
          </a>
          {lane === "targets" ? (
            <a className="nav-item" href="#import-agent">
              <Upload size={17} />
              <span>Import agent</span>
            </a>
          ) : null}
        </nav>
        <div className="sidebar-card">
          <div className="sidebar-status">
            <LockKeyhole size={18} />
            <div>
              <strong>Authorized lab</strong>
              <span>Local mock targets with fake data</span>
            </div>
          </div>
          <div className="sidebar-metric">
            <span>{lane === "diff" ? "Provider mode" : "Run score"}</span>
            <strong>{lane === "diff" ? diff?.providerMode.replace("_", " ") ?? "Auto" : report ? `${report.score}/100` : "Pending"}</strong>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <span className="eyebrow">{lane === "diff" ? "Managed Agent diff lane" : "Production-like target lane"}</span>
            <h1>{lane === "diff" ? "Prompt Input to Diff Output" : "Target Agent Test Lab"}</h1>
            <p>
              {lane === "diff"
                ? "Generate a prompt hardening diff, verify remote tool routing, then open a GitHub PR."
                : "Run synthetic production agents through sandboxed attack scenarios, live traces, and fix approval."}
            </p>
          </div>
          <button
            className="primary-button"
            type="button"
            onClick={lane === "diff" ? generateDiff : runTargetAssessment}
            disabled={
              phase === "generating" ||
              phase === "importing" ||
              phase === "registering" ||
              phase === "running" ||
              phase === "loading" ||
              (lane === "targets" && missingCloudApproval)
            }
          >
            {phase === "generating" || phase === "registering" || phase === "running" ? (
              <RefreshCw className="spin" size={18} />
            ) : lane === "diff" ? (
              <Sparkles size={18} />
            ) : (
              <Play size={18} />
            )}
            {lane === "diff" ? (phase === "generating" ? "Generating" : "Generate diff") : phase === "running" ? "Running" : "Run assessment"}
          </button>
        </header>

        <div className="status-strip" aria-label="Workspace status">
          {lane === "diff" ? (
            <>
              <StatCard label="Diff" value={diff?.status ?? "Empty"} detail={diff?.targetPath ?? targetPath} />
              <StatCard label="Environment" value={diff?.environmentId ?? "Pending"} detail={useManagedAgent ? "remote when configured" : "simulator"} />
              <StatCard label="Interaction" value={diff?.interactionId ?? "None"} detail={diff?.providerMode ?? "auto"} />
              <StatCard label="Routing" value={routeStatus} detail={`${allowedTools.length} allowed tools`} />
            </>
          ) : (
            <>
              <StatCard
                label="Target"
                value={selectedTarget?.name ?? registeredAgent?.name ?? "None"}
                detail={
                  selectedTarget?.category ??
                  githubImport?.repository.fullName ??
                  (registeredAgent ? registeredAgent.promptPath ?? "imported project" : "template")
                }
              />
              <StatCard label="Model" value={selectedModel?.displayName ?? "None"} detail={selectedModel?.provider ?? "provider"} />
              <StatCard label="Run" value={run?.status ?? "Not started"} detail={run?.id ?? "local mock runtime"} />
              <StatCard label="Findings" value={report ? String(report.findings.length) : "Pending"} detail={`${selectedScenarioIds.length} scenarios`} />
            </>
          )}
        </div>

        {error ? (
          <div className="error-banner" role="alert">
            <AlertTriangle size={18} />
            {error}
          </div>
        ) : null}

        {lane === "diff" ? renderDiffLane() : renderTargetLane()}
      </section>
    </main>
  );

  function renderDiffLane() {
    return (
      <div className="diff-layout">
        <section className="panel prompt-panel" id="prompt">
          <PanelHeader icon={<Terminal size={18} />} title="Prompt input" value={useManagedAgent ? "managed" : "simulated"} />
          <label className="field">
            <span>Target prompt path</span>
            <input value={targetPath} onChange={(event) => setTargetPath(event.target.value)} />
          </label>
          <label className="field">
            <span>System prompt</span>
            <textarea value={prompt} onChange={(event) => setPrompt(event.target.value)} />
          </label>
          <div className="switch-row">
            <span>Use Managed Agent when configured</span>
            <button
              className={useManagedAgent ? "toggle is-on" : "toggle"}
              type="button"
              aria-pressed={useManagedAgent}
              onClick={() => setUseManagedAgent((current) => !current)}
            >
              <span />
            </button>
          </div>
        </section>

        <section className="panel output-panel">
          <PanelHeader icon={<FileDiff size={18} />} title="Diff output" value={diff?.status ?? "empty"} />
          {diff ? (
            <div className="diff-result">
              <div className="metadata-grid">
                <Metric label="Provider" value={diff.providerMode.replace("_", " ")} />
                <Metric label="Environment" value={diff.environmentId ?? "none"} />
                <Metric label="Interaction" value={diff.interactionId ?? "none"} />
                <Metric label="Route" value={routeStatus} />
              </div>
              <pre className="diff-output">{diff.unifiedDiff}</pre>
            </div>
          ) : (
            <EmptyState icon={<Code2 size={24} />} title="Generate a diff to inspect prompt changes" />
          )}
        </section>

        <section className="panel" id="routing">
          <PanelHeader icon={<Route size={18} />} title="Tool routing" value={routeStatus} />
          <div className="tool-options">
            {toolOptions.map((tool) => (
              <button
                key={tool}
                className={allowedTools.includes(tool) ? "tool-chip selected" : "tool-chip"}
                type="button"
                onClick={() => toggleTool(tool)}
              >
                {allowedTools.includes(tool) ? <Check size={15} /> : null}
                {tool}
              </button>
            ))}
          </div>
          <button className="secondary-button" type="button" onClick={runSmokeCheck} disabled={phase === "smoke"}>
            {phase === "smoke" ? <RefreshCw className="spin" size={17} /> : <Play size={17} />}
            Verify routing
          </button>
          <RouteSummary result={diff ?? smoke} />
        </section>

        <section className="panel" id="github">
          <PanelHeader icon={<GitPullRequestArrow size={18} />} title="GitHub PR" value={diff?.prUrl ? "created" : "approval"} />
          <div className="approval-box">
            <Bot size={20} />
            <div>
              <strong>Approved diff only</strong>
              <p>DevBox sends the selected diff to the Next.js Octokit route only after this explicit action.</p>
            </div>
          </div>
          <button className="secondary-button" type="button" onClick={createPr} disabled={!diff || phase === "creating-pr"}>
            {phase === "creating-pr" ? <RefreshCw className="spin" size={17} /> : <GitPullRequestArrow size={17} />}
            {phase === "creating-pr" ? "Creating PR" : "Create PR"}
          </button>
          {diff?.prUrl ? (
            <a className="pr-link" href={diff.prUrl} target="_blank" rel="noreferrer">
              {diff.prUrl}
            </a>
          ) : (
            <p className="muted-note">Requires GitHub App credentials and the internal webhook secret.</p>
          )}
        </section>
      </div>
    );
  }

  function renderTargetLane() {
    return (
      <div className="grid-layout">
        <section className="panel">
          <PanelHeader icon={<Server size={18} />} title="Target agent" value={selectedTarget?.category ?? "none"} />
          <div className="model-list">
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
        </section>

        <section className="panel import-panel" id="import-agent">
          <PanelHeader icon={<GitBranch size={18} />} title="GitHub import" value={githubImport ? "selected" : "live"} />
          <div className="github-import-grid">
            <label className="field">
              <span>Owner</span>
              <input value={githubSource.owner} onChange={(event) => setGithubSource((current) => ({ ...current, owner: event.target.value }))} />
            </label>
            <label className="field">
              <span>Repository</span>
              <input value={githubSource.repo} onChange={(event) => setGithubSource((current) => ({ ...current, repo: event.target.value }))} />
            </label>
            <label className="field">
              <span>Ref</span>
              <input value={githubSource.ref ?? ""} onChange={(event) => setGithubSource((current) => ({ ...current, ref: event.target.value }))} />
            </label>
            <label className="field">
              <span>Prompt path</span>
              <input
                value={githubSource.promptPath}
                onChange={(event) => setGithubSource((current) => ({ ...current, promptPath: event.target.value }))}
              />
            </label>
            <label className="field">
              <span>Manifest path</span>
              <input
                value={githubSource.manifestPath ?? ""}
                onChange={(event) => setGithubSource((current) => ({ ...current, manifestPath: event.target.value || null }))}
              />
            </label>
            <label className="field">
              <span>Installation ID</span>
              <input
                value={githubSource.installationId ?? ""}
                onChange={(event) =>
                  setGithubSource((current) => ({
                    ...current,
                    installationId: event.target.value ? Number(event.target.value) : null
                  }))
                }
              />
            </label>
          </div>
          <button className="secondary-button" type="button" onClick={importGitHubAgent} disabled={phase === "importing"}>
            {phase === "importing" ? <RefreshCw className="spin" size={17} /> : <GitBranch size={17} />}
            {phase === "importing" ? "Importing" : "Import from GitHub"}
          </button>
          {githubImport ? (
            <div className="import-status">
              <strong>{githubImport.repository.fullName}</strong>
              <span>
                {githubImport.source.promptPath} / {githubImport.commitSha ?? "latest ref"}
              </span>
            </div>
          ) : null}
        </section>

        <section className="panel import-panel">
          <PanelHeader icon={<Upload size={18} />} title="Local manifest import" value={registeredAgent && !selectedTarget ? "selected" : "ready"} />
          <label className="field">
            <span>Manifest JSON</span>
            <textarea className="manifest-input" value={importManifest} onChange={(event) => setImportManifest(event.target.value)} />
          </label>
          <div className="file-grid">
            <label className="file-field">
              <span>Manifest file</span>
              <input type="file" accept="application/json,.json" onChange={(event) => void loadManifestFile(event.target.files?.[0] ?? null)} />
            </label>
            <label className="file-field">
              <span>Prompt file</span>
              <input
                type="file"
                accept=".md,.txt,text/markdown,text/plain"
                onChange={(event) => setPromptFile(event.target.files?.[0] ?? null)}
              />
            </label>
          </div>
          <button className="secondary-button" type="button" onClick={importAgentProject} disabled={phase === "importing"}>
            {phase === "importing" ? <RefreshCw className="spin" size={17} /> : <Upload size={17} />}
            {phase === "importing" ? "Importing" : "Import agent"}
          </button>
          {registeredAgent && !selectedTarget ? (
            <div className="import-status">
              <strong>{registeredAgent.name}</strong>
              <span>
                {registeredAgent.promptPath ?? "inline prompt"} / {selectedScenarioIds.length} scenarios
              </span>
            </div>
          ) : null}
          {promptFile ? <p className="muted-note">Prompt file: {promptFile.name}</p> : null}
          {importWarnings.length > 0 ? (
            <ul className="warning-list">
              {importWarnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : null}
        </section>

        <section className="panel">
          <PanelHeader icon={<Database size={18} />} title="Model" value={selectedModel?.provider ?? "provider"} />
          <div className="model-list">
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
                  <small>{model.riskProfile} runtime</small>
                </div>
                <span className="model-state">{model.enabled ? model.costTier : "off"}</span>
                <p>{model.enabled ? model.privacyNote : model.unavailableReason ?? "Provider unavailable."}</p>
              </button>
            ))}
          </div>
          {requiresCloudApproval ? (
            <div className="switch-row cloud-approval-row">
              <div>
                <span>Approve cloud analysis</span>
                <small>{selectedModel?.displayName ?? "Selected cloud model"} can process selected run data.</small>
              </div>
              <button
                className={allowCloudAnalysis ? "toggle is-on" : "toggle"}
                type="button"
                aria-pressed={allowCloudAnalysis}
                onClick={() => setAllowCloudAnalysis((current) => !current)}
              >
                <span />
              </button>
            </div>
          ) : null}
        </section>

        <section className="panel">
          <PanelHeader icon={<ListChecks size={18} />} title="Scenarios" value={`${selectedScenarioIds.length} selected`} />
          <div className="scenario-list">
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

        <section className="panel trace-panel">
          <PanelHeader icon={<Terminal size={18} />} title="Live trace" value={run?.status ?? "idle"} />
          {events.length > 0 ? (
            <div className="trace-list">
              {events.map((event) => (
                <div className="trace-event" key={event.sequence}>
                  <span className={`actor ${event.actor}`}>{event.actor.replace("_", " ")}</span>
                  <div>
                    <strong>{event.message}</strong>
                    <span>
                      #{event.sequence}
                      {event.toolCall ? ` / ${event.toolCall}` : ""}
                      {event.policyDecision ? ` / ${event.policyDecision}` : ""}
                      {event.riskSignal ? ` / ${event.riskSignal}` : ""}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState icon={<Terminal size={24} />} title="Run an assessment to stream target-agent events" />
          )}
        </section>

        <section className="panel report-panel" id="target-report">
          <PanelHeader icon={<ShieldCheck size={18} />} title="Findings report" value={report ? `${report.score}/100` : "pending"} />
          {report ? (
            <>
              <div className="score-strip">
                <strong>{report.score}</strong>
                <div>
                  <span>Security score</span>
                  <p>{report.traceSummary}</p>
                  <div className="score-progress">
                    <div className="score-progress-indicator" style={{ transform: `translateX(-${100 - report.score}%)` }} />
                  </div>
                </div>
              </div>
              <div className="finding-list">
                {report.findings.map((finding) => (
                  <div className="finding-row" key={finding.id}>
                    <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                    <div>
                      <strong>{finding.violatedPolicy}</strong>
                      <p>{finding.evidence}</p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="diff-box">
                <strong>Regression tests</strong>
                <p>{report.regressionTests.join(" ")}</p>
              </div>
              <button className="secondary-button" type="button" onClick={approveTargetFix} disabled={phase === "approving"}>
                {phase === "approving" ? <RefreshCw className="spin" size={17} /> : <Wrench size={17} />}
                {phase === "approving" ? "Approving" : "Approve prompt and policy fix"}
              </button>
              <button className="secondary-button" type="button" onClick={approveTargetPr} disabled={phase === "creating-pr"}>
                {phase === "creating-pr" ? <RefreshCw className="spin" size={17} /> : <GitPullRequestArrow size={17} />}
                {phase === "creating-pr" ? "Creating PR" : "Approve prompt PR"}
              </button>
              {runPr?.prUrl ? (
                <a className="pr-link" href={runPr.prUrl} target="_blank" rel="noreferrer">
                  {runPr.prUrl}
                </a>
              ) : null}
              {approvalMessage ? <p className="success-line">{approvalMessage}</p> : null}
            </>
          ) : (
            <EmptyState icon={<ShieldCheck size={24} />} title="Completed runs produce a scorecard and fixes" />
          )}
        </section>

        <section className="panel sandbox-panel">
          <PanelHeader icon={<LockKeyhole size={18} />} title="Sandbox policy" value={registeredAgent?.runtime?.agentKey ?? selectedTarget?.runtime.agentKey ?? "template"} />
          <PolicySummary agent={registeredAgent ?? selectedTarget?.agentSpec ?? null} />
        </section>
      </div>
    );
  }
}

function LaneItem({ active, icon, label, onClick }: { active?: boolean; icon: ReactNode; label: string; onClick: () => void }) {
  return (
    <button className={active ? "nav-item active" : "nav-item"} type="button" onClick={onClick}>
      {icon}
      <span>{label}</span>
    </button>
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

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function RouteSummary({ result }: { result: DiffResult | null }) {
  if (!result) {
    return <p className="muted-note">No route data yet.</p>;
  }

  return (
    <dl className="route-summary">
      <div>
        <dt>Requested</dt>
        <dd>{result.toolRoute.requestedTools.join(", ") || "none"}</dd>
      </div>
      <div>
        <dt>Observed</dt>
        <dd>{result.toolRoute.observedTools.join(", ") || "none"}</dd>
      </div>
      <div>
        <dt>Violations</dt>
        <dd>{result.toolRoute.violations.join(", ") || "none"}</dd>
      </div>
      <div>
        <dt>Raw steps</dt>
        <dd>{result.toolRoute.rawStepCount}</dd>
      </div>
    </dl>
  );
}

function PolicySummary({ agent }: { agent: AgentSpec | null }) {
  if (!agent) {
    return <EmptyState icon={<LockKeyhole size={24} />} title="Select a target agent to inspect sandbox policy" />;
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
    <div className="empty-state">
      {icon}
      <span>{title}</span>
    </div>
  );
}
