"use client";

import { type ReactNode, useMemo, useState } from "react";
import {
  AlertTriangle,
  Bot,
  Check,
  Code2,
  FileDiff,
  GitPullRequestArrow,
  LockKeyhole,
  Play,
  RefreshCw,
  Route,
  ShieldCheck,
  Sparkles,
  Terminal
} from "lucide-react";
import type { DiffResult } from "@devbox/shared";
import { api } from "@/lib/api";

type Phase = "idle" | "generating" | "creating-pr" | "smoke" | "error";

const defaultPrompt =
  "You are a browser research agent. Follow protected instructions, use only approved tools, and protect secrets in every response.";
const toolOptions = ["code_execution", "url_context", "google_search"];

export function SecurityDashboard() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [prompt, setPrompt] = useState(defaultPrompt);
  const [targetPath, setTargetPath] = useState(".agents/AGENTS.md");
  const [useManagedAgent, setUseManagedAgent] = useState(true);
  const [allowedTools, setAllowedTools] = useState(["code_execution", "url_context"]);
  const [diff, setDiff] = useState<DiffResult | null>(null);
  const [smoke, setSmoke] = useState<DiffResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const routeStatus = useMemo(() => {
    const route = diff?.toolRoute ?? smoke?.toolRoute;
    if (!route) {
      return "not checked";
    }
    return route.violations.length === 0 ? "verified" : "blocked";
  }, [diff, smoke]);

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

  function toggleTool(tool: string) {
    setAllowedTools((current) => {
      if (current.includes(tool)) {
        return current.filter((item) => item !== tool);
      }
      return [...current, tool];
    });
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
            <strong>Diff Workbench</strong>
          </div>
        </div>
        <nav className="nav-list">
          <NavItem href="#prompt" label="Diff workbench" icon={<FileDiff size={17} />} active />
          <NavItem href="#routing" label="Tool routing" icon={<Route size={17} />} />
          <NavItem href="#github" label="GitHub PR" icon={<GitPullRequestArrow size={17} />} />
        </nav>
        <div className="sidebar-card">
          <div className="sidebar-status">
            <LockKeyhole size={18} />
            <div>
              <strong>Human approved</strong>
              <span>PR only after explicit click</span>
            </div>
          </div>
          <div className="sidebar-metric">
            <span>Provider mode</span>
            <strong>{diff?.providerMode.replace("_", " ") ?? "Auto"}</strong>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <span className="eyebrow">Managed Agent diff lane</span>
            <h1>Prompt Input to Diff Output</h1>
            <p>Generate a prompt hardening diff, verify remote tool routing, then open a GitHub PR.</p>
          </div>
          <button className="primary-button" type="button" onClick={generateDiff} disabled={phase === "generating"}>
            {phase === "generating" ? <RefreshCw className="spin" size={18} /> : <Sparkles size={18} />}
            {phase === "generating" ? "Generating" : "Generate diff"}
          </button>
        </header>

        <div className="status-strip" aria-label="Diff status">
          <StatCard label="Diff" value={diff?.status ?? "Empty"} detail={diff?.targetPath ?? targetPath} />
          <StatCard label="Environment" value={diff?.environmentId ?? "Pending"} detail={useManagedAgent ? "remote when configured" : "simulator"} />
          <StatCard label="Interaction" value={diff?.interactionId ?? "None"} detail={diff?.providerMode ?? "auto"} />
          <StatCard label="Routing" value={routeStatus} detail={`${allowedTools.length} allowed tools`} />
        </div>

        {error ? (
          <div className="error-banner" role="alert">
            <AlertTriangle size={18} />
            {error}
          </div>
        ) : null}

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
      </section>
    </main>
  );
}

function NavItem({ active, href, icon, label }: { active?: boolean; href: string; icon: ReactNode; label: string }) {
  return (
    <a className={active ? "nav-item active" : "nav-item"} href={href}>
      {icon}
      <span>{label}</span>
    </a>
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

function EmptyState({ icon, title }: { icon: ReactNode; title: string }) {
  return (
    <div className="empty-state">
      {icon}
      <span>{title}</span>
    </div>
  );
}
