import { createHmac, createPrivateKey, timingSafeEqual } from "node:crypto";
import { Buffer } from "node:buffer";
import { createAppAuth } from "@octokit/auth-app";
import { Octokit } from "@octokit/rest";

export const runtime = "nodejs";

interface DiffWebhookPayload {
  diffId: string;
  promptAfter: string;
  unifiedDiff: string;
  targetPath?: string;
  title?: string;
}

const DEFAULT_REPOSITORY = "PeytonLi/DevBox";
const DEFAULT_TARGET_PATH = ".agents/AGENTS.md";

class WebhookConfigurationError extends Error {
  status = 503;
}

export async function POST(request: Request) {
  const rawBody = await request.text();
  const secret = process.env.DEVBOX_PR_WEBHOOK_SECRET;

  if (!secret) {
    return Response.json({ error: "GitHub PR creation unavailable" }, { status: 503 });
  }

  const signature = request.headers.get("x-devbox-signature");
  if (!signature || !verifySignature(rawBody, signature, secret)) {
    return Response.json({ error: "Invalid webhook signature" }, { status: 401 });
  }

  const missing = requiredGithubEnv().filter((key) => !process.env[key]);
  if (missing.length > 0) {
    return Response.json(
      { error: `GitHub PR creation unavailable: missing ${missing.join(", ")}` },
      { status: 503 }
    );
  }

  let payload: DiffWebhookPayload;
  try {
    payload = JSON.parse(rawBody) as DiffWebhookPayload;
  } catch {
    return Response.json({ error: "Invalid JSON payload" }, { status: 400 });
  }

  if (!payload.diffId || !payload.promptAfter) {
    return Response.json({ error: "Payload requires diffId and promptAfter" }, { status: 400 });
  }

  try {
    return Response.json(await createPullRequest(payload));
  } catch (error) {
    return githubErrorResponse(error);
  }
}

async function createPullRequest(payload: DiffWebhookPayload) {
  const { owner, repo } = repositoryTarget();
  const baseBranch = process.env.GITHUB_BASE_BRANCH || "main";
  const targetPath = payload.targetPath || process.env.DEVBOX_TARGET_PROMPT_PATH || DEFAULT_TARGET_PATH;
  const branch = `codex/devbox-diff-${payload.diffId}`;
  const octokit = new Octokit({
    authStrategy: createAppAuth,
    auth: {
      appId: process.env.GITHUB_APP_ID,
      privateKey: normalizePrivateKey(process.env.GITHUB_APP_PRIVATE_KEY || ""),
      installationId: process.env.GITHUB_APP_INSTALLATION_ID
    }
  });

  const { data: base } = await octokit.rest.repos.getBranch({ owner, repo, branch: baseBranch });
  const existingPr = await existingOpenPullRequest(octokit, owner, repo, branch);
  if (existingPr) {
    return {
      prUrl: existingPr.html_url,
      branch,
      commitSha: existingPr.head.sha
    };
  }
  await createBranchIfMissing(octokit, owner, repo, branch, base.commit.sha);

  const sha = await existingFileSha(octokit, owner, repo, targetPath, branch);
  const { data: file } = await octokit.rest.repos.createOrUpdateFileContents({
    owner,
    repo,
    path: targetPath,
    branch,
    message: payload.title || "chore: apply AgentSecure prompt hardening diff",
    content: Buffer.from(payload.promptAfter, "utf8").toString("base64"),
    sha
  });

  const { data: pr } = await octokit.rest.pulls.create({
    owner,
    repo,
    title: payload.title || "chore: apply AgentSecure prompt hardening diff",
    head: branch,
    base: baseBranch,
    body: prBody(payload, targetPath)
  });

  return {
    prUrl: pr.html_url,
    branch,
    commitSha: file.commit.sha
  };
}

function verifySignature(rawBody: string, signature: string, secret: string) {
  const expected = `sha256=${createHmac("sha256", secret).update(rawBody).digest("hex")}`;
  const expectedBytes = Buffer.from(expected);
  const actualBytes = Buffer.from(signature);
  return expectedBytes.length === actualBytes.length && timingSafeEqual(expectedBytes, actualBytes);
}

function requiredGithubEnv() {
  return ["GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY", "GITHUB_APP_INSTALLATION_ID"];
}

function repositoryTarget() {
  const repository = process.env.GITHUB_REPOSITORY || DEFAULT_REPOSITORY;
  const [owner, repo] = repository.split("/");
  return {
    owner: process.env.GITHUB_OWNER || owner,
    repo: process.env.GITHUB_REPO || repo
  };
}

function normalizePrivateKey(value: string) {
  const normalized = value.trim().replace(/^['"]|['"]$/g, "").replace(/\\n/g, "\n").replace(/\r\n/g, "\n");
  const candidates = [normalized];
  const compactBody = normalized.replace(/\s+/g, "");

  if (!normalized.includes("-----BEGIN") && /^[A-Za-z0-9+/=]+$/.test(compactBody) && compactBody.length > 512) {
    candidates.unshift(toPem(compactBody, "RSA PRIVATE KEY"), toPem(compactBody, "PRIVATE KEY"));
  }

  for (const candidate of [...new Set(candidates)]) {
    try {
      createPrivateKey(candidate);
      return candidate;
    } catch {
      // Try the next supported private key representation.
    }
  }

  throw new WebhookConfigurationError(
    "GitHub PR creation unavailable: GITHUB_APP_PRIVATE_KEY is not a valid private key. Use the full downloaded GitHub App private key, a PEM string with \\n escapes, or a base64 key body."
  );
}

function toPem(base64Body: string, label: "PRIVATE KEY" | "RSA PRIVATE KEY") {
  const lines = base64Body.match(/.{1,64}/g) ?? [base64Body];
  return [`-----BEGIN ${label}-----`, ...lines, `-----END ${label}-----`].join("\n");
}

async function createBranchIfMissing(octokit: Octokit, owner: string, repo: string, branch: string, sha: string) {
  try {
    await octokit.rest.git.createRef({
      owner,
      repo,
      ref: `refs/heads/${branch}`,
      sha
    });
  } catch (error) {
    if (isGithubStatus(error, 422)) {
      return;
    }
    throw error;
  }
}

async function existingOpenPullRequest(octokit: Octokit, owner: string, repo: string, branch: string) {
  const { data } = await octokit.rest.pulls.list({
    owner,
    repo,
    head: `${owner}:${branch}`,
    state: "open",
    per_page: 1
  });
  return data[0];
}

async function existingFileSha(
  octokit: Octokit,
  owner: string,
  repo: string,
  path: string,
  branch: string
) {
  try {
    const { data } = await octokit.rest.repos.getContent({
      owner,
      repo,
      path,
      ref: branch
    });
    if (!Array.isArray(data) && "sha" in data) {
      return data.sha;
    }
  } catch (error) {
    if (!isGithubStatus(error, 404)) {
      throw error;
    }
  }
  return undefined;
}

function isGithubStatus(error: unknown, status: number) {
  return typeof error === "object" && error !== null && "status" in error && error.status === status;
}

function githubErrorResponse(error: unknown) {
  if (error instanceof WebhookConfigurationError) {
    return Response.json({ error: error.message }, { status: error.status });
  }

  const status = githubStatus(error) ?? 502;
  const detail = githubErrorMessage(error);
  const requestId = githubRequestId(error);
  return Response.json(
    {
      error: `GitHub PR creation failed: ${detail}`,
      ...(requestId ? { requestId } : {})
    },
    { status }
  );
}

function githubStatus(error: unknown) {
  if (typeof error !== "object" || error === null || !("status" in error)) {
    return undefined;
  }
  const status = Number(error.status);
  return Number.isInteger(status) && status >= 400 && status <= 599 ? status : undefined;
}

function githubErrorMessage(error: unknown) {
  const responseData = typeof error === "object" && error !== null && "response" in error
    ? (error.response as { data?: unknown } | undefined)?.data
    : undefined;

  if (typeof responseData === "object" && responseData !== null && "message" in responseData) {
    const message = (responseData as { message?: unknown }).message;
    if (typeof message === "string" && message.trim()) {
      return message;
    }
  }

  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  return "unknown GitHub API error";
}

function githubRequestId(error: unknown) {
  const headers = typeof error === "object" && error !== null && "response" in error
    ? (error.response as { headers?: Record<string, string | undefined> } | undefined)?.headers
    : undefined;
  return headers?.["x-github-request-id"];
}

function prBody(payload: DiffWebhookPayload, targetPath: string) {
  return [
    "Generated by AgentSecure after explicit diff approval.",
    "",
    `Target path: \`${targetPath}\``,
    `Diff id: \`${payload.diffId}\``,
    "",
    "Approved prompt content is committed in the branch file update and intentionally omitted from this PR body."
  ].join("\n");
}
