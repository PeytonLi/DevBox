import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { allowedAdminEmails, setAdminSession, verifyOAuthState } from "@/lib/server-auth";

export const runtime = "nodejs";

interface GitHubUser {
  login?: string;
  email?: string | null;
}

interface GitHubEmail {
  email?: string;
  primary?: boolean;
  verified?: boolean;
}

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const state = request.nextUrl.searchParams.get("state");
  if (!code || !verifyOAuthState(request, state)) {
    return NextResponse.json({ error: "Invalid GitHub OAuth state." }, { status: 401 });
  }

  const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
  const clientSecret = process.env.GITHUB_OAUTH_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    return NextResponse.json({ error: "GitHub OAuth is not configured." }, { status: 503 });
  }

  let identity: Awaited<ReturnType<typeof fetchGitHubIdentity>>;
  try {
    const token = await exchangeCode(code, clientId, clientSecret, new URL("/api/auth/github/callback", request.url).toString());
    identity = await fetchGitHubIdentity(token);
  } catch (error) {
    const message = error instanceof Error ? error.message : "GitHub OAuth failed.";
    return NextResponse.json({ error: message }, { status: 502 });
  }
  const { email, login } = identity;
  if (!email) {
    return NextResponse.json({ error: "GitHub account does not expose a verified email." }, { status: 403 });
  }

  const allowed = allowedAdminEmails();
  if (allowed.length > 0 && !allowed.includes(email.toLowerCase())) {
    return NextResponse.json({ error: "GitHub account is not allowlisted for DevBox." }, { status: 403 });
  }

  const response = NextResponse.redirect(new URL("/", request.url));
  setAdminSession(response, { email, login });
  response.cookies.set("devbox_oauth_state", "", { path: "/api/auth/github", maxAge: 0 });
  return response;
}

async function exchangeCode(code: string, clientId: string, clientSecret: string, redirectUri: string) {
  const response = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri
    })
  });
  const payload = (await response.json()) as { access_token?: string; error_description?: string };
  if (!response.ok || !payload.access_token) {
    throw new Error(payload.error_description ?? "GitHub OAuth token exchange failed.");
  }
  return payload.access_token;
}

async function fetchGitHubIdentity(token: string) {
  const headers = {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${token}`,
    "X-GitHub-Api-Version": "2022-11-28"
  };
  const [userResponse, emailResponse] = await Promise.all([
    fetch("https://api.github.com/user", { headers }),
    fetch("https://api.github.com/user/emails", { headers })
  ]);
  if (!userResponse.ok) {
    throw new Error("GitHub user lookup failed.");
  }
  const user = (await userResponse.json()) as GitHubUser;
  const emails = emailResponse.ok ? ((await emailResponse.json()) as GitHubEmail[]) : [];
  const primary = emails.find((item) => item.primary && item.verified && item.email)?.email;
  const verified = primary ?? emails.find((item) => item.verified && item.email)?.email ?? user.email ?? null;
  return {
    email: verified,
    login: user.login
  };
}
