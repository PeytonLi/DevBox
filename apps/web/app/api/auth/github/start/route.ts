import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { newOAuthState, setOAuthState } from "@/lib/server-auth";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const clientId = process.env.GITHUB_OAUTH_CLIENT_ID;
  if (!clientId) {
    return NextResponse.json({ error: "GitHub OAuth is not configured." }, { status: 503 });
  }

  const state = newOAuthState();
  const redirect = NextResponse.redirect(githubAuthorizeUrl(request, clientId, state));
  setOAuthState(redirect, state);
  return redirect;
}

function githubAuthorizeUrl(request: NextRequest, clientId: string, state: string) {
  const callback = new URL("/api/auth/github/callback", request.url);
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", callback.toString());
  url.searchParams.set("scope", "read:user user:email");
  url.searchParams.set("state", state);
  return url;
}
