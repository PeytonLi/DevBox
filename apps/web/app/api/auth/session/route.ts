import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { authDisabled, clearAdminSession, readAdminSession } from "@/lib/server-auth";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  const session = readAdminSession(request);
  return NextResponse.json({
    authenticated: Boolean(session),
    authDisabled: authDisabled(),
    email: session?.email ?? null,
    login: session?.login ?? null,
    loginUrl: "/api/auth/github/start"
  });
}

export async function DELETE() {
  const response = NextResponse.json({ authenticated: false });
  clearAdminSession(response);
  return response;
}
