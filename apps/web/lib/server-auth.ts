import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

const ADMIN_COOKIE = "devbox_admin";
const OAUTH_STATE_COOKIE = "devbox_oauth_state";

export interface AdminSession {
  email: string;
  login?: string;
  expiresAt: number;
}

export function authDisabled() {
  return process.env.DEVBOX_AUTH_DISABLED === "true" || (process.env.NODE_ENV !== "production" && !process.env.GITHUB_OAUTH_CLIENT_ID);
}

export function allowedAdminEmails() {
  return (process.env.DEVBOX_ALLOWED_ADMIN_EMAILS ?? "")
    .split(",")
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
}

export function readAdminSession(request: NextRequest): AdminSession | null {
  if (authDisabled()) {
    return {
      email: "local-admin@devbox.local",
      login: "local-admin",
      expiresAt: Date.now() + 60 * 60 * 1000
    };
  }

  const value = request.cookies.get(ADMIN_COOKIE)?.value;
  if (!value) {
    return null;
  }
  const decoded = verifySignedValue(value);
  if (!decoded) {
    return null;
  }
  try {
    const session = JSON.parse(decoded) as AdminSession;
    if (!session.email || session.expiresAt < Date.now()) {
      return null;
    }
    const allowed = allowedAdminEmails();
    if (allowed.length > 0 && !allowed.includes(session.email.toLowerCase())) {
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

export function setAdminSession(response: NextResponse, session: Omit<AdminSession, "expiresAt">) {
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  response.cookies.set(ADMIN_COOKIE, signValue(JSON.stringify({ ...session, expiresAt })), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    expires: new Date(expiresAt)
  });
}

export function clearAdminSession(response: NextResponse) {
  response.cookies.set(ADMIN_COOKIE, "", {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 0
  });
}

export function createOAuthState(response: NextResponse) {
  const state = randomBytes(24).toString("base64url");
  setOAuthState(response, state);
  return state;
}

export function newOAuthState() {
  return randomBytes(24).toString("base64url");
}

export function setOAuthState(response: NextResponse, state: string) {
  response.cookies.set(OAUTH_STATE_COOKIE, signValue(state), {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/api/auth/github",
    maxAge: 10 * 60
  });
}

export function verifyOAuthState(request: NextRequest, state: string | null) {
  const signed = request.cookies.get(OAUTH_STATE_COOKIE)?.value;
  return Boolean(state && signed && verifySignedValue(signed) === state);
}

export function authSecret() {
  return (
    process.env.DEVBOX_AUTH_SECRET ||
    process.env.DEVBOX_API_SERVICE_TOKEN ||
    process.env.DEVBOX_PR_WEBHOOK_SECRET ||
    "devbox-local-auth-secret"
  );
}

function signValue(value: string) {
  const payload = Buffer.from(value, "utf8").toString("base64url");
  const signature = createHmac("sha256", authSecret()).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

function verifySignedValue(value: string) {
  const [payload, signature] = value.split(".");
  if (!payload || !signature) {
    return null;
  }
  const expected = createHmac("sha256", authSecret()).update(payload).digest("base64url");
  const actualBytes = Buffer.from(signature);
  const expectedBytes = Buffer.from(expected);
  if (actualBytes.length !== expectedBytes.length || !timingSafeEqual(actualBytes, expectedBytes)) {
    return null;
  }
  return Buffer.from(payload, "base64url").toString("utf8");
}
