import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";
import { readAdminSession } from "@/lib/server-auth";

export const runtime = "nodejs";

type RouteContext = {
  params: Promise<{ path: string[] }>;
};

export async function GET(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}

export async function POST(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}

export async function PUT(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}

export async function DELETE(request: NextRequest, context: RouteContext) {
  return forward(request, context);
}

async function forward(request: NextRequest, context: RouteContext) {
  const session = readAdminSession(request);
  if (!session) {
    return NextResponse.json({ detail: "DevBox admin login required.", loginUrl: "/api/auth/github/start" }, { status: 401 });
  }

  const params = await context.params;
  const backendUrl = backendBaseUrl();
  const target = new URL(`/${params.path.join("/")}${request.nextUrl.search}`, backendUrl);
  const headers = forwardHeaders(request);
  const body = request.method === "GET" || request.method === "HEAD" ? undefined : await request.arrayBuffer();
  const response = await fetch(target, {
    method: request.method,
    headers,
    body,
    cache: "no-store"
  });
  return new NextResponse(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders(response)
  });
}

function backendBaseUrl() {
  return (
    process.env.DEVBOX_BACKEND_URL ||
    process.env.NEXT_PUBLIC_API_DIRECT_BASE_URL ||
    "http://localhost:8000"
  ).replace(/\/$/, "");
}

function forwardHeaders(request: NextRequest) {
  const headers = new Headers();
  const contentType = request.headers.get("content-type");
  if (contentType) {
    headers.set("content-type", contentType);
  }
  const serviceToken = process.env.DEVBOX_API_SERVICE_TOKEN;
  if (serviceToken) {
    headers.set("authorization", `Bearer ${serviceToken}`);
  }
  return headers;
}

function responseHeaders(response: Response) {
  const headers = new Headers();
  const contentType = response.headers.get("content-type");
  if (contentType) {
    headers.set("content-type", contentType);
  }
  return headers;
}
