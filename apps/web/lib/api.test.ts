import { afterEach, describe, expect, it, vi } from "vitest";

async function loadWebSocketUrl(baseUrl: string) {
  vi.resetModules();
  vi.stubEnv("NEXT_PUBLIC_API_WS_BASE_URL", baseUrl);
  const { webSocketUrl } = await import("./api");
  return webSocketUrl;
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe("webSocketUrl", () => {
  it("keeps run stream tokens in the query string", async () => {
    const webSocketUrl = await loadWebSocketUrl("http://localhost:8000");

    const url = webSocketUrl("/v1/runs/run_123/events", { token: "abc.def-ghi_jkl" });
    const parsed = new URL(url);

    expect(url).toBe("ws://localhost:8000/v1/runs/run_123/events?token=abc.def-ghi_jkl");
    expect(url).not.toContain("%3F");
    expect(parsed.pathname).toBe("/v1/runs/run_123/events");
    expect(parsed.searchParams.get("token")).toBe("abc.def-ghi_jkl");
  });

  it("does not encode legacy path query strings into the pathname", async () => {
    const webSocketUrl = await loadWebSocketUrl("http://localhost:8000");

    const url = webSocketUrl("/v1/runs/run_123/events?token=abc.def-ghi_jkl");
    const parsed = new URL(url);

    expect(url).toBe("ws://localhost:8000/v1/runs/run_123/events?token=abc.def-ghi_jkl");
    expect(url).not.toContain("%3F");
    expect(parsed.pathname).toBe("/v1/runs/run_123/events");
    expect(parsed.searchParams.get("token")).toBe("abc.def-ghi_jkl");
  });

  it("maps HTTP protocols to WebSocket protocols", async () => {
    const httpUrl = await loadWebSocketUrl("http://api.example.test");
    const httpsUrl = await loadWebSocketUrl("https://api.example.test");

    expect(httpUrl("/v1/runs/run_123/events")).toBe("ws://api.example.test/v1/runs/run_123/events");
    expect(httpsUrl("/v1/runs/run_123/events")).toBe("wss://api.example.test/v1/runs/run_123/events");
  });

  it("keeps explicit WebSocket protocols", async () => {
    const wsUrl = await loadWebSocketUrl("ws://api.example.test");
    const wssUrl = await loadWebSocketUrl("wss://api.example.test");

    expect(wsUrl("/v1/runs/run_123/events")).toBe("ws://api.example.test/v1/runs/run_123/events");
    expect(wssUrl("/v1/runs/run_123/events")).toBe("wss://api.example.test/v1/runs/run_123/events");
  });

  it("preserves base path prefixes", async () => {
    const webSocketUrl = await loadWebSocketUrl("https://api.example.test/api/devbox/");

    expect(webSocketUrl("/v1/runs/run_123/events", { token: "abc" })).toBe(
      "wss://api.example.test/api/devbox/v1/runs/run_123/events?token=abc"
    );
  });
});
