import { describe, expect, it } from "vitest";
import {
  DEFAULT_COOKIE,
  DEFAULT_ORIGIN,
  buildDefaultScenarios,
  evaluateCookieSend,
  evaluateJsAccess,
  formatSetCookieHeader,
  getRecommendations,
  isDomainMatch,
  isPathMatch,
  validateAttributes,
  type CookieAttributes,
  type SimulatedRequest,
} from "@/lib/cookies";

const baseCookie: CookieAttributes = { ...DEFAULT_COOKIE };
const origin = { ...DEFAULT_ORIGIN };

function req(partial: Partial<SimulatedRequest>): SimulatedRequest {
  return {
    scheme: "https",
    host: origin.host,
    path: "/",
    method: "GET",
    kind: "navigation",
    siteRelation: "same-site",
    isTopLevel: true,
    ...partial,
  };
}

describe("isDomainMatch", () => {
  it("matches host-only cookies to the exact setter host", () => {
    expect(isDomainMatch("", "app.example.com", "app.example.com")).toBe(true);
    expect(isDomainMatch("", "other.example.com", "app.example.com")).toBe(false);
  });

  it("matches Domain attribute against host and subdomains", () => {
    expect(isDomainMatch("example.com", "example.com", "app.example.com")).toBe(
      true,
    );
    expect(
      isDomainMatch("example.com", "app.example.com", "app.example.com"),
    ).toBe(true);
    expect(
      isDomainMatch(".example.com", "api.example.com", "www.example.com"),
    ).toBe(true);
    expect(isDomainMatch("example.com", "evil.com", "app.example.com")).toBe(
      false,
    );
  });

  it("rejects Domain that the setter could not claim", () => {
    expect(isDomainMatch("other.com", "other.com", "app.example.com")).toBe(
      false,
    );
  });
});

describe("isPathMatch", () => {
  it("matches path prefixes with segment boundaries", () => {
    expect(isPathMatch("/", "/anything")).toBe(true);
    expect(isPathMatch("/app", "/app")).toBe(true);
    expect(isPathMatch("/app", "/app/settings")).toBe(true);
    expect(isPathMatch("/app", "/apple")).toBe(false);
    expect(isPathMatch("/app/", "/app/x")).toBe(true);
  });
});

describe("evaluateCookieSend — SameSite", () => {
  it("Strict allows same-site and blocks all cross-site", () => {
    const cookie = { ...baseCookie, sameSite: "Strict" as const };

    expect(
      evaluateCookieSend(cookie, origin, req({ siteRelation: "same-site" })).sent,
    ).toBe(true);

    expect(
      evaluateCookieSend(
        cookie,
        origin,
        req({ siteRelation: "cross-site", kind: "navigation", method: "GET" }),
      ).sent,
    ).toBe(false);

    expect(
      evaluateCookieSend(
        cookie,
        origin,
        req({ siteRelation: "cross-site", kind: "xhr", method: "POST" }),
      ).sent,
    ).toBe(false);
  });

  it("Lax allows cross-site top-level GET but not XHR or POST", () => {
    const cookie = { ...baseCookie, sameSite: "Lax" as const };

    expect(
      evaluateCookieSend(
        cookie,
        origin,
        req({
          siteRelation: "cross-site",
          kind: "navigation",
          method: "GET",
          isTopLevel: true,
        }),
      ).sent,
    ).toBe(true);

    expect(
      evaluateCookieSend(
        cookie,
        origin,
        req({
          siteRelation: "cross-site",
          kind: "navigation",
          method: "POST",
          isTopLevel: true,
        }),
      ).sent,
    ).toBe(false);

    expect(
      evaluateCookieSend(
        cookie,
        origin,
        req({ siteRelation: "cross-site", kind: "xhr", method: "GET" }),
      ).sent,
    ).toBe(false);
  });

  it("None with Secure allows cross-site XHR", () => {
    const cookie = {
      ...baseCookie,
      sameSite: "None" as const,
      secure: true,
    };

    const decision = evaluateCookieSend(
      cookie,
      origin,
      req({ siteRelation: "cross-site", kind: "xhr", method: "POST" }),
    );
    expect(decision.sent).toBe(true);
  });

  it("None without Secure never stores / never sends", () => {
    const cookie = {
      ...baseCookie,
      sameSite: "None" as const,
      secure: false,
    };

    const decision = evaluateCookieSend(
      cookie,
      origin,
      req({ siteRelation: "same-site" }),
    );
    expect(decision.sent).toBe(false);
    expect(decision.blockedBy).toContain("SameSite=None without Secure");
  });
});

describe("evaluateCookieSend — Secure, Domain, Path", () => {
  it("blocks Secure cookies on HTTP", () => {
    const decision = evaluateCookieSend(
      { ...baseCookie, secure: true },
      origin,
      req({ scheme: "http" }),
    );
    expect(decision.sent).toBe(false);
    expect(decision.blockedBy).toContain("Secure");
  });

  it("allows non-Secure cookies on HTTP", () => {
    const decision = evaluateCookieSend(
      { ...baseCookie, secure: false, sameSite: "Lax" },
      origin,
      req({ scheme: "http" }),
    );
    expect(decision.sent).toBe(true);
  });

  it("enforces Path", () => {
    const cookie = { ...baseCookie, path: "/admin" };
    expect(
      evaluateCookieSend(cookie, origin, req({ path: "/admin/users" })).sent,
    ).toBe(true);
    expect(
      evaluateCookieSend(cookie, origin, req({ path: "/public" })).sent,
    ).toBe(false);
  });

  it("enforces host-only Domain", () => {
    const cookie = { ...baseCookie, domain: "" };
    expect(
      evaluateCookieSend(cookie, origin, req({ host: "app.example.com" })).sent,
    ).toBe(true);
    expect(
      evaluateCookieSend(cookie, origin, req({ host: "api.example.com" })).sent,
    ).toBe(false);
  });
});

describe("evaluateJsAccess", () => {
  it("blocks document.cookie when HttpOnly", () => {
    const r = evaluateJsAccess({ ...baseCookie, httpOnly: true });
    expect(r.accessible).toBe(false);
  });

  it("allows document.cookie when not HttpOnly", () => {
    const r = evaluateJsAccess({ ...baseCookie, httpOnly: false });
    expect(r.accessible).toBe(true);
  });
});

describe("validateAttributes & recommendations", () => {
  it("flags SameSite=None without Secure as error", () => {
    const issues = validateAttributes({
      ...baseCookie,
      sameSite: "None",
      secure: false,
    });
    expect(issues.some((i) => i.code === "samesite-none-requires-secure")).toBe(
      true,
    );
  });

  it("warns when HttpOnly is missing", () => {
    const issues = validateAttributes({ ...baseCookie, httpOnly: false });
    expect(issues.some((i) => i.code === "missing-httponly")).toBe(true);
  });

  it("returns core educational recommendations", () => {
    const recs = getRecommendations(baseCookie);
    expect(recs.some((r) => r.id === "samesite-none-secure")).toBe(true);
    expect(recs.some((r) => r.id === "session-httponly")).toBe(true);
  });
});

describe("helpers", () => {
  it("formats a Set-Cookie style header", () => {
    const header = formatSetCookieHeader({
      name: "sid",
      value: "1",
      secure: true,
      httpOnly: true,
      sameSite: "None",
      domain: ".example.com",
      path: "/",
    });
    expect(header).toContain("sid=1");
    expect(header).toContain("Secure");
    expect(header).toContain("HttpOnly");
    expect(header).toContain("SameSite=None");
    expect(header).toContain("Domain=example.com");
  });

  it("builds six default scenarios", () => {
    const scenarios = buildDefaultScenarios("app.example.com", "/");
    expect(scenarios).toHaveLength(6);
    expect(scenarios.map((s) => s.id)).toContain("cross-xhr");
  });
});
