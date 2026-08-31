/**
 * CookieScope — pure cookie-attribute evaluation (simulator only).
 * Models Secure, HttpOnly, SameSite, Domain, and Path without touching
 * real browser storage or third-party sites.
 */

export type SameSite = "Strict" | "Lax" | "None";
export type Scheme = "http" | "https";
export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
export type RequestKind = "navigation" | "xhr";
export type SiteRelation = "same-site" | "cross-site";

export interface CookieAttributes {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: SameSite;
  /** Empty string = host-only cookie for the setter host. Leading dot optional. */
  domain: string;
  path: string;
}

/** Host that originally Set-Cookie (used for host-only matching). */
export interface CookieOrigin {
  host: string;
}

export interface SimulatedRequest {
  scheme: Scheme;
  host: string;
  path: string;
  method: HttpMethod;
  kind: RequestKind;
  siteRelation: SiteRelation;
  /** Top-level document navigation (vs iframe / XHR). Defaults true for navigation. */
  isTopLevel?: boolean;
}

export interface SendDecision {
  sent: boolean;
  reasons: string[];
  blockedBy: string[];
}

export interface JsAccessDecision {
  accessible: boolean;
  reason: string;
}

export type IssueSeverity = "error" | "warning" | "info";

export interface ValidationIssue {
  severity: IssueSeverity;
  code: string;
  message: string;
}

export interface Recommendation {
  id: string;
  title: string;
  body: string;
  related: string[];
}

const SAFE_METHODS = new Set<HttpMethod>(["GET"]);

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "");
}

function normalizeDomainAttr(domain: string): string {
  return domain.trim().toLowerCase().replace(/^\./, "").replace(/\.$/, "");
}

function normalizePath(path: string): string {
  if (!path || path[0] !== "/") return "/";
  // Drop trailing slash except for root
  if (path.length > 1 && path.endsWith("/")) return path.slice(0, -1);
  return path;
}

/**
 * Domain attribute match (educational model):
 * - Empty domain → host-only: request host must equal setter host.
 * - Non-empty domain → request host equals domain or is a subdomain of it.
 */
export function isDomainMatch(
  cookieDomain: string,
  requestHost: string,
  setterHost: string,
): boolean {
  const req = normalizeHost(requestHost);
  const setter = normalizeHost(setterHost);
  const attr = normalizeDomainAttr(cookieDomain);

  if (!attr) {
    return req === setter;
  }

  // Domain must be a suffix of the setter (cookie couldn't have been set otherwise)
  if (setter !== attr && !setter.endsWith(`.${attr}`)) {
    return false;
  }

  return req === attr || req.endsWith(`.${attr}`);
}

/**
 * Path-prefix match per RFC 6265 simplified rules.
 */
export function isPathMatch(cookiePath: string, requestPath: string): boolean {
  const c = normalizePath(cookiePath);
  const r = requestPath.startsWith("/") ? requestPath : `/${requestPath}`;

  if (c === "/") return true;
  if (r === c) return true;
  if (!r.startsWith(c)) return false;

  // Next character must be '/' so /app does not match /apple
  const next = r[c.length];
  return next === "/" || next === undefined;
}

/**
 * Whether the browser would include this cookie on the simulated request.
 */
export function evaluateCookieSend(
  cookie: CookieAttributes,
  origin: CookieOrigin,
  request: SimulatedRequest,
): SendDecision {
  const reasons: string[] = [];
  const blockedBy: string[] = [];

  // Reject invalid SameSite=None without Secure up front (browsers refuse to store it)
  if (cookie.sameSite === "None" && !cookie.secure) {
    blockedBy.push("SameSite=None without Secure");
    reasons.push(
      "Browsers reject Set-Cookie when SameSite=None is used without the Secure attribute, so the cookie is never stored.",
    );
    return { sent: false, reasons, blockedBy };
  }

  if (!isDomainMatch(cookie.domain, request.host, origin.host)) {
    blockedBy.push("Domain");
    reasons.push(
      `Request host "${request.host}" does not match cookie Domain (setter: ${origin.host}, attr: ${cookie.domain || "(host-only)"}).`,
    );
  } else {
    reasons.push(
      `Domain match: request host "${request.host}" is in scope for ${cookie.domain || `host-only ${origin.host}`}.`,
    );
  }

  if (!isPathMatch(cookie.path || "/", request.path)) {
    blockedBy.push("Path");
    reasons.push(
      `Request path "${request.path}" is outside cookie Path "${cookie.path || "/"}".`,
    );
  } else {
    reasons.push(`Path match: "${request.path}" is under "${cookie.path || "/"}".`);
  }

  if (cookie.secure && request.scheme !== "https") {
    blockedBy.push("Secure");
    reasons.push("Secure cookies are only sent over HTTPS.");
  } else if (cookie.secure) {
    reasons.push("Secure flag satisfied (HTTPS request).");
  } else {
    reasons.push("No Secure flag — cookie may be sent over HTTP (insecure).");
  }

  const isTopLevel =
    request.isTopLevel ?? request.kind === "navigation";

  switch (cookie.sameSite) {
    case "Strict":
      if (request.siteRelation === "cross-site") {
        blockedBy.push("SameSite=Strict");
        reasons.push(
          "SameSite=Strict blocks all cross-site requests, including top-level navigations.",
        );
      } else {
        reasons.push("SameSite=Strict allows this same-site request.");
      }
      break;
    case "Lax":
      if (request.siteRelation === "same-site") {
        reasons.push("SameSite=Lax allows all same-site requests.");
      } else if (
        request.kind === "navigation" &&
        isTopLevel &&
        SAFE_METHODS.has(request.method)
      ) {
        reasons.push(
          "SameSite=Lax allows cross-site top-level GET (safe) navigations.",
        );
      } else {
        blockedBy.push("SameSite=Lax");
        reasons.push(
          "SameSite=Lax blocks cross-site XHR/fetch and non-safe top-level navigations (e.g. POST).",
        );
      }
      break;
    case "None":
      reasons.push(
        "SameSite=None allows same-site and cross-site requests when Secure is set.",
      );
      break;
  }

  // HttpOnly does not affect network send — note it for clarity when relevant
  if (cookie.httpOnly) {
    reasons.push(
      "HttpOnly does not change whether the cookie is attached to HTTP requests; it only blocks document.cookie access.",
    );
  }

  const sent = blockedBy.length === 0;
  return { sent, reasons, blockedBy };
}

/**
 * Whether document.cookie / client JS could read the cookie value.
 */
export function evaluateJsAccess(cookie: CookieAttributes): JsAccessDecision {
  if (cookie.httpOnly) {
    return {
      accessible: false,
      reason:
        "HttpOnly cookies are omitted from document.cookie so XSS cannot exfiltrate the session via script.",
    };
  }
  return {
    accessible: true,
    reason:
      "Without HttpOnly, any script on the page can read this cookie through document.cookie.",
  };
}

/**
 * Attribute consistency checks (storage / policy warnings).
 */
export function validateAttributes(cookie: CookieAttributes): ValidationIssue[] {
  const issues: ValidationIssue[] = [];

  if (!cookie.name.trim()) {
    issues.push({
      severity: "error",
      code: "missing-name",
      message: "Cookie name is required.",
    });
  }

  if (cookie.sameSite === "None" && !cookie.secure) {
    issues.push({
      severity: "error",
      code: "samesite-none-requires-secure",
      message:
        "SameSite=None requires Secure. Modern browsers refuse to store the cookie otherwise.",
    });
  }

  if (!cookie.secure) {
    issues.push({
      severity: "warning",
      code: "missing-secure",
      message:
        "Without Secure, the cookie can be sent over cleartext HTTP and intercepted on the network.",
    });
  }

  if (!cookie.httpOnly) {
    issues.push({
      severity: "warning",
      code: "missing-httponly",
      message:
        "Session tokens should usually be HttpOnly so XSS cannot steal them via document.cookie.",
    });
  }

  if (cookie.sameSite === "None" && cookie.secure) {
    issues.push({
      severity: "info",
      code: "cross-site-enabled",
      message:
        "SameSite=None enables cross-site attachment. Prefer Lax/Strict unless you truly need third-party contexts.",
    });
  }

  if (cookie.domain && cookie.domain.trim()) {
    issues.push({
      severity: "info",
      code: "broad-domain",
      message:
        "A Domain attribute shares the cookie with matching subdomains. Prefer host-only cookies when possible.",
    });
  }

  const path = cookie.path || "/";
  if (path !== "/" && !path.startsWith("/")) {
    issues.push({
      severity: "error",
      code: "invalid-path",
      message: 'Path must start with "/".',
    });
  }

  return issues;
}

/**
 * Educational recommendations tied to the configured attributes.
 */
export function getRecommendations(cookie: CookieAttributes): Recommendation[] {
  const recs: Recommendation[] = [];

  recs.push({
    id: "samesite-none-secure",
    title: "Why SameSite=None requires Secure",
    body: "Cross-site cookies travel on requests initiated by other sites. Without HTTPS, those requests (and the cookie) can be sniffed or altered on the network. Browsers therefore require Secure whenever SameSite=None so third-party cookies only move over TLS.",
    related: ["SameSite", "Secure"],
  });

  recs.push({
    id: "session-httponly",
    title: "Why session cookies should be HttpOnly",
    body: "HttpOnly keeps the cookie out of document.cookie. If an attacker injects script (XSS), they still cannot read the session token from JavaScript. Pair HttpOnly with Secure, short lifetimes, and CSRF defenses (SameSite or tokens).",
    related: ["HttpOnly", "XSS"],
  });

  if (cookie.sameSite === "Strict") {
    recs.push({
      id: "strict-tradeoff",
      title: "SameSite=Strict trade-off",
      body: "Strict gives the strongest CSRF protection but also withholds the cookie on cross-site top-level GET navigations (e.g. clicking a link from email). Users may appear logged out until they navigate within your site.",
      related: ["SameSite=Strict"],
    });
  }

  if (cookie.sameSite === "Lax") {
    recs.push({
      id: "lax-default",
      title: "Lax is a solid default",
      body: "SameSite=Lax sends the cookie on same-site traffic and on top-level GET navigations from other sites, while blocking cross-site XHR/fetch. That stops most CSRF via POST while keeping “open link, already logged in” working.",
      related: ["SameSite=Lax"],
    });
  }

  if (!cookie.secure || cookie.sameSite === "None") {
    recs.push({
      id: "always-secure-prod",
      title: "Prefer Secure in production",
      body: "Mark authentication cookies Secure so they never ride cleartext HTTP. Required for SameSite=None; strongly recommended for Lax/Strict as well.",
      related: ["Secure"],
    });
  }

  return recs;
}

/** Preset scenarios used by the UI simulator. */
export interface ScenarioDefinition {
  id: string;
  label: string;
  description: string;
  request: SimulatedRequest;
}

export function buildDefaultScenarios(
  originHost: string,
  cookiePath: string,
): ScenarioDefinition[] {
  const path = cookiePath.startsWith("/") ? cookiePath : `/${cookiePath}`;
  const childPath = path === "/" ? "/dashboard" : `${path}/item`;

  return [
    {
      id: "same-nav-get",
      label: "Same-site navigation (GET)",
      description: "User clicks an in-app link on the same site.",
      request: {
        scheme: "https",
        host: originHost,
        path: childPath,
        method: "GET",
        kind: "navigation",
        siteRelation: "same-site",
        isTopLevel: true,
      },
    },
    {
      id: "cross-nav-get",
      label: "Cross-site navigation (GET)",
      description: "User follows a link from another site (top-level GET).",
      request: {
        scheme: "https",
        host: originHost,
        path: childPath,
        method: "GET",
        kind: "navigation",
        siteRelation: "cross-site",
        isTopLevel: true,
      },
    },
    {
      id: "cross-nav-post",
      label: "Cross-site navigation (POST)",
      description: "Cross-site form POST into your origin.",
      request: {
        scheme: "https",
        host: originHost,
        path: childPath,
        method: "POST",
        kind: "navigation",
        siteRelation: "cross-site",
        isTopLevel: true,
      },
    },
    {
      id: "same-xhr",
      label: "Same-site XHR / fetch",
      description: "fetch() or XHR from a page on the same site.",
      request: {
        scheme: "https",
        host: originHost,
        path: childPath,
        method: "GET",
        kind: "xhr",
        siteRelation: "same-site",
        isTopLevel: false,
      },
    },
    {
      id: "cross-xhr",
      label: "Cross-site XHR / fetch",
      description: "Cross-origin API call that might include credentials.",
      request: {
        scheme: "https",
        host: originHost,
        path: childPath,
        method: "POST",
        kind: "xhr",
        siteRelation: "cross-site",
        isTopLevel: false,
      },
    },
    {
      id: "http-nav",
      label: "Same-site over HTTP",
      description: "Insecure scheme — tests the Secure attribute.",
      request: {
        scheme: "http",
        host: originHost,
        path: childPath,
        method: "GET",
        kind: "navigation",
        siteRelation: "same-site",
        isTopLevel: true,
      },
    },
  ];
}

export function formatSetCookieHeader(cookie: CookieAttributes): string {
  const parts = [`${cookie.name}=${cookie.value}`];
  parts.push(`Path=${cookie.path || "/"}`);
  if (cookie.domain.trim()) {
    parts.push(`Domain=${normalizeDomainAttr(cookie.domain)}`);
  }
  if (cookie.secure) parts.push("Secure");
  if (cookie.httpOnly) parts.push("HttpOnly");
  parts.push(`SameSite=${cookie.sameSite}`);
  return parts.join("; ");
}

export const DEFAULT_COOKIE: CookieAttributes = {
  name: "session_id",
  value: "sim_abc123",
  secure: true,
  httpOnly: true,
  sameSite: "Lax",
  domain: "",
  path: "/",
};

export const DEFAULT_ORIGIN: CookieOrigin = {
  host: "app.example.com",
};

/** Named attribute presets for the simulator UI. */
export interface CookiePreset {
  id: string;
  label: string;
  description: string;
  cookie: CookieAttributes;
  setterHost?: string;
}

export const COOKIE_PRESETS: CookiePreset[] = [
  {
    id: "session-httponly-lax",
    label: "Session HttpOnly Lax",
    description:
      "Typical auth cookie: Secure + HttpOnly + SameSite=Lax. Blocks cross-site XHR; JS cannot read it.",
    cookie: {
      name: "session_id",
      value: "sim_session_ok",
      secure: true,
      httpOnly: true,
      sameSite: "Lax",
      domain: "",
      path: "/",
    },
  },
  {
    id: "tracking-none-insecure",
    label: "Tracking SameSite=None (no Secure)",
    description:
      "Invalid combo — browsers refuse to store SameSite=None without Secure. Expect an error warning.",
    cookie: {
      name: "track_id",
      value: "sim_tracker",
      secure: false,
      httpOnly: false,
      sameSite: "None",
      domain: "example.com",
      path: "/",
    },
  },
  {
    id: "third-party-secure",
    label: "Third-party None + Secure",
    description:
      "Valid cross-site cookie: SameSite=None with Secure. Sent on cross-site XHR when allowed.",
    cookie: {
      name: "embed_pref",
      value: "sim_embed",
      secure: true,
      httpOnly: false,
      sameSite: "None",
      domain: "",
      path: "/",
    },
  },
];
