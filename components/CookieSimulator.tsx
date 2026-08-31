"use client";

import { useMemo, useState } from "react";
import {
  COOKIE_PRESETS,
  DEFAULT_COOKIE,
  DEFAULT_ORIGIN,
  buildDefaultScenarios,
  evaluateCookieSend,
  evaluateJsAccess,
  formatSetCookieHeader,
  getRecommendations,
  validateAttributes,
  type CookieAttributes,
  type SameSite,
} from "@/lib/cookies";
import styles from "./simulator.module.css";

const SAME_SITE_OPTIONS: SameSite[] = ["Strict", "Lax", "None"];

export function CookieSimulator() {
  const [cookie, setCookie] = useState<CookieAttributes>(DEFAULT_COOKIE);
  const [setterHost, setSetterHost] = useState(DEFAULT_ORIGIN.host);
  const [expanded, setExpanded] = useState<string | null>("cross-xhr");
  const [activePreset, setActivePreset] = useState<string | null>(
    "session-httponly-lax",
  );

  const origin = useMemo(() => ({ host: setterHost }), [setterHost]);

  const scenarios = useMemo(
    () => buildDefaultScenarios(setterHost, cookie.path || "/"),
    [setterHost, cookie.path],
  );

  const results = useMemo(
    () =>
      scenarios.map((s) => ({
        ...s,
        decision: evaluateCookieSend(cookie, origin, s.request),
      })),
    [scenarios, cookie, origin],
  );

  const issues = useMemo(() => validateAttributes(cookie), [cookie]);
  const jsAccess = useMemo(() => evaluateJsAccess(cookie), [cookie]);
  const recommendations = useMemo(() => getRecommendations(cookie), [cookie]);
  const header = useMemo(() => formatSetCookieHeader(cookie), [cookie]);

  function patch(partial: Partial<CookieAttributes>) {
    setActivePreset(null);
    setCookie((prev) => ({ ...prev, ...partial }));
  }

  function applyPreset(id: string) {
    const preset = COOKIE_PRESETS.find((p) => p.id === id);
    if (!preset) return;
    setActivePreset(id);
    setCookie({ ...preset.cookie });
    if (preset.setterHost) setSetterHost(preset.setterHost);
  }

  const sentCount = results.filter((r) => r.decision.sent).length;

  return (
    <div className={styles.shell}>
      <header className={styles.hero}>
        <div className={styles.scopeRing} aria-hidden>
          <span className={styles.sweep} />
        </div>
        <p className={styles.kicker}>Saeed Rumaneh · portfolio lab</p>
        <h1 className={styles.brand}>CookieScope</h1>
        <p className={styles.lede}>
          Dial cookie attributes and watch the beam: which requests would carry
          the cookie — without ever reading your real browser jar.
        </p>
        <p className={styles.simBadge}>Simulator only · no live cookies</p>
      </header>

      <main className={styles.main}>
        <section className={styles.panel} aria-labelledby="attrs-heading">
          <div className={styles.panelHead}>
            <h2 id="attrs-heading">Attributes</h2>
            <code className={styles.headerPreview}>{header}</code>
          </div>

          <div className={styles.presetRow} role="group" aria-label="Example presets">
            {COOKIE_PRESETS.map((p) => (
              <button
                key={p.id}
                type="button"
                className={
                  activePreset === p.id ? styles.presetOn : styles.presetOff
                }
                title={p.description}
                onClick={() => applyPreset(p.id)}
              >
                {p.label}
              </button>
            ))}
          </div>
          {activePreset && (
            <p className={styles.presetHint}>
              {COOKIE_PRESETS.find((p) => p.id === activePreset)?.description}
            </p>
          )}

          <div className={styles.fields}>
            <label className={styles.field}>
              <span>Name</span>
              <input
                value={cookie.name}
                onChange={(e) => patch({ name: e.target.value })}
                spellCheck={false}
              />
            </label>
            <label className={styles.field}>
              <span>Value</span>
              <input
                value={cookie.value}
                onChange={(e) => patch({ value: e.target.value })}
                spellCheck={false}
              />
            </label>
            <label className={styles.field}>
              <span>Setter host</span>
              <input
                value={setterHost}
                onChange={(e) => {
                  setActivePreset(null);
                  setSetterHost(e.target.value);
                }}
                spellCheck={false}
              />
            </label>
            <label className={styles.field}>
              <span>Domain</span>
              <input
                value={cookie.domain}
                onChange={(e) => patch({ domain: e.target.value })}
                placeholder="(host-only)"
                spellCheck={false}
              />
            </label>
            <label className={styles.field}>
              <span>Path</span>
              <input
                value={cookie.path}
                onChange={(e) => patch({ path: e.target.value })}
                spellCheck={false}
              />
            </label>
            <label className={styles.field}>
              <span>SameSite</span>
              <select
                value={cookie.sameSite}
                onChange={(e) =>
                  patch({ sameSite: e.target.value as SameSite })
                }
              >
                {SAME_SITE_OPTIONS.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt}
                  </option>
                ))}
              </select>
            </label>
          </div>

          <div className={styles.toggles}>
            <Toggle
              label="Secure"
              checked={cookie.secure}
              onChange={(secure) => patch({ secure })}
              hint="HTTPS only"
            />
            <Toggle
              label="HttpOnly"
              checked={cookie.httpOnly}
              onChange={(httpOnly) => patch({ httpOnly })}
              hint="No document.cookie"
            />
          </div>

          <div className={styles.jsRow}>
            <span className={styles.jsLabel}>JS access</span>
            <span
              className={
                jsAccess.accessible ? styles.pillWarn : styles.pillOk
              }
            >
              {jsAccess.accessible ? "readable via script" : "blocked by HttpOnly"}
            </span>
            <p className={styles.jsReason}>{jsAccess.reason}</p>
          </div>

          {issues.length > 0 && (
            <ul className={styles.issues}>
              {issues.map((issue) => (
                <li
                  key={issue.code}
                  className={
                    issue.severity === "error"
                      ? styles.issueError
                      : issue.severity === "warning"
                        ? styles.issueWarn
                        : styles.issueInfo
                  }
                >
                  <strong>{issue.severity}</strong> {issue.message}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className={styles.panel} aria-labelledby="beam-heading">
          <div className={styles.panelHead}>
            <h2 id="beam-heading">Transmission beam</h2>
            <p className={styles.meter}>
              <span className={styles.meterFill} style={{ width: `${(sentCount / results.length) * 100}%` }} />
              <span className={styles.meterText}>
                {sentCount}/{results.length} scenarios send
              </span>
            </p>
          </div>

          <ul className={styles.scenarioList}>
            {results.map((row) => {
              const open = expanded === row.id;
              return (
                <li key={row.id} className={styles.scenario}>
                  <button
                    type="button"
                    className={styles.scenarioBtn}
                    aria-expanded={open}
                    onClick={() =>
                      setExpanded(open ? null : row.id)
                    }
                  >
                    <span
                      className={
                        row.decision.sent ? styles.blipOn : styles.blipOff
                      }
                      aria-hidden
                    />
                    <span className={styles.scenarioMeta}>
                      <span className={styles.scenarioLabel}>{row.label}</span>
                      <span className={styles.scenarioDesc}>
                        {row.description}
                      </span>
                    </span>
                    <span
                      className={
                        row.decision.sent ? styles.verdictOn : styles.verdictOff
                      }
                    >
                      {row.decision.sent ? "SENT" : "BLOCKED"}
                    </span>
                  </button>
                  {open && (
                    <div className={styles.scenarioDetail}>
                      <p className={styles.reqLine}>
                        {row.request.scheme}://{row.request.host}
                        {row.request.path} · {row.request.method} ·{" "}
                        {row.request.kind} · {row.request.siteRelation}
                      </p>
                      {row.decision.blockedBy.length > 0 && (
                        <p className={styles.blockedBy}>
                          Blocked by: {row.decision.blockedBy.join(", ")}
                        </p>
                      )}
                      <ol>
                        {row.decision.reasons.map((reason) => (
                          <li key={reason}>{reason}</li>
                        ))}
                      </ol>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </section>

        <section className={styles.recs} aria-labelledby="recs-heading">
          <h2 id="recs-heading">Recommendations</h2>
          <div className={styles.recGrid}>
            {recommendations.map((rec) => (
              <article key={rec.id} className={styles.recCard}>
                <h3>{rec.title}</h3>
                <p>{rec.body}</p>
                <p className={styles.recTags}>{rec.related.join(" · ")}</p>
              </article>
            ))}
          </div>
        </section>
      </main>

      <footer className={styles.footer}>
        <p>
          CookieScope · MIT 2026 Saeed Rumaneh · evaluation in{" "}
          <code>lib/cookies.ts</code>
        </p>
      </footer>
    </div>
  );
}

function Toggle({
  label,
  checked,
  onChange,
  hint,
}: {
  label: string;
  checked: boolean;
  onChange: (next: boolean) => void;
  hint: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      className={checked ? styles.toggleOn : styles.toggleOff}
      onClick={() => onChange(!checked)}
    >
      <span className={styles.toggleKnob} />
      <span className={styles.toggleText}>
        <strong>{label}</strong>
        <small>{hint}</small>
      </span>
    </button>
  );
}
