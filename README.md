# CookieScope

Educational **cookie-attribute simulator** by Saeed Rumaneh. Toggle Secure, HttpOnly, SameSite (Strict / Lax / None), Domain, and Path — then see whether a cookie would be attached on same-site vs cross-site navigations and XHR/fetch.

**This app never reads real browser cookies.** Everything is a local simulation.

## How to run

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

| Script | Purpose |
|--------|---------|
| `npm run dev` | Dev server |
| `npm run build` | Production build |
| `npm test` | Vitest |
| `npm run typecheck` | TypeScript check |

## Example presets

| Preset | What to notice |
|--------|----------------|
| **Session HttpOnly Lax** | Cross-site XHR blocked; JS access blocked; same-site + top-level GET send |
| **Tracking SameSite=None (no Secure)** | Error: browsers refuse to store; all scenarios blocked |
| **Third-party None + Secure** | Cross-site XHR can send; JS can still read (no HttpOnly) |

Dial attributes manually after loading a preset. Logic lives in `lib/cookies.ts`.

## Complete product flows

1. Load **Session HttpOnly Lax** — cross-site XHR is BLOCKED; JS access is blocked; same-site GET sends.
2. Load **Tracking SameSite=None (no Secure)** — expect a store warning; scenarios do not send.
3. Compare **Third-party None + Secure** — cross-site XHR is SENT. Expand a scenario to read the reasons.

## Security

See [SECURITY.md](./SECURITY.md).

## License

MIT © 2026 Saeed Rumaneh
