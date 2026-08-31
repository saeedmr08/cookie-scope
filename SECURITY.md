# Security Policy

## Simulator-only design

**CookieScope does not read, write, or inspect real browser cookies.** It never accesses `document.cookie`, the Cookie Store API, or network traffic from third-party sites. All analysis runs against an in-memory attribute model you configure in the UI.

Do not use this project to:

- Scrape or dump cookies from the user's browser
- Probe live third-party origins for cookie behavior
- Store session secrets from production systems in the simulator fields

Demo values in the UI are fictional (`session_id=sim_abc123`). Treat any real tokens you paste as compromised and rotate them.

## Reporting a vulnerability

If you discover a security issue in CookieScope itself (for example, unintended access to browser storage), email **saeedmr08@gmail.com** with steps to reproduce. Please allow reasonable time for a fix before public disclosure.

## Safe defaults for real apps

When applying lessons from this simulator to production:

- Prefer `Secure` + `HttpOnly` for session cookies
- Prefer `SameSite=Lax` (or `Strict`) unless you truly need cross-site credentialed requests
- Use `SameSite=None` only with `Secure`, and only when third-party contexts are required
- Prefer host-only cookies (omit `Domain`) unless subdomain sharing is intentional
