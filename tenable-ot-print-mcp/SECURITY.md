# Security Policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in this project,
please **do not** open a public issue. Instead, either:

- Email **dstorey@barossafarm.com**, or
- Use GitHub's private vulnerability reporting feature on this
  repository (Security tab → "Report a vulnerability").

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce, proof-of-concept code, or the affected
  commit/tag.
- Your suggested fix, if you have one.

You'll get an acknowledgment within 5 business days, and a plan for a
coordinated disclosure timeline appropriate to the severity.

## Scope

This project's threat model assumes:

- The Tenable OT service-account API key configured in
  `/data/config.enc` is treated as a production secret. The bearer
  tokens issued by the setup wizard are likewise sensitive.
- Generated reports written to `/output` can contain sensitive OT
  asset, vulnerability, and policy-finding data pulled live from your
  Enterprise Manager — treat that filestore with the same access
  controls you'd apply to an export from Tenable OT Security itself.
- The container's `/data` and `/output` volumes are protected by the
  host's standard filesystem permissions; an attacker with shell
  access to the host is outside the threat model.
- TLS termination for production deployments is provided by a reverse
  proxy in front of the container (nginx, Caddy, Traefik, or a cloud
  load balancer). The container itself listens on plain HTTP by
  default (`MCP_TLS_DISABLE=1`) unless configured otherwise.

## Out of scope

- Vulnerabilities in Tenable OT Security itself (report those to
  Tenable directly).
- Vulnerabilities in the consuming MCP client (report those to the
  client's vendor).
- Self-inflicted issues from disabling TLS verification, exposing the
  setup wizard publicly, sharing bearer tokens, or leaving generated
  reports in a world-readable location.
