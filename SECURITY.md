# Security Policy

## Supported code

The `main` branch contains unreleased development work. The last verified installed baseline remains `v1.6.2` until a newer version completes real Windows acceptance, installation, upgrade, uninstall, and rollback testing.

## Reporting a vulnerability

Please do not open a public issue containing API keys, tokens, cookies, account identifiers, chat content, local absolute paths, SSH targets, or diagnostic archives with private data.

When reporting a problem, include only:

- the Guardian and Codex versions;
- the stable public error code;
- the operating system version;
- minimal reproduction steps using fake credentials and synthetic content.

Rotate any credential that may have been exposed before sharing a report.

## Security boundaries

- API credentials are expected to be protected with Windows DPAPI.
- Gateway and management endpoints bind to loopback and use separate tokens.
- The failover data plane must not read or modify Codex chat, archive, SQLite, or index files.
- Logs and diagnostic bundles must not contain prompts, responses, tool arguments, authorization headers, cookies, or full upstream URLs.
- NAS support is experimental until separately validated on a real target.
