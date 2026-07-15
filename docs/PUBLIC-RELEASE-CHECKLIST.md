# Public Git Release Checklist

This checklist prepares the repository for public hosting. It does not authorize pushing, publishing binaries, installing a new version, switching a real provider, or using a real API key.

## Repository hygiene

- [ ] No real keys, passwords, cookies, tokens, account identifiers, SSH targets, or private upstream URLs.
- [ ] No user-specific absolute paths.
- [ ] Runtime data, SQLite files, logs, diagnostics, screenshots, build output, and credentials are ignored.
- [ ] `README.md` clearly distinguishes the stable installed baseline from unreleased `main` development.
- [ ] `SECURITY.md` describes safe vulnerability reporting.
- [x] MIT License selected by the repository owner.

Preparation audit:

```powershell
.\.venv\Scripts\python.exe -B tools\public_release_audit.py --allow-no-license
```

Final audit must run without `--allow-no-license`.

## Windows product gates

- [x] Offline protocol, failover, breaker, privacy, resource, and diagnostics tests passed.
- [ ] Real minimal P1/P2 capability acceptance completed under an explicit request and cost budget.
- [ ] Real fixed-provider activation and recovery completed without chat/archive/index/SQLite changes.
- [ ] Windows Gateway background registration and login restart verified.
- [ ] Versioned portable package and installer generated with SHA-256 manifests.
- [ ] Clean install, `v1.6.2` upgrade, uninstall-with-data-retention, and rollback passed.
- [ ] Final binary contents and logs passed secret/privacy scanning.

## Scope statement

The first release target is a local Windows computer. Linux/NAS code remains experimental and must not be advertised as production-supported until a separate real NAS acceptance is completed.

## Publication ownership

The repository owner will create the remote and publish it. Automation must not add a remote, push commits, publish a release, or overwrite any `latest` artifact without explicit authorization.
