# Roadmap

Security posture: assume capable attackers and prioritize least privilege, auditability, and safe rollback paths.

## Path 1: Core auth and storage modularization (short term)
- Done: Extract auth/token utilities into `py/fortress/auth.py`.
- Done: Extract storage helpers into `py/fortress/storage.py`.
- Done: Keep `py/server.py` focused on route wiring and orchestration.

## Path 2: Monitoring baseline and anomaly detection (short term)
- Persist historical resource snapshots for hosts and containers.
- Compare new samples against baselines to flag rate-based anomalies (CPU deltas, network spikes).

## Path 3: Audit and scope enforcement tests (short term)
- Add unit tests for container scope enforcement rules.
- Add unit tests for audit logging behavior (mock LXC subprocess calls).

## Path 4: Integration tests and permission matrix (mid term)
- Add integration tests for core API flows.
- Validate the permission matrix across endpoints and scopes.

## Path 5: Recipes lifecycle management (mid term)
- Add export/import bundles for recipes.
- Track semantic versions and change history for recipe updates.

## Path 6: External server cloning and migration (mid term)
- Add a secure "clone external server" workflow using FTP/SFTP and database credentials (MySQL, MongoDB, etc.).
- Support read-only migrations, dry-run planning, and checksums to validate transferred assets.
- Store credentials securely and redact them from logs; enforce TLS and least-privilege roles.
- Provide rollback and cleanup steps for partially applied migrations.

## Path 7: Shared hosting routing (short term)
- Add automatic TLS issuance/renewal (Let's Encrypt) for routing entries.
- Support multi-domain routes and wildcard certificates.
- Refresh nginx upstreams when container IPs change (or add LXD DNS-based upstreams).

## Path 8: Lizard UI (app-based web manager) (short term)
- Add UI auth flow with server-side sessions backed by delegated tokens (no tokens in the browser).
- Expand container actions: start/stop/restart, snapshots, exec, user/group management, and port exposure flows.
- Implement step-by-step wizards for container creation, routing, recipe apply, and backup/restore.
- Flesh out container sub-apps (Access, Network, Packages, Recipes, Backups) with live API wiring.
- Add monitoring dashboards powered by `/monitoring/resources` with alert overlays.
- Define and document a stable module manifest schema + hot-reload for `ui/apps` modules.
- LAMP module: add HTTPS routing wizard, web file manager option, and service detection backed by container labels or probes.
