# Roadmap

Security posture: assume capable attackers and prioritize least privilege, auditability, and safe rollback paths.

## Path 1: Core auth and storage modularization (short term)
- Done: Extract auth/token utilities into `py/fortress/auth.py`.
- Done: Extract storage helpers into `py/fortress/storage.py`.
- Done: Keep `py/server.py` focused on route wiring and orchestration.

## Path 2: Monitoring baseline and anomaly detection (short term)
- Done: Persist historical resource snapshots for hosts and containers.
- Done: Compare new samples against baselines to flag rate-based anomalies (CPU deltas, network spikes).
- Done: Expose anomaly thresholds and history retention controls via API parameters or config.

## Path 3: Audit and scope enforcement tests (short term)
- Done: Add unit tests for container scope enforcement rules.
- Done: Add unit tests for audit logging behavior (mock LXC subprocess calls).

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
- Done: Support multi-domain routes and wildcard server names for routing entries.
- Done: Add `/routing/refresh` to rebuild nginx configs when container IPs drift.
- Next: Add automatic TLS issuance/renewal (Let's Encrypt) for routing entries.
- Next: Automate upstream refresh on IP change (polling or LXD DNS-based upstreams).

## Path 8: Lizard UI (app-based web manager) (short term)
- Done: Add UI auth flow with server-side sessions backed by delegated tokens (no tokens in the browser).
- Expand container actions: start/stop/restart, snapshots, exec, user/group management, and port exposure flows.
- Implement step-by-step wizards for container creation, routing, recipe apply, and backup/restore.
- Flesh out container sub-apps (Access, Network, Packages, Recipes, Backups) with live API wiring.
- Add monitoring dashboards powered by `/monitoring/resources` with alert overlays.
- Define and document a stable module manifest schema + hot-reload for `ui/apps` modules.
- LAMP module: add opt-in auto-probe toggle, hardening for the file manager credentials flow, and routing wizard validation hints.

## Path 9: Bootstrap and run tooling (short term)
- Done: Document `run-server.sh` usage and supported distro assumptions (apt/dnf, LXD availability).
- Done: Add a least-privilege sudoers template + service-user setup for running without full root.

## Path 10: Production HTTP hosting readiness (near term)
### Path 10.1: Firewall management + anti-DDoS
Milestones:
- Normalize firewall drivers (ufw + firewalld) behind a single policy/rules model with rule inventory and diff support.
- Add WebUI + CLI flows for opening/closing/listing ports, including the WebUI/API listener.
- Add anti-DDoS profiles (rate limits, connection caps, ban lists) with safe rollback and alert hooks.

Acceptance criteria:
- API supports open/close/list/status for host firewall rules with parity across ufw/firewalld, including CIDR allowlists.
- Rule changes are idempotent, auditable, and revert on partial failure.
- Anti-DDoS policies can be enabled/disabled per host with visible effective rules and rollback history.
- WebUI exposes a minimal firewall dashboard and the CLI includes one-command rule operations.
Next:
- Add conn-limit enforcement (nftables/iptables integration) for anti-DDoS profiles.

### Path 10.2: LAMP recipes (container-ready)
Milestones:
- Ship a curated LAMP recipe set (Apache + PHP-FPM + MariaDB/MySQL) with dependency wiring and parameter templates.
- Add recipe health checks (service status, ports, config validity) and idempotent re-apply behavior.
- Provide CLI/WebUI helpers to apply LAMP recipes with version parameters (PHP version, DB engine).

Acceptance criteria:
- A fresh container can be turned into a working LAMP stack via a single recipe apply.
- Reapplying recipes is safe (no duplicate users/config, services remain stable).
- Recipe parameters support PHP version selection, DB root password bootstrap, and optional app user creation.
- Success/failure returns a deterministic plan and a post-apply service probe report.

### Path 10.3: WebUI admin authentication hardening
Milestones:
- Introduce a dedicated admin identity store with strong password hashing and policy enforcement.
- Add lockout, throttling, and audit logging for failed logins; expose audit views to admins.
- Optional second factor (TOTP) and recovery flow if feasible without UI bloat.

Acceptance criteria:
- WebUI requires admin login even when the API is reachable; no direct access to privileged pages without a session.
- Password policy (length, complexity, rotation hints) is enforced and configurable.
- Failed login attempts are rate-limited and recorded in the audit log with source IP and user agent.
- Admin sessions can be revoked and have explicit TTLs.
Next:
- Add optional TOTP MFA enrollment and verification for admin accounts.

### Path 10.4: Website lifecycle management for PHP sites
Milestones:
- Define a first-class website model (domain(s), container, docroot, runtime, TLS, DB bindings).
- Add create/deploy/update/backup/rollback/logs/health endpoints plus WebUI flows.
- Provide PHP runtime controls (FPM pools, php.ini overrides), log tailing, and config validation checks.

Acceptance criteria:
- A site can be created, bound to routing, deployed, and verified via health check in one workflow.
- Backups and rollbacks are one-click and leave the site in a consistent state.
- Logs (web + PHP-FPM) are retrievable via API with bounded output and permissions.
- Routing, TLS, and service restarts are coordinated and rollback-safe.
Next:
- Add Let's Encrypt automation to site TLS workflows and surface TLS status.
- Support php.ini override injection and FPM pool tuning during site updates.

### Path 10.5: Auto-upgrade + migrations
Milestones:
- Add a schema registry for all JSON-backed stores with versioned definitions and default/alias metadata.
- Implement a patch ledger and migration runner (plan/apply/rollback) with dry-run support.
- Provide CLI/WebUI upgrade workflows with preflight checks and backup verification.

Acceptance criteria:
- Every JSON store carries a schema version and can be migrated forward in a dry-run that reports all changes.
- Applying a migration creates a backup and writes a patch ledger entry with checksums and timestamps.
- Rollback restores from the last known-good backup and replays integrity checks before unblocking the API.
Next:
- Extend schema coverage to monitoring history and any new JSON stores.

Design: migration engine (schema registry + patch tracking)
- Registry: keep `schemas/*.json` with `schema_version`, `schema_hash`, defaults, and `aliases` for renamed fields.
- Auto-transform: on upgrade, fill missing fields with defaults, rename alias keys, coerce common type changes, and preserve unknown fields under `_legacy` unless `prune_unknown` is set.
- Patch ledger: append to `/var/lib/fortress/migrations/ledger.jsonl` with `patch_id`, `store`, `from_schema`, `to_schema`, `checksum_before`, `checksum_after`, `backup_path`, and `applied_at`.
- Dry-run: compute a change plan per store, emit a preview (added/renamed/removed fields) without writing files.
- Rollback: restore backups for each store, verify checksums, and record a rollback entry; lock migrations with a file lock to prevent concurrent runs.
