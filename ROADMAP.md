# Roadmap

Security posture: assume capable attackers and prioritize least privilege, auditability, and safe rollback paths.

## Production readiness checklist (current)
- [x] WebUI admin bootstrap form with password policy enforcement and gated sessions.
- [x] Package/firewall support for Ubuntu + AlmaLinux (apt/dnf/yum + ufw/firewalld).
- [x] Let's Encrypt automation (HTTP-01 via certbot) for routes and sites, with ACME challenge location in nginx configs.
- [x] Routing conflict detection across primary/alias/wildcard domains with 409 responses.
- [x] System upgrade endpoint (package updates + migrations) with dry-run planning.
- [ ] Scheduled TLS renewals (systemd timer/cron) with alerting on failures.
- [ ] DNS-01 wildcard support for Let's Encrypt.
- [ ] WebUI surfaces TLS renewal status/health.

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
- Done: Add route-level integration tests for recipes/system-upgrade flows with delegated-token permission matrix coverage.
- Done: Validate container-scope enforcement during recipe applies (`allowed_containers` checks).
- Done: Expand integration coverage to routing/sites/firewall endpoint sequences with fixture-backed state setup.
- Next: Add token-expiry/invalid-token integration cases and 401-vs-403 assertions across the permission matrix.

## Path 5: Recipes lifecycle management (mid term)
- Done: Add export/import bundles for recipes.
- Done: Track semantic versions and change history for recipe updates.
- Done: Add signed/verified recipe bundles (checksum + optional HMAC signature) before import.
- Done: Add key rotation support (active + previous signing keys) for bundle signature verification.
- Next: Add optional key identifiers in bundle metadata to improve rotation observability during verification.

## Path 6: External server cloning and migration (mid term)
- Add a secure "clone external server" workflow using FTP/SFTP and database credentials (MySQL, MongoDB, etc.).
- Support read-only migrations, dry-run planning, and checksums to validate transferred assets.
- Store credentials securely and redact them from logs; enforce TLS and least-privilege roles.
- Provide rollback and cleanup steps for partially applied migrations.

## Path 7: Shared hosting routing (short term)
- Done: Support multi-domain routes and wildcard server names for routing entries.
- Done: Add `/routing/refresh` to rebuild nginx configs when container IPs drift.
- Done: Add automatic TLS issuance/renewal (Let's Encrypt) for routing entries.
- Next: Schedule automated certbot renewals and alert on failures.
- Next: Automate upstream refresh on IP change (polling or LXD DNS-based upstreams).

## Path 8: Lizard UI (app-based web manager) (short term)
- Done: Add UI auth flow with server-side sessions backed by delegated tokens (no tokens in the browser).
- Done: Wire Routing, Recipes, Host Packages, Hosts, Firewall, Monitoring, and VM list views with live API calls and wizards.
- Done: Expand container actions with start/stop/restart, snapshot create/list/restore/delete, exec/logs, and port exposure flows (user/group management still pending).
- Done: Move wizards from the right sidebar into a full-stage horizontal slide flow, with the sidebar reused for current-operation context.
- Implement step-by-step wizards for container creation, routing, recipe apply, and backup/restore.
- Flesh out container sub-apps (Access, Network, Packages, Recipes, Backups) with live API wiring.
- Add a settings panel to manage popular LXD image presets, show remote availability, and refresh latest LTS aliases.
- Add monitoring dashboards powered by `/monitoring/resources` with alert overlays.
- Define and document a stable module manifest schema + hot-reload for `ui/apps` modules.
- LAMP module: add opt-in auto-probe toggle, hardening for the file manager credentials flow, and routing wizard validation hints.
- Next: Add keyboard + touch navigation for wizard step transitions (left/right arrows, swipe gestures).
- Next: Add an inline wizard step summary/history strip so users can jump directly to prior steps without losing context.

## Path 9: Bootstrap and run tooling (short term)
- Done: Document `run-server.sh` usage and supported distro assumptions (apt/dnf, LXD availability).
- Done: Add a least-privilege sudoers template + service-user setup for running without full root.
- Done: Ensure `run-server.sh` installs missing OS packages on subsequent runs, supports AlmaLinux snap-based LXD installs, and offers optional SSH hardening prompts.
- Done: Add `run-client.sh` helper for CLI/WebUI connection setup against remote APIs.
- Done: Add first-run delegated token prompts (server + client) with copy/paste helpers for UI/CLI bootstrap.
- Next: add CLI config crypto-versioning + re-encrypt stored secrets when hashing/crypto algorithms evolve.

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
Done:
- Add conn-limit enforcement via iptables when available.
Next:
- Add nftables conn-limit support and allowlist-aware ordering for anti-DDoS profiles.

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
Done:
- LAMP recipes accept `php_version`, `db_root_password`, `db_name`, `db_user`, and `db_password` parameters for PHP/DB bootstrapping.
- `/recipes/apply` now appends LAMP-aware `probe.health_checks` with service/process checks, port probes, and config validations.
- Lizard UI recipe apply flow now surfaces `probe.health_checks` with pass/fail/skipped severity badges and check summaries.
Next:
- Add persisted recipe health history/trend views for repeated applies per container.

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
Done:
- Add optional TOTP MFA enrollment and verification for admin accounts.
Next:
- Add recovery codes and admin-side MFA reset workflow.

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
Done:
- Add Let's Encrypt automation to site TLS workflows.
- Support php.ini override injection during site updates.
Progress:
- WebUI surfaces per-site routing/TLS/runtime/database details and backup lists with rollback triggers.
Next:
- Surface TLS status/renewal state in WebUI.
- Add PHP-FPM pool tuning during site updates.

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
Done: Add `/system/upgrade` API + CLI hook for package updates and migrations.
Done: Add WebUI upgrade wizard with preflight checks and backup confirmation.
Done: Add `/system/update-reload` API + CLI/WebUI action to pull git updates, run migrations if needed, and restart API/UI via `restart.sh`.
Done:
- Extend schema coverage to monitoring history.
- Extend schema coverage to container image presets (`/var/lib/fortress/container_images.json`).
Next:
- Extend schema coverage to any new JSON stores (firewall state, UI admin store if adopted server-side).
- Add migration tests for future object-style JSON stores beyond `container_images`.
- Add upgrade execution history/audit cards in WebUI (past preflights + run outcomes).
- Add optional branch/channel pinning and signed-update verification for update-reload workflows.

Design: migration engine (schema registry + patch tracking)
- Registry: keep `schemas/*.json` with `schema_version`, `schema_hash`, defaults, and `aliases` for renamed fields.
- Auto-transform: on upgrade, fill missing fields with defaults, rename alias keys, coerce common type changes, and preserve unknown fields under `_legacy` unless `prune_unknown` is set.
- Patch ledger: append to `/var/lib/fortress/migrations/ledger.jsonl` with `patch_id`, `store`, `from_schema`, `to_schema`, `checksum_before`, `checksum_after`, `backup_path`, and `applied_at`.
- Dry-run: compute a change plan per store, emit a preview (added/renamed/removed fields) without writing files.
- Rollback: restore backups for each store, verify checksums, and record a rollback entry; lock migrations with a file lock to prevent concurrent runs.
