# Roadmap

Security posture: assume capable attackers and prioritize least privilege, auditability, and safe rollback paths.

## Production readiness checklist (current)
- [x] WebUI admin bootstrap form with password policy enforcement and gated sessions.
- [x] Package/firewall support for Ubuntu + AlmaLinux (apt/dnf/yum + ufw/firewalld).
- [x] Let's Encrypt automation (HTTP-01 via certbot) for routes and sites, with ACME challenge location in nginx configs.
- [x] Routing conflict detection across primary/alias/wildcard domains with 409 responses.
- [x] System upgrade endpoint (package updates + migrations) with dry-run planning.
- [x] Scheduled TLS renewals via an opt-in systemd timer, with failure alerts in Lizard UI Monitoring and systemd.
- [ ] DNS-01 wildcard support for Let's Encrypt.
- [x] WebUI surfaces site TLS certificate status and recent named renewal outcomes.

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
- Done: Record request outcomes including authorization failures, with request IDs linking route activity, shared subprocess outcomes and background container backups. Upgrade the existing SQLite register in place.
- Next: Add off-host audit delivery with independent retention, and collect persistent OS and guest audit events alongside Fortress events.

## Path 4: Integration tests and permission matrix (mid term)
- Done: Add route-level integration tests for recipes/system-upgrade flows with delegated-token permission matrix coverage.
- Done: Validate container-scope enforcement during recipe applies (`allowed_containers` checks).
- Done: Expand integration coverage to routing/sites/firewall endpoint sequences with fixture-backed state setup.
- Done: Delegated-token expiry (`ttl_seconds`/`expires_at` on create/update, `expired` flag in listings, CLI `api-users create --ttl` / `api-users expire`) and a 401 (missing/unknown/expired credential, with `WWW-Authenticate`) vs 403 (insufficient permission/scope) split, with a route-level status matrix in `tests/test_auth_tokens.py`.
- Done: Lizard UI preserves the expiry reason when prompting for credentials and keeps requests denied with 403 in the operation view.
- Done: Show the current delegated token's expiry in Settings. Authorized operators can review masked token summaries with expired entries first. Verify permission checks and expiry refresh after a token update through desktop and phone Chromium against the AlmaLinux 10.2 QEMU guest.

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
- Done: Add an opt-in persistent systemd timer for Certbot renewal, validate and reload nginx after each run, and report the latest outcome in Lizard UI Monitoring with its audit run ID.
- Done: Install AlmaLinux 10.2 x86_64 from the minimal ISO in QEMU and boot with SELinux enforcing. Verify the systemd timer, nginx configuration rejection, Certbot lock contention, and matching audit run IDs through desktop and phone Chromium. The browser lab uses an empty LXD inventory fixture.
- Next: Automate upstream refresh on IP change (polling or LXD DNS-based upstreams).
- Done: Verify the managed `sites-enabled` include during RPM bootstrap. Install it through nginx's HTTP configuration and roll back if verification or reload fails. Verify that real nginx on AlmaLinux 10.2 QEMU with SELinux enforcing rejects a broken route, then serves an extensionless managed route after recovery.

## Path 8: Lizard UI (app-based web manager) (short term)
- Done: Add UI auth flow with server-side sessions backed by delegated tokens (no tokens in the browser).
- Done: Wire Routing, Recipes, Host Packages, Hosts, Firewall, Monitoring, and VM list views with live API calls and wizards.
- Done: Expand container actions with start/stop/restart, snapshot create/list/restore/delete, exec/logs, and port exposure flows (user/group management still pending).
- Done: Move wizards from the right sidebar into a full-stage horizontal slide flow, with the sidebar reused for current-operation context.
- Done: Add a live image catalog panel on the Containers page with remote filters and direct LXD availability refresh.
- Done: Add a dedicated Settings app for global operations and a customizable fast-actions horizontal menu.
- Done: Add a destination and confirmation wizard for stored container restores. The Backups app lists, verifies, downloads, and restores accessible archives even when the source container has been removed. The per-container view also queues exports and shows request IDs.
- Flesh out container sub-apps (Access, Network, Packages, Recipes) with live API wiring.
- Add a settings panel to manage popular LXD image presets, show remote availability, and refresh latest LTS aliases.
- Add monitoring dashboards powered by `/monitoring/resources` with alert overlays.
- Define and document a stable module manifest schema + hot-reload for `ui/apps` modules.
- LAMP module: add opt-in auto-probe toggle, hardening for the file manager credentials flow, and routing wizard validation hints.
- Done: Add keyboard + touch navigation for wizard step transitions (← / → outside form fields, horizontal swipe on the wizard viewport); gestures never submit the final step.
- Done: Add an inline wizard step summary/history strip with breadcrumb quick-jump so users can navigate back to Home/sections and prior wizard steps without losing context.
- Done: Persist wizard progress markers per active flow (sessionStorage, sensitive fields dropped, 12 h expiry) with a Resume/Discard banner after page refresh.
- Done: Add drag/drop (and ↑/↓ button) ordering for the fast-actions menu in Settings.
- Done: Save, switch, and remove named fast-action profiles in Settings. Preserve the legacy selection and order as the default profile.
- Done: Rerun the dry-run preflight when resuming System Upgrade past Scope. Restore saved Execute progress at Backups with fresh confirmation, and allow a retry from Scope after preflight failure.
- Next: Add a background cache refresh + health indicator for public LXD simplestream lookups and keep Ubuntu/Debian version-to-codename mappings current as new releases ship.
- Done: Rework app navigation cards into an app-store model where icon click opens directly and title/description toggles an animated more-info panel with deep actions + Open CTA.
- Done: Align app deck UX closer to legacy Lizard: fixed-height rectangular app buttons, row-level dark-fiber more-info expansion, and active-button bottom-extension animation without resizing sibling cards.
- Done: Add stage-level app-home fallbacks for leaf/fullscreen app views so opening main apps without child cards never renders a blank stage.
- Done: Add richer per-item app-home actions for main ops (route refresh/delete, site deploy/backup, VM start/stop/snapshot).
- Done: VM Labs can create live QEMU snapshots, display saved snapshots, and confirm restore and deletion. Puppeteer verifies the wizard and session proxy, including cancellation and refresh after mutations.
- Done: Add Puppeteer-based visual regression coverage for all top-level app homes using deterministic screenshot hashes.
- Done: Add Puppeteer interaction coverage for app-card bridge open/close sequencing, row-edge alignment, and sibling non-interference during collapse.
- Done: Rework bridge/tab/panel animation geometry to use live card coordinates + shared background width/offset variables so the expanded app card, bridge, and info area render as one continuous unibody surface.
- Done: Add create-container wizard step validation (name/image/resources) with unavailable-image blocking and inline debug visibility from image catalog metadata.
- Done: Ensure Check Update + Reload triggers browser reload after successful API completion and cover it with Puppeteer automation.
- Done: Improve browser-side debugging by surfacing backend fortress-status errors (including LXD endpoint mismatch hints) in the Debug panel/event log.
- Done: Harden container image availability discovery for older LXD CLIs by retrying `lxc image list` without `--limit` when unsupported.
- Done: Add copy/export controls for debug payloads in the UI Debug panel (copy latest/all, JSON export with key redaction, last 20 errors, clear).
- Done: Add `npm run screenshots` (`ui/scripts/capture-screenshots.mjs` + read-only demo API) that captures key Lizard UI screens into `docs/screenshots/`, plus a README Screenshots section.
- Done: Fix phone-width horizontal overflow (single grid column is now `minmax(0, 1fr)`) and inactive sites being counted/rendered as active.
- Next: Add a screenshot-freshness check that reruns `npm run screenshots` in CI and flags large diffs.
- Done: Escape wizard input values, option labels, textarea contents, and summary text. Puppeteer verifies quoted names and literal markup, and recipe parameter blocks are excluded from saved progress.
- Done: Check app-card bridge and tab alignment with Puppeteer at desktop, tablet, and phone widths.
- Next: Continue expanding app-home dashboards with richer per-item actions (route/site/VM quick controls), container sub-app homes, and visual regression coverage for stage rendering.
- Next: Add a CI lane with a real LXD daemon fixture (including Fedora remotes output variants) to validate image availability discovery end-to-end beyond mocked unit tests.
- Done: Add xterm.js Terminal app (host + recursive container sub-app) backed by server-side `/terminal/sessions*` APIs with delegated-token scope checks and OS-user mapping policies.
- Next: Add terminal session recording/replay controls (opt-in, redacted) and alert hooks for suspicious shell activity patterns.
- Next: Add optional WebSocket transport for terminal streams to reduce polling overhead on high-latency links.

## Path 9: Bootstrap and run tooling (short term)
- Done: Document `run-server.sh` usage and supported distro assumptions (apt/dnf, LXD availability).
- Done: Add a least-privilege sudoers template + service-user setup for running without full root.
- Done: Ensure `run-server.sh` installs missing OS packages on subsequent runs, supports AlmaLinux snap-based LXD installs, and offers optional SSH hardening prompts.
- Done: Auto-heal LXD bootstrap in scripts (`lxd init --auto`, storage-pool detection, and default profile root disk device/pool assignment) to prevent `Failed getting root disk` container-launch errors.
- Done: Add `run-client.sh` helper for CLI/WebUI connection setup against remote APIs.
- Done: Add first-run delegated token prompts (server + client) with copy/paste helpers for UI/CLI bootstrap.
- Done: On a freshly installed AlmaLinux 10.2 QEMU guest, initialize LXD 5.21.9 and verify the normal Lizard UI delegated-token sign-in with SELinux enforcing. Use signed snapd RPMs from the 10.2 EPEL stream because the newer policy from the default EPEL stream failed to load.
- Done: Report the detected AlmaLinux minor release when Snap reports a SquashFS mount failure and the SELinux policy is missing. Keep Snap's exit status and direct the operator to matching signed EPEL packages.
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
- Add nftables conn-limit fallback with allowlist-aware ordering for anti-DDoS profiles.
- Revert already-applied rules when a later rule in `/firewall/rules/apply` fails (structured 500 + error audit).
- Expose connection-limit backend preference, live rule presence, and matching nftables handles in the firewall API and Lizard UI. Cover permission enforcement, unreadable rules, and status rendering.
- Install AlmaLinux 10.2 x86_64 from its minimal ISO onto a fresh QEMU disk and boot from the installed system. Verify the connection-limit allowlist and cap against real firewalld and nftables, remove the cap to check drift reporting, and confirm the result and request ID in Chromium at desktop and phone widths.

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
- Add persisted recipe health history storage (`/var/lib/fortress/recipe_health_history.json`) and `/recipes/health-history` trend endpoint.
- Surface recipe health history trend cards in Lizard UI (run totals, pass rate, failure trend sparkline, recent runs).
Next:
- Add optional trend-based alerts (for repeated failed runs) into monitoring cards/webhooks.

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
- Show failed service restarts in the Lizard UI wizard and preserve structured site operation error messages from Fortress.
- Show per-certificate TLS renewal history in Lizard UI. Record successful and failed named Certbot attempts in the audit register with request IDs and dry-run flags. Enforce container scope when renewing by domain.
- Validate TLS history on AlmaLinux 10.2 x86_64 under QEMU with SELinux enforcing. Check a current certificate and a failed dry run with real Certbot, then match the audit request IDs to the Sites preview in desktop and phone Chromium.
Progress:
- WebUI surfaces per-site routing/TLS/runtime/database details and backup lists with rollback triggers.
- Add TLS status/renewal state in WebUI (`tls_status` + `/sites/{site_id}/tls/status`).
- Add PHP-FPM pool tuning during site updates (runtime `fpm_pool` controls in API + WebUI wizard).

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
Done: Auto-stash/restore local changes in `/system/update-reload` (default enabled) to avoid dirty-tree failures in Settings/CLI update flows.
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

## Path 11: Known gaps from the AGENTS.md audit (short term)
Discovered while rebuilding `AGENTS.md` against the code.
- Done: Sync `api-v1.yaml` with the route registry (container lifecycle/snapshot/exec/logs, `/firewall/rules/diff`, `/sites/{site_id}/backups`, missing `ErrorResponse` schema) and enforce method+path parity and `$ref` resolution in `tests/test_api_spec.py`.
- Done: `GET /backup/download/{filename}` returns a `FileResponse` with filename-pattern validation; `/backup/list` and downloads are scoped by `allowed_containers`; `BACKUP_DIR` is created on demand; backups are written `0600` via `.partial` + rename.
- Done: `POST /restore` streams uploads into a per-request staging dir (no concurrent-restore collisions), validates container names, and supports `FORTRESS_RESTORE_MAX_BYTES`.
- Done: `apply_firewall_rules` reverts already-applied changes when a later rule fails, and the route audits the failure (Path 10.1 acceptance criteria).
- Done: Atomic writes + file locking in `fortress.storage.save_json`, plus `update_json` for locked read-modify-write.
- Done: `encodeURIComponent` all path params proxied by `ui/server.js` (covered by `ui/tests/proxy_path_encoding.test.js`).
- Done: Filter `/status` container output by `allowed_containers`.
- Next: Consider hashing stored delegated tokens (needs a migration + `PUT/DELETE /api-users/{token}` redesign).
- Done: Moved `/api-users` writes, route persistence (routing add/remove, site routing/delete), and recipe health history appends onto locked `update_json` helpers.
- Done: Serialized the remaining read-modify-write stores: `json_store_lock` is re-entrant per thread; recipes and site create/update/delete hold the store lock (`_holds_store_lock`), hosts/VMs use `_locked_store_operation` (with the error-path audits they were missing), and SSH provision/probe run unlocked then merge changed fields.
- Done: Serialize site deploy, backup, rollback, update, delete, and restart per site across API workers. Use isolated staging directories, publish unique owner-only backup archives, and verify site ownership before rollback.
- Done: Passed the full Python suite on AlmaLinux 10.2 x86_64 under QEMU (Python 3.12.13). A three-worker smoke test verified same-site serialization, independent site progress, backup ownership, and a GNU tar round trip with stubbed LXD transport.
- Done: Checkpoint and recover the previous document root when a deploy or rollback fails. Include dotfiles, symlinks and permissions, retain the private checkpoint after failed compensation, and audit recovery outcomes. Report genuine service restart failures.
- Done: Require a separate trusted host-file permission for local site deploy sources. Omit source URLs and post-deploy command arguments from audit previews.
- Done: Booted the supplied AlmaLinux 10.2 ISO kernel and installer initramfs in QEMU. Verified checkpoint recovery, bind-mounted document roots, nested mount protection, and GNU tar's database dump exclusion.
- Done: Checkpoint the site database before rollback and recover it independently of the files after a partial SQL import or required restart failure. Preserve the private recovery artifact if database compensation fails. Verify the database binding for new backups and use the site account for imports.
- Done: Fix site routing defaults for omitted fields and quote database provisioning inputs. Verify real deployment, backup, and recovery with nginx, LXD, and MariaDB on the AlmaLinux 10.2 QEMU guest, including successful restoration of a missing database and cleanup when that restoration fails.
- Next: Persist rollback progress across API worker or host termination and give operators a way to locate interrupted recoveries. Serialize database binding changes against an active rollback.
- Done: Fixed schema registry gaps that made migrations park live fields under `_legacy` (api_users `terminal_host`/`terminal_container`, recipes `version`/`history`/timestamps, VM lifecycle fields); schemas bumped to v2, `_promote_legacy_fields` restores already-parked fields, and `SchemaFieldCoverageTests` guards new fields.
- Done: Validate SSH host/username/port/key_path (ssh option-injection → host command execution), add `--` before the ssh destination, and validate env names and provision profile names in `fortress.remote`.
- Done: Constrained VM inputs so `vm_manage` no longer implies command execution: `qemu_binary` allowlist (bare names), `extra_args` option/value allowlist, `bridge_name` pattern (no `,helper=`), `vm_dir`/`disk_path` confined to `FORTRESS_VM_ROOT` (purge refuses paths outside it), `.iso`-only `iso_path`, bounded resources; re-validated before start so legacy records can't bypass it.
- Done: QEMU snapshot create/restore/delete return 409 while the VM is running (found on AlmaLinux: `qemu-img` can't take the write lock and restore would corrupt a live disk).
- Done: Opt-in live QEMU snapshot creation, restore, and deletion through a private per-launch QMP socket, with managed disk verification, job outcome checks, and audited API and CLI operations. Stopped QEMU disk snapshots still use `qemu-img`.
- Done: Booted the supplied AlmaLinux 10.2 ISO in QEMU and verified that a live snapshot restored the installer boot menu to its saved selection. Ran the same operations from Chromium through Lizard UI and the real Fortress API, then matched the browser request IDs to their SQLite audit entries.
- Done: Add an opt-in configuration report to the VM list and surface invalid stored settings in VM Labs. Check the records without executing a hypervisor or modifying the VM store.
- Done: Write authenticated chunked container backups with private staging and collision-resistant filenames. Read legacy Fernet archives, support offline verification and scoped stored restores, and restrict uploaded archives to trusted recovery operators.
- Done: Add a local restic workflow for off-host snapshots of Fortress host state and verified staged recovery, including a rebuild and isolation runbook.
- Done: Include migration schema definitions in host snapshots. Restore a verified snapshot from a client-held restic repository into SSH staging, or transfer an existing local recovery directory. Register a checked, restored QEMU disk from a client-held VM configuration with `vm_import` permission.
- Next: Automate off-host backup scheduling, retention and backup-age alerts, and run a clean-host recovery drill with real LXD and a stopped VM disk.
- Done: Record separate macOS arm64 Chromium visual baselines for the app homes and dark surfaces while retaining the existing default baselines.
- Done: Validated the Python suite, cross-process `update_json` locking, and real firewalld partial-failure revert on an AlmaLinux 10.2 x86_64 QEMU VM; fixed firewalld 2.x rich-rule parsing (attribute order) found there.
- Done: Validated token expiry, the 401/403 split, cross-process `update_json` locking (4 uvicorn workers, 40 concurrent `/api-users` creates), the api_users v1→v2 migration with `_legacy` promotion, SSH option-injection rejection, and a real-ssh host probe on an AlmaLinux 10.2 x86_64 QEMU VM (FastAPI 0.162 / Starlette 1.10 / Pydantic 2.14 / Python 3.12).
- Done: Validated VM hardening and store locking on an AlmaLinux 10.2 x86_64 QEMU VM (Python 3.12, FastAPI 0.162 / Starlette 1.10 / Pydantic 2.14): full suite green; via the real API under 4 uvicorn workers, injection attempts (`qemu_binary` path, `-netdev …script=`, `-monitor`, `bridge_name ,helper=`, disks outside the VM root) are rejected and audited, a VM is created with real `qemu-img` and started through auto-detected `/usr/libexec/qemu-kvm` (RHEL has no `qemu-system-*` on PATH — `qemu-kvm` support was added because of this), legacy unsafe records are refused at start/purge, and 40 concurrent `/hosts` creates all persist.
- Done: Add GitHub Actions jobs for Python 3.9 and 3.12 and for Lizard UI on Node 24 with Chromium. Keep platform screenshot hash comparisons in the full local suite.
- Next: Pin `requirements.txt` versions across supported Python runtimes.
- Done: Focused tests for `fortress.tls` and `fortress.remote` (`tests/test_remote_tls.py`) and `fortress.monitoring` (`tests/test_monitoring.py`); monitoring history appends moved onto locked `update_json` (concurrent samples were being dropped).
- Done: Focused tests for `fortress.hosts`/`fortress.vms` lifecycle and VM hardening (`tests/test_hosts_vms.py`).
- Done: Add focused HTTP tests for scoped container lifecycle, snapshots, logs, exec, and connectivity, with coverage of audit redaction and port-exposure rollback. Use LXD's restart command and snapshot API for those operations.
