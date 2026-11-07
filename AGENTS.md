# Linus' Fortress — AI Agent Reference

Fast-access operational reference for AI agents working in this repository. Read it completely before changing code; keep it true for the checked-out revision.

**Linus' Fortress** is a single-host control plane for LXD-based servers: a FastAPI service ([`py/server.py`](py/server.py)) that automates container lifecycle, nginx domain routing with TLS, encrypted container backups, delegated API tokens, monitoring/anomaly detection, an SQLite audit register, "nix-like" install recipes, firewall/anti-DDoS rules, package management (`apt`/`dnf`/`yum`), PHP site lifecycle, JSON-store migrations, PTY terminal sessions, SSH host provisioning, and QEMU/VirtualBox test VMs. It ships with an encrypted-credential CLI ([`fortress-cli.py`](fortress-cli.py)) and an optional Node/Express web UI called **Lizard UI** ([`ui/`](ui/)).

- **Maturity:** actively developed, single-maintainer project; features are functional but not yet production-hardened (see [Current Status and Known Gaps](#current-status-and-known-gaps)). No CI exists in the repository.
- **Not to be confused with:**
  - **Lizardim** — the legacy PHP/jQuery control panel vendored under [`dev_samples/lizardim-main/`](dev_samples/lizardim-main/) as *visual/UX inspiration only*. It is not part of the product, is not served, and MUST NOT be edited as if it were Lizard UI.
  - **"VPS Fortress Manager"** — the FastAPI `title` string in `py/server.py`; same product, legacy name.
  - The UI is **optional**. The API is the product and the only place security decisions are enforced.

## Read This First

Source-of-truth order (higher wins; report and fix mismatches in the same change):

1. **This file's [Essential Project Principles](#essential-project-principles)** and the README [Security posture](README.md#security-posture) section — threat model and least-privilege rules. Code that contradicts them is a bug, even if it runs.
2. **Executable contracts:** route registrations in [`py/server.py`](py/server.py) and [`py/fortress/api/containers.py`](py/fortress/api/containers.py), schema registry [`schemas/*.json`](schemas/), and tests in [`tests/`](tests/) and [`ui/tests/`](ui/tests/).
3. **[`api-v1.yaml`](api-v1.yaml)** — OpenAPI 3.0.3 HTTP contract. Method+path parity with the route registry is enforced by [`tests/test_api_spec.py`](tests/test_api_spec.py); when request/response details disagree with the route code, the code is the current behavior and the spec MUST be updated.
4. **Current source and launch scripts** ([`run-server.sh`](run-server.sh), [`restart.sh`](restart.sh), [`run-client.sh`](run-client.sh), [`requirements.txt`](requirements.txt), [`ui/package.json`](ui/package.json)).
5. **[`README.md`](README.md)** — operator documentation: auth headers, permission names, per-endpoint request bodies, env vars, setup flows. Does not prove a command still works.
6. **[`ROADMAP.md`](ROADMAP.md)** — planned work in numbered "Paths"; `Done:` items are history, `Next:` items are NOT implemented.
7. [`docs/notes/`](docs/notes/) and commit messages — historical notes only.

## Collaboration and Maintenance Rules

- **Documentation sync:** any change to routes, permissions, request bodies, env vars, CLI commands, or persisted paths MUST update, in the same change: this file, [`README.md`](README.md) (API Reference + env vars), and [`api-v1.yaml`](api-v1.yaml). New or deferred work goes into [`ROADMAP.md`](ROADMAP.md) under the matching Path as a `Next:` item.
- **Roadmap discipline:** when implementing roadmap work, move the item to `Done:` only after implementation and tests. Append any not-yet-implemented follow-ups as `Next:` bullets.
- **Tests:** add or update focused tests under [`tests/`](tests/) (Python `unittest`) or [`ui/tests/`](ui/tests/) (`node:test` + optional Puppeteer) with every behavior change. Mock `subprocess`/`run_command`; tests MUST NOT require a real LXD, nginx, firewall, or root.
- **Runtime state is never committed:** everything under `/var/lib/fortress`, `/etc/fortress`, `/etc/nginx`, `.venv/`, `ui/node_modules/`, `ui/.env.local`, `.restart-*.log`, `.update-reload.log` is host state. [`schemas/*.json`](schemas/) are *schema definitions*, not data stores.
- **Visual baselines:** [`ui/tests/fixtures/*.json`](ui/tests/fixtures/) hold screenshot/CSS hashes. Regenerate only intentionally (`UPDATE_VISUAL_BASELINES=1` / `UPDATE_DARK_SURFACE_BASELINES=1`) and say so in the commit.
- **Dirty tree:** preserve unrelated user changes; never `git reset --hard`/`clean` to simplify work. Note that `/system/update-reload` itself auto-stashes on the server host — don't rely on it in development.
- **Commits:** plain descriptive messages on `main` (no enforced convention). Commit only when asked.
- **Never** put real tokens, API keys, passwords, or private keys in code, tests, docs, or examples; tests use obvious placeholders such as `integration-master-key`.

## Essential Project Principles

### Assume a capable adversary; least privilege by default

- Every API route MUST call `authorize(endpoint, permission, ...)` in [`py/server.py`](py/server.py) (or the injected `authorize` in the container router) before doing anything, with the narrowest permission that fits. A new capability gets a new permission name rather than reusing a broad one.
- Any route that touches a container MUST pass the container name(s) to `authorize(..., containers=...)` or call `enforce_container_scope` so `allowed_containers` is honored.
- The master key (`FORTRESS_API_KEY`/`API_SECRET_KEY`) is a bootstrap tool. Long-term access uses delegated tokens. Do not add features that only work with the master key.

### Everything is audited

- Every mutating route MUST call `audit_api(...)` on success *and* on failure (`status="error"`). Internal subprocess activity goes through `audit_internal` / the `configure_audit` callback in [`py/fortress/containers.py`](py/fortress/containers.py).
- Audit details MUST be sanitized: `sanitize_payload`, `sanitize_payload_fuzzy(..., SENSITIVE_KEYWORDS)`, `sanitize_command_details`, `mask_token`. Never log raw tokens, passwords, or DB credentials.

### Changes to the host roll back on failure

- Multi-step host mutations (nginx configs, LXD proxy devices, firewall rules, migrations, site deploys) MUST restore the previous state when a later step fails. Patterns to copy: `_apply_nginx_config`/`_restore_nginx_config` (routing), `expose_ports` cleanup loop (containers), `MigrationEngine.apply` backups + ledger (migrations).
- Destructive or broad operations offer `dry_run` (recipes, firewall, migrations, system upgrade).

### The API is the security boundary; the UI is a convenience

- Lizard UI MUST NOT store delegated tokens in the browser; tokens live in server-side session maps in [`ui/server.js`](ui/server.js). UI admin login is an *additional* gate, never a replacement for API permission checks.
- No permission logic may exist only in `ui/` or `fortress-cli.py`.

### Commands are argument lists, not shell strings

- Host commands go through `run_command(list)` in [`py/fortress/system.py`](py/fortress/system.py) (`subprocess.run` without a shell). Shell strings are only acceptable for scripts executed *inside* containers/remote hosts (`bash -lc` in recipes, `bash -s` over SSH) and every interpolated value there MUST be `shlex.quote`d or validated first.

## Critical Implementation Contracts

- **Auth resolution:** `verify_token` in [`py/fortress/auth.py`](py/fortress/auth.py) accepts `X-API-Key` or `X-User-Token`, either optionally typed (`api-key:…`, `user-token:…`, aliases in `TOKEN_TYPE_ALIASES`). Master key wins when both are present. The master key is disabled when unset *or equal to* `DEFAULT_API_SECRET`. All failures raise **403** (no 401 distinction yet). Tests: [`tests/test_auth_audit.py`](tests/test_auth_audit.py), [`tests/test_permissions_matrix.py`](tests/test_permissions_matrix.py).
- **Wildcard permission:** a token with `"*"` in `permissions` passes every permission check, and `_terminal_admin_access` lets it read/write *any user's* terminal sessions.
- **Empty scope means unrestricted:** `enforce_container_scope` only restricts when `allowed_containers` is a **non-empty** list. `null` *and* `[]` both grant every container. Never treat `[]` as "no containers".
- **Container-terminal exception:** `_require_terminal_permission` accepts `terminal_container` **or** `manage_containers` for container shells. Host shells require `terminal_host`. Root shells require `terminal_root` (or policy `allow_root`); OS-user override requires `terminal_impersonate` (or `allow_user_override`). A token with no `terminal_*.os_user` mapping falls back to its username if that is a valid unix name, else 403.
- **Terminal session ownership:** sessions are bound to `owner_id` = `subject_id` (`user:<sha256-prefix>` or `master`). `TerminalSessionManager` enforces owner checks, shell allowlist (`FORTRESS_TERMINAL_ALLOWED_SHELLS`), size limits, idle timeout, and max sessions. Tests: [`tests/test_terminal.py`](tests/test_terminal.py), permission matrix.
- **Delegated tokens are stored in plaintext** as the keys of `/var/lib/fortress/api_users.json` (`users[token] = record`). Responses and audit details MUST use `mask_token`. `PUT/DELETE /api-users/{token}` take the raw token in the path.
- **Routing domain conflicts:** `/routing/add` MUST call `find_domain_conflicts` (primary, aliases, and wildcard overlap via `domains_conflict`) and return **409** on conflict. Tests: [`tests/test_routing.py`](tests/test_routing.py).
- **Let's Encrypt bootstrap order:** for `tls.mode=letsencrypt` the route first writes an HTTP-only config with the ACME location (`_build_acme_location`), then runs certbot, then writes the TLS config; a certbot failure restores the previous nginx config. Do not reorder.
- **Recipe bundles:** export/import use format `fortress.recipe-bundle.v1` with SHA-256 checksum and optional HMAC-SHA256 signature. Verification tries the active key `FORTRESS_RECIPE_BUNDLE_SIGNING_KEY` then every key in `FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS`. Unsigned import requires explicit `require_signature=false` (CLI `--allow-unsigned`). Tests: [`tests/test_recipes.py`](tests/test_recipes.py), permission matrix.
- **Recipe templating:** `{{param}}` placeholders (`PLACEHOLDER_PATTERN`) are rendered by `render_template`; a missing parameter is a `ValueError` → HTTP 400. Recipe dependency cycles are rejected by `resolve_recipe_plan`.
- **Migrations:** every JSON store registered in `MIGRATION_ENGINE` (server.py) MUST have a matching `schemas/<store>.json`. `apply` takes a file lock (`migrations.lock`), backs up each store, appends to `ledger.jsonl`, and updates `versions.json`. Unknown fields are preserved under `_legacy` unless `prune_unknown`. Tests: [`tests/test_migrations.py`](tests/test_migrations.py).
- **Backups:** `perform_encrypted_backup` runs `lxc export` then Fernet-encrypts with a key derived by SHA-256 of `FORTRESS_BACKUP_PASSWORD` (`get_fernet_key`; the CLI uses the same derivation to decrypt). Changing the derivation breaks every existing backup.
- **Update-reload:** `/system/update-reload` runs `git pull --ff-only` in the repo root, auto-stashes local changes by default, applies pending migrations only when HEAD changed, then schedules `restart.sh --no-pull --mode <mode>` in a detached process. It refuses to restart if the stash could not be restored cleanly.
- **Firewall anti-DDoS ordering:** allowlist ACCEPT rules MUST be inserted *before* conn-limit DROP rules. iptables is preferred; nftables fallback uses table `inet fortress`, chain `input`, and comment tags from `_build_nft_rule_tag`. Tests: [`tests/test_firewall.py`](tests/test_firewall.py).
- **Container image canonicalization:** popular image lists merge discovered LXD images, saved presets (`/var/lib/fortress/container_images.json`, legacy bare-list and `alias` key supported), and fallbacks; stale aliases (`ubuntu:lts`, `debian:12`) are resolved via the public simplestream index (`FORTRESS_PUBLIC_IMAGE_INDEX_URL`). `_run_lxc_image_list_json` retries without `--limit` for old LXD CLIs. Tests: [`tests/test_container_images.py`](tests/test_container_images.py).
- **Lizard UI admin gate:** with `FORTRESS_UI_ADMIN_ENABLED` on (default), every `/api/*` request except `/api/admin/*` and `/api/health` needs an admin session — except while no admin exists, when `/api/session` and token-session requests are allowed (bootstrap window). Tests: [`ui/tests/admin_bootstrap.test.js`](ui/tests/admin_bootstrap.test.js).

## Architecture and Data/Control Flow

**API request:**
`uvicorn` (`py/server.py __main__`, TLS from `/etc/fortress/ssl/{key,cert}.pem`) → FastAPI route (`@app.*` in server.py, or `build_container_router` in `fortress/api/containers.py`) → `authorize` → `verify_token` + `enforce_container_scope` → domain module (`fortress/*.py`) → `run_command` / `subprocess` (`lxc`, `nginx`, `certbot`, `ufw`/`firewall-cmd`/`iptables`/`nft`, `apt`/`dnf`, `qemu`/`VBoxManage`, `ssh`) and/or JSON store (`fortress.storage`) → `audit_api` → `CommandLogger` (SQLite).

**CLI:** `fortress-cli.py <cmd>` → `FortressClient.request` (credentials decrypted with the local RSA private key) → HTTPS API.

**Lizard UI:** browser (`ui/public/js/app.js`, no tokens) → `ui/server.js` `/api/*` (admin gate → session token lookup) → `fortressRequest` (adds `X-API-Key`/`X-User-Token`) → Fortress API. The UI app graph comes from `ui/apps/*/app.json` manifests combined with live container data (`buildAppGraph`).

**Process/trust boundaries:** the API runs as root or a sudo-scoped service user ([`scripts/fortress-sudoers.template`](scripts/fortress-sudoers.template)); containers and remote hosts are untrusted; the UI server is a separate Node process with its own admin store (`ui_admins.json`) that is **local to the UI host**, not the API host.

**Persistence (all runtime, untracked):**

| Path | Owner | Notes |
| --- | --- | --- |
| `/var/lib/fortress/api_users.json` | server.py `load_api_users` | token → record; plaintext tokens |
| `/var/lib/fortress/recipes.json` | `fortress.recipes` | with version + history |
| `/var/lib/fortress/recipe_health_history.json` | server.py | capped by `FORTRESS_RECIPE_HEALTH_HISTORY_MAX` |
| `/var/lib/fortress/routes.json` | server.py routing | + nginx files in `/etc/nginx/sites-{available,enabled}` |
| `/var/lib/fortress/sites.json`, `site_backups/` | `fortress.sites` + server.py | |
| `/var/lib/fortress/hosts.json`, `vms.json`, `vms/` | `fortress.hosts`, `fortress.vms` | SSH passwords stored; redacted on output |
| `/var/lib/fortress/monitoring_history.json` | `fortress.monitoring` | ring buffer (`history_limit`) |
| `/var/lib/fortress/container_images.json` | container router | popular image presets |
| `/var/lib/fortress/firewall/{rollbacks/,ddos_policy.json}` | `fortress.firewall` | |
| `/var/lib/fortress/migrations/{versions.json,ledger.jsonl,migrations.lock}` | `fortress.migrations` | |
| `/var/lib/fortress/backups/*.enc` | server.py backup | Fernet-encrypted `lxc export`, `<container>_<ts>.tar.gz.enc`, `0600`; `.restore-*` staging dirs are transient |
| `/var/lib/fortress/command_log.db` | `fortress.audit` | override `FORTRESS_COMMAND_LOG_DB` |
| `/var/lib/fortress/shares/`, `acme-challenges/` | container router, `fortress.tls` | |
| `/etc/fortress/fortress.env` | `run-server.sh` | env for service/screen modes |
| `~/.fortress-cli/` | `fortress-cli.py` | config + RSA keypair (`FORTRESS_HOME`) |
| `ui_admins.json` (`/var/lib/fortress` as root, else `~/.fortress-ui`) | `ui/server.js` | UI admins, PBKDF2 hashes, TOTP |

## Linked Source Tree and File Reference

### [`py/server.py`](py/server.py)

The FastAPI application and the owner of most routes, configuration constants, auth glue, audit glue, and orchestration that spans modules. Domain logic that can be unit-tested without FastAPI belongs in `py/fortress/*`; keep this file as route wiring and cross-module orchestration.

- **Key functions and subparts:**
  - Module constants (lines ~183–216) — all runtime paths (`API_USERS_DB`, `ROUTING_DB`, `BACKUP_DIR`, …) and env-driven settings (`FORTRESS_API_KEY`, `FORTRESS_BACKUP_PASSWORD`, `FORTRESS_HOST_INTERFACE`/`PORT`, `FORTRESS_SCHEMA_DIR`, `FORTRESS_ACME_CHALLENGE_DIR`, `FORTRESS_RECIPE_BUNDLE_SIGNING_KEY(S)`, `FORTRESS_LOG_PATH`, `FORTRESS_COMMAND_LOG_DB`, `FORTRESS_UPDATE_RELOAD_LOG`, `FORTRESS_RECIPE_HEALTH_HISTORY_MAX`, `FORTRESS_RESTORE_MAX_BYTES`). Evaluated at import time.
  - `MIGRATION_ENGINE` — registry of store name → path; add new JSON stores here *and* in `schemas/`.
  - `authorize` — the single entry point for permission + scope checks; sets `REQUEST_CONTEXT` so audits carry the actor.
  - `audit_event` / `audit_api` / `audit_internal`, `sanitize_payload`, `sanitize_payload_fuzzy` — audit glue.
  - Terminal policy helpers: `_resolve_terminal_policy`, `_resolve_terminal_os_user`, `_require_terminal_permission`, `_authorize_terminal_session_access`, `_serialize_terminal_policy`.
  - Request models (`DomainRoute`, `DomainRouteTLS`, `APIUserCreate`, `TerminalAccessPolicy`, `Firewall*Request`, `SystemUpgradeRequest`, `SystemUpdateReloadRequest`, `Migration*Request`, `Package*Request`).
  - Update-reload: `_run_system_update_reload`, `_launch_restart_script`, `_git_*` helpers, `_restore_stashed_changes`.
  - Routing: `add_domain_routing`, `refresh_domain_routing`, `remove_domain_routing`, `_apply_nginx_config`, `_restore_nginx_config`, `_apply_nginx_route`.
  - Recipes: `LAMP_RECIPE_BUNDLE` + `FILEMANAGER_COMMAND` (seed data), `_collect_lamp_health_report` and probe builders, health-history store helpers (`_append_recipe_health_history_entry`, `_build_recipe_health_trend`).
  - Sites: `_resolve_site_tls_status`, `_apply_php_ini_overrides`, `_normalize_fpm_pool_tuning`, `_apply_php_fpm_pool_tuning`, `_apply_site_routing`, `_backup_site_files`, `_restore_site_db`, `_restart_site_services`.
  - Backups: `get_fernet_key`, `perform_encrypted_backup` (background task; `.partial` + rename, `0600`), `CONTAINER_NAME_PATTERN`, `BACKUP_FILENAME_PATTERN` (`<container>_<YYYYmmdd_HHMMSS>.tar.gz.enc`, used to scope list/download), `_ensure_backup_dir`, `restore_container` (per-request staging dir, `RESTORE_MAX_BYTES`).
  - `/status` scoping: `_filter_status_containers`.
- **Called by / depends on:** started by [`run-server.sh`](run-server.sh) / [`restart.sh`](restart.sh) as `.venv/bin/python py/server.py` (the script dir `py/` is on `sys.path`, which is how `import fortress` resolves). Imports every module in [`py/fortress/`](py/fortress/).
- **Tests:** [`tests/test_permissions_matrix.py`](tests/test_permissions_matrix.py) loads this file with `importlib` into a temp sandbox; [`tests/test_container_images.py`](tests/test_container_images.py) for popular-image endpoints.
- **Common mistakes:** path constants are read at import, so tests reassign `module.API_USERS_DB` etc. after loading — helpers MUST read the module global at call time (don't capture paths in default args). Use `.dict()` on models consistently (Pydantic v1-style API is used throughout). Don't forget the error-path `audit_api(..., status="error")`.

### [`py/fortress/api/containers.py`](py/fortress/api/containers.py)

`build_container_router(authorize, audit_api, sanitize_payload, shared_storage_dir, popular_images_db)` returns the `APIRouter` for all container routes; dependencies are injected so the module never imports `server.py`.

- **Key functions and subparts:**
  - Pydantic models: `ContainerCreate`, `PopularImage`, `ExternalAccessRule`, `ContainerUser*`, `ContainerLinkRequest`, `SharedMountRequest`, `PortRange`, `InterfaceExposure`, `MultiInterfaceExposeRequest`, `ContainerLifecycle`, `ContainerSnapshot*`, `ContainerExecRequest`.
  - `_list_popular_entries` / `_list_custom_popular_entries` / `_extract_popular_store_entries` — merge discovered, saved, and fallback images; tolerate legacy store shapes.
  - `/containers/expose` handler — creates proxy devices per interface and optional firewall allowlist rules, removing both on failure.
- **Called by / depends on:** included via `app.include_router(...)` in [`py/server.py`](py/server.py); uses [`py/fortress/containers.py`](py/fortress/containers.py) (`container_ops`) and [`py/fortress/firewall.py`](py/fortress/firewall.py).
- **Tests:** [`tests/test_container_images.py`](tests/test_container_images.py) (`PopularImageEndpointTests`).
- **Common mistakes:** every handler must pass the container name(s) into `authorize(..., containers=...)`. Image-preset endpoints reuse the audit endpoint name `container_create`; keep permission `manage_containers`.

### [`py/fortress/containers.py`](py/fortress/containers.py)

LXC/LXD operations and image discovery. Owns everything that shells out to `lxc`; owns no HTTP models.

- **Key functions and subparts:**
  - `configure_audit` / `_audit` / `sanitize_command_details` — audit hook set by server.py; redacts arguments matching `SENSITIVE_KEYWORDS`.
  - `exec_in_container`, `exec_in_container_advanced` — `lxc exec` wrappers (user/workdir/env).
  - Lifecycle: `create_container` (storage-pool selection via `list_storage_pools`/`_select_launch_storage_pool`, root-disk retry on `MISSING_ROOT_DEVICE_MARKERS`, `_set_root_disk_limit`), `start/stop/restart/delete_container`, snapshot helpers, `get_container_logs`.
  - Networking: `add_proxy_device`, `remove_device`, `open_external_access`, `connect_containers_network`, `expose_ports` (rolls back created devices), `_expand_port_inputs` (caps at `MAX_PROXY_DEVICES_PER_REQUEST`).
  - Shared mounts: `create_shared_mount`, `remove_shared_mount`, disk device helpers.
  - Services: `probe_container_services` (`CONTAINER_SERVICE_PROBES`), `set_container_services_label` (writes `user.lizard.services`).
  - Packages: `detect_package_manager`, `run_package_command`, `update_package_index`.
  - Images: `discover_popular_images`, `ensure_image_available`, `resolve_image_alias`, `resolve_alias_via_public_catalog`, `find_latest_ubuntu_lts_alias`, codename maps (`UBUNTU_VERSION_TO_CODENAME`, `DEBIAN_VERSION_TO_CODENAME`).
- **Called by / depends on:** [`py/fortress/api/containers.py`](py/fortress/api/containers.py), [`py/server.py`](py/server.py) (recipes, sites, packages, routing IP lookup via `get_container_ip`).
- **Tests:** [`tests/test_container_images.py`](tests/test_container_images.py).
- **Common mistakes:** codename maps are hard-coded — new Ubuntu/Debian releases need entries. Do not hit the network in tests; mock `_public_image_products`/`requests`. Pass commands as lists to `lxc exec … --`.

### [`py/fortress/auth.py`](py/fortress/auth.py)

Master-key resolution, typed-token parsing, delegated-token verification, and container scope enforcement. No storage access of its own (users are injected via `load_users`).

- **Key functions and subparts:** `resolve_master_key`, `parse_prefixed_token` + `TOKEN_TYPE_ALIASES`, `normalize_auth_headers`, `verify_token` (returns `auth_context` with `actor`, `permissions`, `allowed_containers`, `is_master`, `subject_id`, `user_record`), `token_fingerprint`, `mask_token`, `enforce_container_scope(s)`.
- **Called by / depends on:** `authorize` in [`py/server.py`](py/server.py).
- **Tests:** [`tests/test_auth_audit.py`](tests/test_auth_audit.py), [`tests/test_permissions_matrix.py`](tests/test_permissions_matrix.py).
- **Common mistakes:** see [Critical Implementation Contracts](#critical-implementation-contracts) — empty `allowed_containers` is unrestricted; `*` bypasses permission checks; comparisons are plain `==` (not constant-time).

### [`py/fortress/audit.py`](py/fortress/audit.py)

`CommandLogger` — thread-locked SQLite writer for the `command_log` table (`timestamp, actor, endpoint, category, action, target, details, status`). Failures are logged, never raised, so auditing can't break a request.

- **Called by / depends on:** instantiated once in [`py/server.py`](py/server.py) with `COMMAND_LOG_DB`.
- **Tests:** [`tests/test_auth_audit.py`](tests/test_auth_audit.py) (`AuditLoggingTests`).
- **Common mistakes:** the table is append-only by convention; don't add update/delete paths. Schema changes need a manual migration (it is not in the JSON migration engine).

### [`py/fortress/storage.py`](py/fortress/storage.py)

JSON helpers: `load_json` (default on missing/corrupt), `load_json_dict` (resets non-dict to `{}`), `save_json` (creates parent dir; atomic + locked), `update_json`, `json_store_lock`, `ensure_parent_dir`.

- `save_json` is atomic (temp file in the same dir + fsync + `os.replace`) and holds `json_store_lock(path)` (in-process `RLock` + `flock` on a hidden `.<name>.lock` sidecar). New files are created `0600`; existing files keep their mode. `update_json(path, default, mutate)` does a locked read-modify-write.
- **Tests:** [`tests/test_storage.py`](tests/test_storage.py).
- **Common mistakes:** a plain `load_json` → modify → `save_json` sequence is still racy across writers; use `update_json` for read-modify-write. A corrupt store silently loads as empty — and a subsequent save overwrites it.

### [`py/fortress/system.py`](py/fortress/system.py)

`run_command(cmd_list)` — `subprocess.run(check=True)` without a shell; raises `HTTPException(500, "System Error: <stderr>")` on failure. The shared way to run host commands.

### [`py/fortress/routing.py`](py/fortress/routing.py)

Pure helpers for nginx reverse-proxy configs and domain rules; owns no persistence (routes.json is handled in server.py).

- **Key functions and subparts:** `validate_domain` / `_validate_domain_name` (`*.` wildcard allowed, label/length limits), `normalize_domains`, `validate_tls_paths`, `build_nginx_proxy_config` (HTTP, TLS, redirect, ACME location, `PROXY_HEADERS`), `domains_conflict` / `find_domain_conflicts`, `write_nginx_config`, `ensure_nginx_site`, `remove_nginx_site`, `test_nginx_config` (`nginx -t`), `reload_nginx`.
- **Tests:** [`tests/test_routing.py`](tests/test_routing.py).
- **Common mistakes:** always `test_nginx_config` before `reload_nginx` and restore the previous file on failure (server.py `_apply_nginx_config` does this — reuse it).

### [`py/fortress/tls.py`](py/fortress/tls.py)

Certbot HTTP-01 integration: `ensure_certbot_available`, `ensure_acme_challenge_dir`, `build_certificate_paths` (`/etc/letsencrypt/live/<name>`), `validate_letsencrypt_domains` (rejects wildcards — DNS-01 is not supported), `issue_letsencrypt_certificate`, `renew_letsencrypt`.

- **Called by:** routing and sites flows plus `POST /tls/renew` in [`py/server.py`](py/server.py).
- **Tests:** none focused (gap).

### [`py/fortress/firewall.py`](py/fortress/firewall.py)

Firewall driver abstraction over ufw and firewalld plus anti-DDoS conn-limit rules via iptables or nftables.

- **Key functions and subparts:** `detect_firewall_backend`, `apply_firewall_rule` (single open/close incl. firewalld rich rules), parsers `_parse_ufw_status`, `_parse_ufw_rules`, `_parse_firewalld_ports`, `_parse_firewalld_rich_rules`, `get_firewall_status`, `list_firewall_rules`, `apply_firewall_rules` (merge/replace diff + rollback file), `rollback_firewall_rules`, DDoS policy `get/update/apply/remove_ddos_policy`, conn-limit backends `detect_connlimit_backend`, `_apply_connlimit_rule` (iptables), `_apply_nft_connlimit_rule` + `_ensure_nft_ddos_chain` (nftables).
- **Called by:** firewall routes in [`py/server.py`](py/server.py); `/containers/expose` allowlists.
- **Tests:** [`tests/test_firewall.py`](tests/test_firewall.py).
- **Common mistakes:** parser changes must keep both ufw and firewalld output shapes working, including firewalld attribute order differences (`port port=".." protocol=".."` on firewalld 2.x / AlmaLinux 10) — `_parse_firewalld_rich_rules` parses attributes order-independently and skips `forward-port`/`source-port`. `apply_firewall_rules` reverts already-applied changes (reverse order, via `_revert_firewall_changes`) when a later rule fails and raises `HTTPException(500)` with a structured `detail`; keep that contract when adding new rule actions.

### [`py/fortress/monitoring.py`](py/fortress/monitoring.py)

Host (`/proc/meminfo`, `/proc/stat`, `/proc/net/dev`, `df`) and container (`lxc list` state) metrics, threshold alerts, and history-based rate anomaly detection.

- **Key functions and subparts:** `collect_host_metrics`, `collect_container_metrics`, `gather_resource_snapshot`, `evaluate_host_alerts`, `evaluate_container_alerts`, `detect_rate_anomalies`, `record_resource_snapshot` (appends to history, trims to `history_limit`), defaults `DEFAULT_HOST_THRESHOLDS`, `DEFAULT_CONTAINER_THRESHOLDS`, `DEFAULT_ANOMALY_THRESHOLDS`.
- **Called by:** `GET /monitoring/resources` in [`py/server.py`](py/server.py) (thresholds are query parameters).
- **Tests:** none focused (gap). Linux-only (`/proc`).

### [`py/fortress/recipes.py`](py/fortress/recipes.py)

Recipe models, dependency resolution, template rendering, versioning/history, bundle export/import, and LAMP health-target definitions.

- **Key functions and subparts:** models `RecipeDefinition`, `RecipeUpdate`, `RecipeApplyRequest`, `RecipeExportRequest`, `RecipeImportRequest`; `resolve_recipe_plan` (topological, cycle detection), `build_recipe_execution`, `render_template`, `normalize_parameters`/`merge_parameters`; lifecycle `normalize_semver`, `bump_semver`, `create_recipe_record`, `update_recipe_record`, `build_recipe_history_entry`, `merge_recipe_histories`; bundles `build_recipe_export_bundle`, `verify_recipe_bundle`, `extract_recipe_bundle`, `prepare_import_recipe_record`; LAMP `LAMP_STACK_EXPANSION`, `collect_lamp_health_targets`, config-check constants.
- **Called by:** recipe routes in [`py/server.py`](py/server.py).
- **Tests:** [`tests/test_recipes.py`](tests/test_recipes.py), [`tests/test_permissions_matrix.py`](tests/test_permissions_matrix.py).
- **Common mistakes:** changing the digest payload (`_bundle_payload_for_digest`) invalidates all existing signed bundles. LAMP recipe content lives in server.py (`LAMP_RECIPE_BUNDLE`) and is mirrored in `ui/public/js/app.js` (`RECIPE_CATALOG`, `LAMP_STACK_DEPENDENCIES`) — keep all three in sync.

### [`py/fortress/sites.py`](py/fortress/sites.py)

Website (PHP site) Pydantic models and record helpers; execution lives in server.py.

- **Key functions and subparts:** `SiteRecord`, `SiteRuntime`, `SiteFpmPoolTuning`, `SiteDatabase`, `SiteTls`, `SiteRouting`, request models (`SiteCreateRequest`, `SiteUpdateRequest`, `SiteDeployRequest`, `SiteBackupRequest`, `SiteRollbackRequest`, `SiteServiceActionRequest`); `create_site_record` (generates DB password), `update_site_record`, `delete_site_record`, `sanitize_site_record` (masks `*password*` keys), `build_service_names`, `build_site_backup_id`.
- **Tests:** [`tests/test_sites.py`](tests/test_sites.py).
- **Common mistakes:** always return `sanitize_site_record(...)` from routes, never the raw record.

### [`py/fortress/migrations.py`](py/fortress/migrations.py)

Schema-registry migrations for JSON stores.

- **Key functions and subparts:** `load_schema_registry`, `migrate_record` (`_apply_aliases`, `_apply_defaults`, `_preserve_unknown_fields`), `migrate_store_payload`, `MigrationEngine.status/plan/apply/rollback`, `load_ledger_entries`, lock helpers `_acquire_lock`/`_release_lock`.
- **Called by:** migration routes, `/system/upgrade`, `/system/update-reload` in [`py/server.py`](py/server.py).
- **Tests:** [`tests/test_migrations.py`](tests/test_migrations.py).
- **Common mistakes:** bump `schema_version` in `schemas/<store>.json` whenever fields, defaults, or aliases change; otherwise `status()` reports nothing pending.

### [`py/fortress/terminal.py`](py/fortress/terminal.py)

PTY-backed host and container shell sessions with resource limits and owner binding. Policy (who may open what) is decided in server.py; this module enforces mechanics.

- **Key functions and subparts:** `TerminalSession` dataclass; `TerminalSessionManager` (`create_host_session` demotes to the target OS user via `pwd` + `setuid` in a preexec, `create_container_session` uses `lxc exec`, `read`/`write`/`resize`/`close`/`describe`, `_sweep_locked` idle cleanup, `_assert_owner_locked`); `normalize_shell_path`, `normalize_unix_username`; env limits `FORTRESS_TERMINAL_MAX_SESSIONS` (24), `_IDLE_TIMEOUT_SECONDS` (900), `_READ_CHUNK_BYTES`, `_READ_LIMIT_BYTES`, `_WRITE_LIMIT_BYTES`, `_ALLOWED_SHELLS`.
- **Tests:** [`tests/test_terminal.py`](tests/test_terminal.py) (helpers only); route policy in the permission matrix.
- **Common mistakes:** sessions are in-process memory — they vanish on restart and do not work with multiple uvicorn workers. Output is base64 (`output_b64`) and polled; there is no WebSocket transport.

### [`py/fortress/hosts.py`](py/fortress/hosts.py)

SSH-managed (non-VM) host registry: models `HostCreateRequest`, `HostUpdateRequest`, `HostProvisionRequest`, `HostProbeRequest`, `HostSSHConfig`; `create/update/delete_host`, `provision_host`, `probe_host`, `list_saved_states`, `sanitize_host_record` (masks SSH password).

- **Depends on:** [`py/fortress/remote.py`](py/fortress/remote.py). **Tests:** none focused (gap).

### [`py/fortress/vms.py`](py/fortress/vms.py)

VM registry plus QEMU and VirtualBox lifecycle: models `VMCreateRequest`…`VMProbeRequest`; `create_vm`, `update_vm`, `delete_vm` (`purge`, `force`), `start_vm`, `stop_vm`, `vm_status`, snapshot create/restore/delete/list, `provision_vm`, `probe_vm`; provider internals `_start_qemu_vm`, `_build_qemu_network`, `_create_virtualbox_vm`, etc. Default disk dir `/var/lib/fortress/vms`.

- **Depends on:** [`py/fortress/remote.py`](py/fortress/remote.py). **Tests:** none focused (gap).

### [`py/fortress/remote.py`](py/fortress/remote.py)

SSH execution shared by hosts and VMs: `SSHConfig`, `build_ssh_command` (`StrictHostKeyChecking=accept-new`), `run_ssh_script` (pipes script to `bash -s`, quotes env values, uses `sshpass` for passwords), `load_provision_script` (from [`scripts/provision/`](scripts/provision/)), `build_probe_script` (embedded Python probe; its inner `def run` is part of the script string, not a module function).

- **Common mistakes:** `sshpass -p` exposes the password in the process list — prefer key auth; don't add new password flows.

### [`py/fortress/__init__.py`](py/fortress/__init__.py) and [`py/fortress/api/__init__.py`](py/fortress/api/__init__.py)

Package markers only.

### [`fortress-cli.py`](fortress-cli.py)

Standalone client. Stores credentials in `~/.fortress-cli/config.json` encrypted with a passphrase-protected 4096-bit RSA keypair; decrypts backups locally.

- **Key functions and subparts:** `setup_command` (keys, server URL, TLS mode/CA bundle), `CredentialContext.get_secret`, `FortressClient.request` / `stream_download` (`FORTRESS_API_KEY` / `FORTRESS_USER_TOKEN` env override stored secrets), `get_fernet_key` (must match server), `build_parser` (subcommands: `setup`, `info`, `call`, `status`, `api-users`, `backup`, `recipes`, `firewall`, `sites`, `migrations`, `system upgrade|update-reload`, `tls renew`, `terminal open|read|write|resize|close`, `vms`, `hosts`), per-group `*_command` handlers.
- **Tests:** [`tests/test_cli_crypto.py`](tests/test_cli_crypto.py), [`tests/test_cli_terminal.py`](tests/test_cli_terminal.py).
- **Common mistakes:** a new API route needs a CLI handler *and* parser entry; container lifecycle, routing, packages, and monitoring are only reachable via `call`.

### [`ui/server.js`](ui/server.js)

Lizard UI Express server: static assets, admin auth (PBKDF2-SHA256 passwords, lockout, audit log, TOTP), delegated-token sessions, app-graph API, and a thin proxy to the Fortress API.

- **Key functions and subparts:** `loadEnvFileSync` (reads `ui/.env.local` or `FORTRESS_UI_ENV_FILE`), config constants (`FORTRESS_UI_*`, `FORTRESS_API_URL`, `FORTRESS_DEBUG`), `/api` admin guard middleware + `ensureAdminAuthorized`, admin store `loadAdminStore`/`saveAdminStore`/`logAdminEvent`, `passwordPolicyErrors`, `hashPassword`/`verifyPassword`, TOTP (`generateTotpSecret`, `verifyTotp`), sessions (`createSession`, `getSessionToken`, `createAdminSession`), `parseTypedToken`, `fortressRequest` / `fortressRequestFor`, `detectApiIdentity`, app graph (`loadModules`, `buildAppGraph`, `resolveContainerStack`), `/api/*` proxy routes, SPA fallback `app.get("*")`.
- **Tests:** [`ui/tests/`](ui/tests/) (spawns this server).
- **Common mistakes:** every `req.params.*` interpolated into an upstream path MUST be wrapped in `encodeURIComponent` (guarded by [`ui/tests/proxy_path_encoding.test.js`](ui/tests/proxy_path_encoding.test.js)). Sessions are in-memory `Map`s; restart logs everyone out.

### [`ui/public/js/app.js`](ui/public/js/app.js)

Single-file browser app (vanilla JS): app-deck rendering, wizards, previews per app, terminal (xterm.js, polling), debug panel, fast-actions menu.

- **Key functions and subparts:** `apiRequest` (all calls go to the UI server `/api/*`), `loadGraph`, `renderAll`/`renderGrid`/`renderCard`/`renderMoreInfoPanel`/`renderAppHome`, `renderWizard` + `WIZARD_STEP_COUNTS`/`WIZARD_MODE_LABELS`, `render*Preview` per app (routing, recipes, settings, packages, monitoring, firewall, VMs, sites, hosts, terminal), `loadPopularImages`/`renderImageCatalog`, `renderDebugPanel`, fast actions (`FAST_ACTION_OPTIONS`, `FAST_ACTION_STORAGE_KEY` in localStorage), `RECIPE_CATALOG`, `TERMINAL_POLL_INTERVAL_MS`.
- **Tests:** Puppeteer suites in [`ui/tests/`](ui/tests/).
- **Common mistakes:** never store tokens in `localStorage`; only UI preferences go there. Bridge/card animation geometry is guarded by visual hashes — rerun the visual tests after CSS/layout edits.

### [`ui/public/css/app.css`](ui/public/css/app.css) and [`ui/public/index.html`](ui/public/index.html)

Styles (dark-surface tokens, unibody card/bridge geometry, wizard slide stage) and the SPA shell that loads xterm from `/vendor/xterm/*` (served from `node_modules`). Guarded by [`ui/tests/css_dark_surface_token_regression.test.js`](ui/tests/css_dark_surface_token_regression.test.js) and [`ui/tests/wizard_css_transform_guard.test.js`](ui/tests/wizard_css_transform_guard.test.js).

### [`ui/apps/`](ui/apps/)

One directory per UI app, each containing only an `app.json` manifest (`id`, `title`, `description`, `icon`, `order`, optional `root`, `scope: "container"`, `template`, `actions`, `parent`). Top-level apps: `home` (root), `containers`, `routing`, `recipes`, `packages`, `firewall`, `monitoring`, `sites`, `hosts`, `vms`, `terminal`, `settings`. Container-scoped sub-apps: `container-*` (overview, handle, access, network, packages, recipes, backups, terminal, and `container-lamp*` which appear only for LAMP-tagged containers). Behavior for an app lives in `app.js`, not in the manifest. The manifest schema is undocumented beyond existing files (roadmap item).

### [`ui/package.json`](ui/package.json), [`ui/package-lock.json`](ui/package-lock.json), [`ui/run.sh`](ui/run.sh)

Node ESM package `fortress-lizard-ui`: deps `express`, `undici`, `web-streams-polyfill`, `xterm`; dev dep `puppeteer`. Scripts `npm start` (`node server.js`) and `npm test` (`node --test`). `run.sh` sources `.env.local` then runs `npm start`.

### [`run-server.sh`](run-server.sh)

Host bootstrap and launcher (~1.5k lines bash). Detects apt/dnf/yum, installs missing OS packages every run, creates `.venv`, installs LXD (snap on AlmaLinux), runs `lxd init --auto` and heals the default profile root disk, writes `/etc/fortress/fortress.env`, optionally hardens SSH, opens firewall ports for non-loopback binds, offers relocation to `/opt/linus-fortress` for systemd, and starts API (+ optional UI) in foreground, `screen`, or systemd mode. Flags: `--mode`, `--foreground`, `--screen`, `--service`, `--skip-ui`, `--enable-ui`, `--debug-enable`, `--debug-disable`, `--configure`, `--reset`. **Mutates the host; requires root.**

### [`restart.sh`](restart.sh)

Restarts API/UI in `auto|service|screen|process` mode, optionally `git pull` first (`--no-pull` to skip), with `--env` and `--dry-run`. Invoked by `/system/update-reload`. Logs to `.restart-api.log`/`.restart-ui.log`.

### [`run-client.sh`](run-client.sh)

Interactive client bootstrap: runs `fortress-cli setup`, TLS pinning (`--pin-cert` → `~/.fortress-cli/api-ca.pem`, `--ca-bundle`, `--insecure`), token issuance (`--issue-token`), key reset, and `--webui` to write `ui/.env.local` and optionally bootstrap a local UI admin.

### [`scripts/setup-service-user.sh`](scripts/setup-service-user.sh) and [`scripts/fortress-sudoers.template`](scripts/fortress-sudoers.template)

Create a non-root service user and install the sudoers entry allowing only `run-server.sh` and `systemctl start|stop|restart|status fortress[-ui]`. Keep the template minimal; adding commands widens privilege.

### [`scripts/provision/`](scripts/provision/)

`provision_ubuntu.sh` and `provision_fedora.sh` — scripts piped over SSH by `load_provision_script(profile)` for host/VM provisioning. The profile name selects `provision_<profile>.sh`.

### [`schemas/`](schemas/)

One JSON file per migration-managed store (`api_users`, `container_images`, `hosts`, `monitoring_history`, `recipe_health_history`, `recipes`, `routes`, `sites`, `vms`): `store`, `schema_version`, `record_type` (`mapping`/`list`/object), `fields`, `defaults`, `aliases`, `prune_unknown`. Loaded from `FORTRESS_SCHEMA_DIR` (default repo `schemas/`).

### [`api-v1.yaml`](api-v1.yaml)

OpenAPI 3.0.3 description of the HTTP API. Update it with every route change.

### [`requirements.txt`](requirements.txt)

Unpinned Python deps: `fastapi`, `uvicorn[standard]`, `pydantic`, `cryptography`, `python-multipart`, `requests`.

### [`tests/test_permissions_matrix.py`](tests/test_permissions_matrix.py)

Route-level integration tests: loads `server.py` with `importlib` into a temp dir, rewires store paths, and drives FastAPI `TestClient` sequences across recipes, system upgrade/update-reload, routing, sites, firewall, and terminal with allowed/denied tokens. The reference pattern for new route tests.

### [`tests/test_auth_audit.py`](tests/test_auth_audit.py)

Container scope enforcement and `CommandLogger` / exec audit redaction.

### [`tests/test_container_images.py`](tests/test_container_images.py)

Image discovery against mocked `lxc` JSON (incl. old-CLI `--limit` retry, Fedora remote shapes), public simplestream fallback, create-container storage-pool/root-disk handling, disk limits, and popular-image endpoints.

### [`tests/test_recipes.py`](tests/test_recipes.py)

Recipe name validation, dependency resolution/cycles, template rendering, LAMP health targets, semver/history lifecycle, bundle signing and key rotation.

### [`tests/test_routing.py`](tests/test_routing.py), [`tests/test_firewall.py`](tests/test_firewall.py), [`tests/test_migrations.py`](tests/test_migrations.py), [`tests/test_sites.py`](tests/test_sites.py), [`tests/test_terminal.py`](tests/test_terminal.py)

Focused unit tests for nginx config rendering + domain conflicts; ufw/firewalld parsing + conn-limit iptables/nft ordering; record migration + engine plan/apply/rollback; site model validation + record helpers; terminal shell/username normalization.

### [`tests/test_cli_crypto.py`](tests/test_cli_crypto.py) and [`tests/test_cli_terminal.py`](tests/test_cli_terminal.py)

CLI secret encrypt/decrypt round-trip and terminal subcommand payload/validation (loads `fortress-cli.py` as a module).

### [`tests/scripts/agent-viewport.js`](tests/scripts/agent-viewport.js) and [`tests/scripts/agent-viewport.md`](tests/scripts/agent-viewport.md)

Standalone Puppeteer helper library (and its design doc) that snapshots visible viewport elements as JSON/text/overlay HTML for agent-driven UI inspection. Not imported by any test suite.

### [`ui/tests/`](ui/tests/)

`node:test` suites that spawn `ui/server.js` against a stub API. Puppeteer-based files skip themselves when Puppeteer/Chromium is unavailable.

- [`admin_bootstrap.test.js`](ui/tests/admin_bootstrap.test.js) — first-admin bootstrap and admin gate.
- [`api_identity_hint.test.js`](ui/tests/api_identity_hint.test.js) — API identity detection hints.
- [`local_ui_remote_api.test.js`](ui/tests/local_ui_remote_api.test.js) — local UI proxying to a remote API.
- [`ui_token_bootstrap_overlay.test.js`](ui/tests/ui_token_bootstrap_overlay.test.js) — token entry overlay (Puppeteer).
- [`app_home_leaf_render.test.js`](ui/tests/app_home_leaf_render.test.js), [`preview_meta_inheritance.test.js`](ui/tests/preview_meta_inheritance.test.js) — stage/app-home rendering (Puppeteer).
- [`app_bridge_wizard_reload.test.js`](ui/tests/app_bridge_wizard_reload.test.js) — card bridge open/close, wizard flow, update-reload browser reload (Puppeteer).
- [`app_home_visual_regression.test.js`](ui/tests/app_home_visual_regression.test.js), [`css_dark_surface_token_regression.test.js`](ui/tests/css_dark_surface_token_regression.test.js) — screenshot/CSS hash baselines in [`fixtures/`](ui/tests/fixtures/).
- [`wizard_css_transform_guard.test.js`](ui/tests/wizard_css_transform_guard.test.js) — static CSS guard for wizard transforms.
- [`proxy_path_encoding.test.js`](ui/tests/proxy_path_encoding.test.js) — proxied path params are URI-encoded upstream.

### [`dev_samples/`](dev_samples/)

Reference material only: `lizardim-main/` (legacy Lizardim PHP/jQuery UI, ~1.4k vendored files) and `sh/almalinux-ssh-and-lxd.md` (manual AlmaLinux SSH/LXD notes automated by `run-server.sh`). Do not edit, lint, or ship.

### [`docs/notes/`](docs/notes/)

`venv-cmd.md` (the unit-test command) and `proceed.md` (a reusable "continue the roadmap" prompt). Historical; not authoritative.

## Features and Recurring Development Pitfalls

### Delegated tokens and permissions — Shipped

- **Behavior:** `/api-users` CRUD issues 64-hex tokens with permission lists, optional `allowed_containers`, and per-target terminal policies.
- **Flow and owners:** route → `authorize` ([`py/server.py`](py/server.py)) → `verify_token` ([`py/fortress/auth.py`](py/fortress/auth.py)) → `api_users.json`.
- **Constraints:** permission names are listed in [README Authentication](README.md#authentication); adding one requires README + `api-v1.yaml` updates.
- **Tests and gaps:** permission matrix; no token expiry, no hashed storage, no 401/403 split.

### Container lifecycle, access, and connectivity — Shipped

- **Behavior:** create/delete/start/stop/restart, snapshots, exec, logs, service probes, user/group management, external port access, container↔container TCP links, shared mounts, bulk `/containers/expose`.
- **Flow and owners:** [`py/fortress/api/containers.py`](py/fortress/api/containers.py) → [`py/fortress/containers.py`](py/fortress/containers.py) → `lxc`.
- **Tests and gaps:** image/create paths tested; lifecycle/exec/connectivity routes untested.

### Domain routing and TLS — Shipped

- **Behavior:** nginx reverse proxy per domain with aliases/wildcards, conflict detection, manual or Let's Encrypt TLS (HTTP-01), `/routing/refresh` to re-resolve container IPs, `/tls/renew`.
- **Flow and owners:** `add_domain_routing` ([`py/server.py`](py/server.py)) → [`py/fortress/routing.py`](py/fortress/routing.py) + [`py/fortress/tls.py`](py/fortress/tls.py) → `/etc/nginx`, `routes.json`.
- **Tests and gaps:** [`tests/test_routing.py`](tests/test_routing.py), matrix; no scheduled renewals, no DNS-01/wildcard certs, IP drift needs a manual refresh.

### Recipes (install blueprints) — Shipped

- **Behavior:** CRUD, seed (`lamp`), plan, apply (host or container, `dry_run`), versioned history, signed export/import, LAMP post-apply health checks, persisted health history with trends.
- **Flow and owners:** recipe routes ([`py/server.py`](py/server.py)) → [`py/fortress/recipes.py`](py/fortress/recipes.py) → package manager + `bash -lc` commands (in container via `lxc exec`).
- **Tests and gaps:** [`tests/test_recipes.py`](tests/test_recipes.py), matrix; no key identifiers in bundles, no trend alerts.

### Sites (PHP website lifecycle) — Shipped

- **Behavior:** site records bound to a container/docroot/runtime/DB/TLS/routing; deploy from archive, backup/rollback (files + DB dump), logs, health, service restart, php.ini overrides, PHP-FPM pool tuning, TLS status.
- **Flow and owners:** site routes + helpers in [`py/server.py`](py/server.py) → models in [`py/fortress/sites.py`](py/fortress/sites.py) → `lxc exec`, routing helpers.
- **Tests and gaps:** [`tests/test_sites.py`](tests/test_sites.py), matrix; no TLS renewal failure history.

### Firewall and anti-DDoS — Shipped

- **Behavior:** open/close, status, rule inventory, diff, merge/replace apply with rollback IDs, rollback, DDoS policy with conn-limit caps and allowlists.
- **Flow and owners:** firewall routes ([`py/server.py`](py/server.py)) → [`py/fortress/firewall.py`](py/fortress/firewall.py) → `ufw`/`firewall-cmd`, `iptables`/`nft`.
- **Tests and gaps:** [`tests/test_firewall.py`](tests/test_firewall.py), matrix; conn-limit diagnostics not exposed.

### Monitoring — Shipped

- **Behavior:** `/monitoring/resources` returns host + container metrics, threshold alerts, and rate anomalies against a persisted baseline.
- **Owners:** [`py/fortress/monitoring.py`](py/fortress/monitoring.py). **Gaps:** no focused tests; no alert delivery (webhooks).

### Encrypted backups and restore — Shipped

- **Behavior:** background `lxc export` + Fernet encryption; container-scoped list/download (`FileResponse`, filename pattern validated); restore by streamed upload into a per-request staging dir + `lxc import`.
- **Owners:** backup section of [`py/server.py`](py/server.py); decryption in [`fortress-cli.py`](fortress-cli.py) `backup decrypt`.
- **Tests:** [`tests/test_backups.py`](tests/test_backups.py). **Gaps:** decrypt/encrypt are in-memory (Fernet format is a compatibility contract); legacy archive names not matching the pattern are only visible to unscoped tokens.

### Migrations, system upgrade, update-reload — Shipped

- **Behavior:** migration status/plan/apply/rollback/ledger; `/system/upgrade` (packages + migrations, `dry_run` preflight; needs `migration_admin` + `package_manage`); `/system/update-reload` (git pull + migrations + restart).
- **Owners:** [`py/fortress/migrations.py`](py/fortress/migrations.py), [`py/server.py`](py/server.py), [`restart.sh`](restart.sh). **Tests:** [`tests/test_migrations.py`](tests/test_migrations.py), matrix.

### Terminal sessions — Shipped

- **Behavior:** PTY host/container shells over polling HTTP (`/terminal/sessions*`), used by Lizard UI (xterm.js) and `fortress-cli terminal`.
- **Owners:** policy in [`py/server.py`](py/server.py), mechanics in [`py/fortress/terminal.py`](py/fortress/terminal.py). **Gaps:** no recording/replay, no WebSocket, single-process only.

### SSH hosts and test VMs — Shipped

- **Behavior:** registries with provision/probe/saved states; VMs add QEMU/VirtualBox start/stop/status/snapshots.
- **Owners:** [`py/fortress/hosts.py`](py/fortress/hosts.py), [`py/fortress/vms.py`](py/fortress/vms.py), [`py/fortress/remote.py`](py/fortress/remote.py), [`scripts/provision/`](scripts/provision/). **Gaps:** no focused tests.

### Lizard UI — Shipped (several sub-apps Experimental/scaffold)

- **Behavior:** admin login (password policy, lockout, audit, optional TOTP), token sessions, app deck with wizards, image catalog, Settings (upgrade/update-reload, fast actions), Terminal apps, LAMP sub-apps for tagged containers (`user.lizard.stack=lamp`).
- **Owners:** [`ui/server.js`](ui/server.js), [`ui/public/js/app.js`](ui/public/js/app.js), [`ui/apps/`](ui/apps/).
- **Tests and gaps:** [`ui/tests/`](ui/tests/); container sub-apps (Access, Network, Packages, Recipes, Backups) are not fully wired; manifest schema undocumented.

### Pitfall: forgetting container scope on a new route

- **Symptom / wrong assumption:** "the permission check is enough." A token limited to `web01` can then act on `db01`.
- **Cause and invariant:** scope is a separate check; `authorize(..., containers=...)` or `enforce_container_scope` is mandatory wherever a container name arrives in the path, body, query, *or a stored record* (e.g. `remove_domain_routing` checks the route's stored `container_name`).
- **Risk area:** any new route in [`py/server.py`](py/server.py) / [`py/fortress/api/containers.py`](py/fortress/api/containers.py).
- **Safe pattern / regression check:** add an out-of-scope token case to [`tests/test_permissions_matrix.py`](tests/test_permissions_matrix.py).
- **Status:** recurring regression risk.

### Pitfall: adding a JSON store without schema registration

- **Symptom:** migrations report the store as unknown, upgrades never transform it.
- **Cause and invariant:** each store needs an entry in `MIGRATION_ENGINE` (server.py) *and* `schemas/<store>.json`.
- **Safe pattern / regression check:** add both plus a case in [`tests/test_migrations.py`](tests/test_migrations.py).
- **Status:** recurring regression risk (firewall state and UI admin store are still unregistered).

### Pitfall: partial host mutation without rollback

- **Symptom:** nginx, LXD devices, or firewall left half-configured after an error.
- **Cause and invariant:** mutate → verify → persist record; on failure restore the previous state before re-raising, and persist JSON only after the host change succeeded (as `add_domain_routing` does).
- **Safe pattern:** reuse `_apply_nginx_config`, `expose_ports`, and the `/containers/expose` firewall rollback loop.
- **Status:** fixed in `apply_firewall_rules`; regression risk elsewhere.

### Pitfall: tests touching the real host

- **Symptom:** tests fail on macOS/CI or modify `/var/lib/fortress`.
- **Cause and invariant:** server.py constants default to system paths and `run_command` executes real binaries. Tests MUST set `FORTRESS_LOG_PATH` / `FORTRESS_COMMAND_LOG_DB` before import, rewire module path globals after import, and `mock.patch` `run_command`/`subprocess`.
- **Safe pattern:** copy `setUp` from [`tests/test_permissions_matrix.py`](tests/test_permissions_matrix.py).
- **Status:** regression risk.

### Pitfall: drifting duplicated definitions

- **Symptom:** UI shows recipes/services the API doesn't seed (or vice versa); docs list routes that don't exist.
- **Cause:** LAMP recipe definitions exist in server.py (`LAMP_RECIPE_BUNDLE`), recipes.py (`LAMP_STACK_EXPANSION`), and app.js (`RECIPE_CATALOG`, `FILEMANAGER_COMMAND`); routes are described in code, README, and `api-v1.yaml`.
- **Safe pattern:** change all copies in one commit; diff route registries against `api-v1.yaml` (command in [Validation](#build-run-debug-and-release)).
- **Status:** route drift is caught by `tests/test_api_spec.py`; LAMP definitions remain duplicated.

## Interface Ownership Map

- **HTTP API (authoritative registry: `@app.*` decorators in [`py/server.py`](py/server.py) and `@router.*` in [`py/fortress/api/containers.py`](py/fortress/api/containers.py)):**
  - [`py/fortress/api/containers.py`](py/fortress/api/containers.py): `/container/create`, `DELETE /container/{name}`, `/containers/images/popular[/remove]`, `/access/external/{open,close}`, `/container/users/{create,password,groups}`, `DELETE /container/users`, `/container/groups`, `/containers/connect/tcp[/remove]`, `/containers/connect/share[/remove]`, `/containers/expose`, `/containers/probe`, `/containers/{start,stop,restart}`, `/containers/snapshot`, `/containers/snapshots/restore`, `GET /containers/{name}/snapshots`, `DELETE /containers/{name}/snapshots/{snapshot_name}`, `/containers/exec`, `GET /containers/{name}/logs`.
  - [`py/server.py`](py/server.py): `/status`, `/monitoring/resources`, `/routing`, `/routing/add`, `/routing/refresh`, `DELETE /routing/{domain}`, `/tls/renew`, `/api-users[/{token}]`, `/terminal/sessions[/{id}[/output|/input|/resize]]`, `/firewall/{open,close,status,rules,rules/apply,rules/diff,rollback,ddos}`, `/packages/{install,remove,update}`, `/system/upgrade`, `/system/update-reload`, `/vms*`, `/hosts*`, `/recipes`, `/recipes/{name}`, `/recipes/{seed,export,import,apply,plan,health-history}`, `/sites`, `/sites/{site_id}[/tls/status|/backups|/deploy|/backup|/rollback|/logs|/health|/services/restart]`, `/migrations/{status,plan,apply,rollback,ledger}`, `/backup/{container_name}`, `/backup/list`, `/backup/download/{filename}`, `/restore`.
  - Contract document: [`api-v1.yaml`](api-v1.yaml); request bodies and permissions: [README API Reference](README.md#api-reference).
- **CLI:** `build_parser` in [`fortress-cli.py`](fortress-cli.py) is the command registry.
- **Lizard UI HTTP (`/api/*`):** route registrations in [`ui/server.js`](ui/server.js) — `/api/admin/*` (UI-local admin), `/api/session`, `/api/health`, `/api/apps` (app graph), and proxies mirroring Fortress routes.
- **UI screens:** manifests in [`ui/apps/*/app.json`](ui/apps/); renderers `render*Preview`/`renderWizard` in [`ui/public/js/app.js`](ui/public/js/app.js).
- **Operator scripts:** [`run-server.sh`](run-server.sh), [`restart.sh`](restart.sh), [`run-client.sh`](run-client.sh), [`scripts/setup-service-user.sh`](scripts/setup-service-user.sh).

## Build, Run, Debug, and Release

Prerequisites: Linux host with `apt` or `dnf`/`yum`, LXD (`lxc`), nginx, ufw or firewalld, certbot, Python 3 with `venv`; Node.js + npm for the UI. Development of pure modules and tests works on macOS.

Python environment and tests (no root, no host mutation):

```bash
python3 -m venv .venv
```

```bash
.venv/bin/pip install -r requirements.txt
```

```bash
.venv/bin/python -m unittest discover -s tests
```

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_permissions_matrix.py'
```

UI (from `ui/`; Puppeteer suites download Chromium on install and self-skip if unavailable):

```bash
cd ui && npm install && npm test
```

```bash
cd ui && UPDATE_VISUAL_BASELINES=1 npm test
```

Run the API on a server host (**root, mutates the host**, installs packages, writes `/etc/fortress/fortress.env`):

```bash
sudo ./run-server.sh --configure
```

```bash
sudo ./restart.sh --mode auto --no-pull
```

Run Lizard UI locally against a remote API (writes `ui/.env.local`; contacts the remote server):

```bash
./run-client.sh --server <host> --webui
```

```bash
cd ui && npm start
```

Debug/inspect: API log `FORTRESS_LOG_PATH` (default `/var/log/fortress.log`, falls back to stderr); audit register `sqlite3 /var/lib/fortress/command_log.db 'select * from command_log order by id desc limit 20;'`; update-reload output in `.update-reload.log`; UI debug responses gated by `FORTRESS_DEBUG` (default on; toggled by `run-server.sh --debug-enable|--debug-disable`).

Validation helpers for docs (run from repo root):

```bash
diff <(grep -hoE '@(app|router)\.(get|post|put|delete)\("[^"]+"' py/server.py py/fortress/api/containers.py | sed -E 's/.*\("//; s/"$//' | sort -u) <(grep -E '^  /' api-v1.yaml | sed 's/:$//; s/^ *//' | sort -u)
```

```bash
git diff --check
```

Release: there is no packaging, versioning, or CI. Servers update via `git pull` (`/system/update-reload` or `restart.sh`), followed by `POST /migrations/apply` when schemas change.

## Test Ownership Map

- Auth, scope, audit redaction → [`tests/test_auth_audit.py`](tests/test_auth_audit.py)
- Route permissions, scope on recipes/routing/sites/firewall/terminal/system → [`tests/test_permissions_matrix.py`](tests/test_permissions_matrix.py)
- Container images and create → [`tests/test_container_images.py`](tests/test_container_images.py)
- Recipes (resolution, templating, versioning, bundles, LAMP targets) → [`tests/test_recipes.py`](tests/test_recipes.py)
- Routing configs and conflicts → [`tests/test_routing.py`](tests/test_routing.py)
- Firewall parsing and conn-limit ordering → [`tests/test_firewall.py`](tests/test_firewall.py)
- Migrations → [`tests/test_migrations.py`](tests/test_migrations.py)
- Site models → [`tests/test_sites.py`](tests/test_sites.py)
- Terminal helpers → [`tests/test_terminal.py`](tests/test_terminal.py)
- CLI crypto and terminal commands → [`tests/test_cli_crypto.py`](tests/test_cli_crypto.py), [`tests/test_cli_terminal.py`](tests/test_cli_terminal.py)
- UI admin gate, proxying, rendering, visuals → [`ui/tests/`](ui/tests/)
- Backup/restore routes and `/status` scoping → [`tests/test_backups.py`](tests/test_backups.py)
- JSON storage atomicity/locking → [`tests/test_storage.py`](tests/test_storage.py)
- Route registry ↔ `api-v1.yaml` parity and `$ref` resolution → [`tests/test_api_spec.py`](tests/test_api_spec.py)
- **Known test gaps:** `fortress.monitoring`, `fortress.tls`, `fortress.hosts`, `fortress.vms`, `fortress.remote`; container lifecycle/exec/connectivity routes; invalid/expired token and 401-vs-403 cases; no test runs against a real LXD daemon.

## Data, Security, Privacy, and Compatibility Boundaries

- **Canonical data:** JSON stores and SQLite audit DB under `/var/lib/fortress`, nginx files, LXD state. `schemas/` defines shape; it is not data. Monitoring history and recipe health history are derived/trimmed.
- **Secrets:** `FORTRESS_API_KEY`, `FORTRESS_BACKUP_PASSWORD`, `FORTRESS_RECIPE_BUNDLE_SIGNING_KEY(S)` come from env (`/etc/fortress/fortress.env`). Delegated tokens, SSH passwords, and site DB passwords are stored in plaintext JSON on the API host and MUST be redacted in every response (`sanitize_host_record`, `sanitize_vm_record`, `sanitize_site_record`, `mask_token`) and audit entry.
- **CLI secrets:** RSA-encrypted under `~/.fortress-cli`; never print them except via explicit `--show-passphrase`.
- **UI:** admin passwords hashed with PBKDF2-SHA256 (200k iterations, per-user salt); tokens kept server-side only; `FORTRESS_UI_COOKIE_SECURE=1` when served over HTTPS.
- **Trust levels:** containers, remote hosts, uploaded archives/backups, and imported recipe bundles are untrusted. Validate names with the module regexes (`HOST_NAME_PATTERN`, `VM_NAME_PATTERN`, `SITE_NAME_PATTERN`, `RECIPE_NAME_PATTERN`, `validate_domain`, `validate_port`) before they reach commands or paths.
- **Compatibility:** stored JSON shapes evolve only through `schemas/` + migrations (aliases for renames). Backup encryption (`get_fernet_key`) and bundle digest format are compatibility contracts. The API has no versioned prefix; route removals break the CLI and UI.
- **Backup/restore:** backups are only as safe as `FORTRESS_BACKUP_PASSWORD`; the default placeholder string is insecure and must be overridden.

## Current Status and Known Gaps

### Shipped

- All features listed under [Features](#features-and-recurring-development-pitfalls) marked Shipped, verified against route registrations and modules at this revision.

### Experimental / Scaffold

- Lizard UI container sub-apps (Access, Network, Packages, Recipes, Backups) — partially wired.
- `run-server.sh` SSH hardening and relocation prompts — interactive, untested.
- [`tests/scripts/agent-viewport.js`](tests/scripts/agent-viewport.js) — helper library, not wired into any suite.

### Known Gaps

- **Restore/backup memory:** Fernet encrypt/decrypt holds the whole archive in memory (cap uploads with `FORTRESS_RESTORE_MAX_BYTES`); a streamable format would need a new versioned backup format.
- **Auth:** all auth failures are 403; no token expiry; tokens stored unhashed.
- **Concurrency:** most server.py writers still do unlocked `load_json` → `save_json` (atomic, but last writer wins); migrate hot stores to `update_json`. Terminal sessions and UI sessions are in-process memory.
- **Visual baselines:** `app_home_visual_regression` and `css_dark_surface_token_regression` hashes are environment-sensitive (they fail on macOS Chromium at this revision without code changes).
- **Dependencies:** `requirements.txt` is unpinned (a fresh AlmaLinux 10 install pulled FastAPI 0.162 / Starlette 1.10 vs 0.128 / 0.49 on the dev venv — newer FastAPI no longer flattens included routers into `app.routes`, so enumerate routes via `app.openapi()`); code uses Pydantic v1-style `.dict()`.
- **No CI** and no real-LXD integration test lane.

### Near-Term Priorities

Detailed sequencing lives in [`ROADMAP.md`](ROADMAP.md). Highest-leverage next steps:

1. Close the remaining Known Gaps above (tracked in ROADMAP Path 11).
2. Path 4: token-expiry/invalid-token and 401-vs-403 integration cases.
3. Path 7 / production checklist: scheduled certbot renewals with failure alerts; automatic upstream refresh on container IP change.
4. Path 10.5: register remaining JSON stores (firewall state) in schemas/migrations.

## Task Start and Handoff Checklist

1. Read this file fully; run `git status` and preserve unrelated changes.
2. Locate the owning file subsection and its tests above; read the relevant README endpoint section and ROADMAP Path.
3. Verify any claim here against the code before relying on it; fix this file if it is wrong.
4. For route work: `authorize` with the narrowest permission, container scope, `audit_api` on success and error, sanitized details, rollback on partial failure.
5. For persisted-shape work: update `schemas/` + `MIGRATION_ENGINE` + migration tests.
6. Add focused tests that mock host commands; run `.venv/bin/python -m unittest discover -s tests` (and `cd ui && npm test` for UI changes). Report what was not run.
7. Update this file, `README.md`, `api-v1.yaml`, and `ROADMAP.md` (`Done:`/`Next:`) in the same change; run the route-diff helper and `git diff --check`.
