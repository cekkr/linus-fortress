This file contains the directives for AIs and must be kept current with the minimum information needed to understand the project quickly and avoid repeated study. Keep README.md and ROADMAP.md aligned when this file changes. When implementing or planning new features, append any related next steps or not-yet-implemented parts to ROADMAP.md.

## Project status
- py/server.py contains the main central server with APIs and now includes the containers router
- `py/fortress/auth.py` centralizes master key resolution, delegated token verification, and container scope enforcement
- `py/fortress/storage.py` centralizes JSON store helpers for API users, recipes, hosts, VMs, sites, and monitoring history
- py/fortress/monitoring.py centralizes host/container resource snapshots with alert thresholds
- Container lifecycle/access/connectivity APIs are implemented in `py/fortress/api/containers.py` with LXC helpers in `py/fortress/containers.py`
- `py/fortress/routing.py` centralizes nginx routing config rendering, domain validation, TLS path checks, ACME challenge support, conflict detection, and reload/testing helpers for HTTP(S) host routing
- `py/fortress/tls.py` handles certbot-backed Let's Encrypt issuance/renewal for HTTP-01 challenges
- Routing entries support multi-domain server names (including wildcard domains), conflict detection, and can be refreshed via `POST /routing/refresh` to update upstream IPs
- Routing entries persist in `/var/lib/fortress/routes.json` and generate nginx vhosts under `/etc/nginx/sites-available` (symlinked into `sites-enabled`)
- `py/fortress/system.py` owns the shared `run_command` helper used by server and container management
- py/server.py also manages host/container package operations (apt/dnf/yum), firewall rules (ufw + firewalld), site lifecycle APIs (including php.ini overrides), TLS automation, system upgrades, and migrations
- `/monitoring/resources` exposes structured host+container metrics plus alert flags for automation against anomalous usage/malware-like spikes
- Security posture assumes strong adversaries; prefer least privilege, audit trails, and rollback on failure
- Master API key is optional (set via `FORTRESS_API_KEY`/`API_SECRET_KEY`) and should be disabled after bootstrap; delegated tokens are preferred long-term
- New recipe automation endpoints (`/recipes`, `/recipes/{name}`, `/recipes/apply`, `/recipes/seed`, `/recipes/plan`) allow "nix-like" install blueprints with dependencies, packages, and commands (templated with `{{param}}`), stored in `/var/lib/fortress/recipes.json`
- LAMP recipe bundle supports PHP version selection and optional DB bootstrap parameters (`db_root_password`, `db_name`, `db_user`, `db_password`)
- A new fortress.audit module powers the SQLite-based command register that captures all API activity plus container exec behaviour for investigation
- `py/fortress/recipes.py` holds recipe models, dependency resolution, and template rendering
- `py/fortress/migrations.py` manages schema-registry migrations with plan/apply/rollback and a patch ledger
- `py/fortress/sites.py` centralizes website models and JSON store helpers for site lifecycle APIs
- `py/fortress/hosts.py` tracks SSH-managed host records for provisioning/probing on non-VM machines; shared SSH/script helpers are in `py/fortress/remote.py`
- fortress-cli.py now includes `recipes list|create|apply|plan|seed`, `firewall *`, `sites *`, `migrations *`, `system upgrade`, and `tls renew` helpers in addition to status/api-users/package/backup calls
- Unit tests in `tests/test_recipes.py`, `tests/test_routing.py`, `tests/test_firewall.py`, `tests/test_migrations.py`, and `tests/test_sites.py` cover recipes, routing, firewall parsing, migrations, and site model validation
- `py/fortress/vms.py` centralizes VM registry + QEMU/VirtualBox lifecycle, snapshots, and SSH probe/provision helpers; provisioning scripts live in `scripts/provision`
- api-v1.yaml documents the HTTP contract (OpenAPI 3.0.3) and README.md lists request bodies/permissions for each endpoint
- Domain routing and LXD proxy helpers now support choosing container interfaces and host listen ports/addresses for finer TCP/IP exposure control between containers and the host
- Lizard UI supports admin login sessions (bootstrap + optional TOTP MFA) plus server-side delegated-token sessions (no tokens stored in the browser)
- `POST /containers/expose` supports bulk interface/port exposure to a container with port ranges, protocol selection, per-interface upstream selection, and optional firewall allowlists (rolls back devices and firewall rules on failure)
- `run-server.sh` now ensures missing OS packages on subsequent runs, supports AlmaLinux snap-based LXD installs, and can optionally harden SSH by creating a sudo user and disabling root login

## Project structure (tree)
```
.
|-- AGENTS.md
|-- LICENSE
|-- README.md
|-- ROADMAP.md
|-- api-v1.yaml
|-- docs
|   `-- notes
|       `-- venv-cmd.md
|-- fortress-cli.py
|-- py
|   |-- server.py
|   `-- fortress
|       |-- __init__.py
|       |-- auth.py
|       |-- audit.py
|       |-- containers.py
|       |-- migrations.py
|       |-- routing.py
|       |-- tls.py
|       |-- monitoring.py
|       |-- hosts.py
|       |-- remote.py
|       |-- vms.py
|       |-- recipes.py
|       |-- sites.py
|       |-- storage.py
|       |-- system.py
|       `-- api
|           |-- __init__.py
|           `-- containers.py
|-- schemas
|   |-- api_users.json
|   |-- hosts.json
|   |-- monitoring_history.json
|   |-- recipes.json
|   |-- routes.json
|   |-- sites.json
|   `-- vms.json
|-- requirements.txt
|-- scripts
|   |-- fortress-sudoers.template
|   |-- setup-service-user.sh
|   |-- provision
|   |   |-- provision_fedora.sh
|   |   `-- provision_ubuntu.sh
|   `-- vm
`-- tests
    |-- test_firewall.py
    |-- test_migrations.py
    |-- test_recipes.py
    |-- test_routing.py
    `-- test_sites.py
```

## HTTP API map (code ownership)
- `py/fortress/api/containers.py`: `/container/create`, `/container/{name}`, `/access/external/*`, `/container/users/*`, `/container/groups`, `/containers/connect/*`
- `py/server.py`: `/status`, `/monitoring/resources`, `/routing`, `/routing/add`, `/routing/{domain}`, `/tls/renew`, `/api-users*`, `/firewall/*`, `/packages/*`, `/system/upgrade`, `/recipes*`, `/sites*`, `/migrations*`, `/backup/*`, `/restore`
- `py/server.py`: `/vms*` (VM registry, start/stop/status, snapshots, SSH provisioning/probing)
- `py/server.py`: `/hosts*` (SSH-managed host registry, provisioning/probing, saved states)
- `api-v1.yaml`: canonical OpenAPI reference; README.md mirrors route summaries and permissions

## Roadmap for AI
- See ROADMAP.md for detailed development paths and sequencing (modularization, monitoring baselines, tests, recipe lifecycle).
