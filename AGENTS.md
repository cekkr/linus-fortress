This file contains the directives for AIs and must be kept current with the minimum information needed to understand the project quickly and avoid repeated study. Keep README.md and ROADMAP.md aligned when this file changes.

## Project status
- py/server.py contains the main central server with APIs and now includes the containers router
- py/fortress/monitoring.py centralizes host/container resource snapshots with alert thresholds
- Container lifecycle/access/connectivity APIs are implemented in `py/fortress/api/containers.py` with LXC helpers in `py/fortress/containers.py`
- `py/fortress/system.py` owns the shared `run_command` helper used by server and container management
- py/server.py also manages host/container package operations (apt + dnf) and firewall rules (ufw + firewalld)
- `/monitoring/resources` exposes structured host+container metrics plus alert flags for automation against anomalous usage/malware-like spikes
- Security posture assumes strong adversaries; prefer least privilege, audit trails, and rollback on failure
- Master API key is optional (set via `FORTRESS_API_KEY`/`API_SECRET_KEY`) and should be disabled after bootstrap; delegated tokens are preferred long-term
- New recipe automation endpoints (`/recipes`, `/recipes/{name}`, `/recipes/apply`) allow "nix-like" install blueprints with dependencies, packages, and commands (templated with `{{param}}`), stored in `/var/lib/fortress/recipes.json`
- A new fortress.audit module powers the SQLite-based command register that captures all API activity plus container exec behaviour for investigation
- `py/fortress/recipes.py` holds recipe models, storage helpers, dependency resolution, and template rendering
- `py/fortress/hosts.py` tracks SSH-managed host records for provisioning/probing on non-VM machines; shared SSH/script helpers are in `py/fortress/remote.py`
- fortress-cli.py now includes `recipes list|create|apply` helpers in addition to status/api-users/package/backup calls
- Unit tests in `tests/test_recipes.py` cover recipe dependency resolution and apply planning
- `py/fortress/vms.py` centralizes VM registry + QEMU/VirtualBox lifecycle, snapshots, and SSH probe/provision helpers; provisioning scripts live in `scripts/provision`
- api-v1.yaml documents the HTTP contract (OpenAPI 3.0.3) and README.md lists request bodies/permissions for each endpoint
- Domain routing and LXD proxy helpers now support choosing container interfaces, explicit upstream addresses, and host listen ports/addresses for finer TCP/IP exposure control between containers and the host
- `POST /containers/expose` supports bulk interface/port exposure to a container with port ranges, protocol selection, per-interface upstream selection, and optional firewall allowlists (rolls back devices and firewall rules on failure)

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
|       |-- audit.py
|       |-- containers.py
|       |-- monitoring.py
|       |-- hosts.py
|       |-- remote.py
|       |-- vms.py
|       |-- recipes.py
|       |-- system.py
|       `-- api
|           |-- __init__.py
|           `-- containers.py
|-- requirements.txt
|-- scripts
|   `-- provision
|       |-- provision_fedora.sh
|       `-- provision_ubuntu.sh
`-- tests
    `-- test_recipes.py
```

## HTTP API map (code ownership)
- `py/fortress/api/containers.py`: `/container/create`, `/container/{name}`, `/access/external/*`, `/container/users/*`, `/container/groups`, `/containers/connect/*`
- `py/server.py`: `/status`, `/monitoring/resources`, `/routing/add`, `/api-users*`, `/firewall/*`, `/packages/*`, `/recipes*`, `/backup/*`, `/restore`
- `py/server.py`: `/vms*` (VM registry, start/stop/status, snapshots, SSH provisioning/probing)
- `py/server.py`: `/hosts*` (SSH-managed host registry, provisioning/probing, saved states)
- `api-v1.yaml`: canonical OpenAPI reference; README.md mirrors route summaries and permissions

## Roadmap for AI
- See ROADMAP.md for detailed development paths and sequencing (modularization, monitoring baselines, tests, recipe lifecycle).
