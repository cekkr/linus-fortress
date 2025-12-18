This file contains the directives for AIs, and has to be updated by AIs itself to containing all strictly needed informations about the entire project to avoid repeated studies and next steps to do. In the meanwhile, update project's README.md

## Project status
- py/server.py contains the main central server with APIs and now includes the containers router
- py/fortress/monitoring.py centralizes host/container resource snapshots with alert thresholds
- Container lifecycle/access/connectivity APIs are implemented in `py/fortress/api/containers.py` with LXC helpers in `py/fortress/containers.py`
- `py/fortress/system.py` owns the shared `run_command` helper used by server and container management
- py/server.py also manages host/container package operations (apt + dnf) and firewall rules (ufw + firewalld)
- `/monitoring/resources` exposes structured host+container metrics plus alert flags for automation against anomalous usage/malware-like spikes
- Master API key is optional (set via `FORTRESS_API_KEY`/`API_SECRET_KEY`) and should be disabled after bootstrap; delegated tokens are preferred long-term
- New recipe automation endpoints (`/recipes`, `/recipes/{name}`, `/recipes/apply`) allow "nix-like" install blueprints with dependencies, packages, and commands (templated with `{{param}}`), stored in `/var/lib/fortress/recipes.json`
- A new fortress.audit module powers the SQLite-based command register that captures all API activity plus container exec behaviour for investigation
- `py/fortress/recipes.py` holds recipe models, storage helpers, dependency resolution, and template rendering
- fortress-cli.py now includes `recipes list|create|apply` helpers in addition to status/api-users/package/backup calls
- Unit tests in `tests/test_recipes.py` cover recipe dependency resolution and apply planning
- api-v1.yaml documents the HTTP contract (OpenAPI 3.0.3) and README.md lists request bodies/permissions for each endpoint

## Project structure (tree)
```
.
|-- AI_REFERENCES.md
|-- README.md
|-- api-v1.yaml
|-- fortress-cli.py
|-- py
|   |-- server.py
|   `-- fortress
|       |-- __init__.py
|       |-- audit.py
|       |-- containers.py
|       |-- monitoring.py
|       |-- recipes.py
|       |-- system.py
|       `-- api
|           |-- __init__.py
|           `-- containers.py
`-- tests
    `-- test_recipes.py
```

## HTTP API map (code ownership)
- `py/fortress/api/containers.py`: `/container/create`, `/container/{name}`, `/access/external/*`, `/container/users/*`, `/container/groups`, `/containers/connect/*`
- `py/server.py`: `/status`, `/monitoring/resources`, `/routing/add`, `/api-users*`, `/firewall/*`, `/packages/*`, `/recipes*`, `/backup/*`, `/restore`
- `api-v1.yaml`: canonical OpenAPI reference; README.md mirrors route summaries and permissions

## Roadmap for AI
- Short term: extract auth/token utilities + storage helpers into `py/fortress/auth.py` and `py/fortress/storage.py` to keep py/server.py lean
- Short term: add unit tests for container scope enforcement and audit logging (mock LXC subprocess calls)
- Short term: add persistence/baseline tracking for monitoring to surface rate-based anomalies (CPU deltas, network spikes)
- Mid term: add integration tests for core API flows and permission matrix
- Mid term: recipe export/import bundles with semantic versioning and change history
