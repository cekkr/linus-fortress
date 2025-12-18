This file contains the directives for AIs, and has to be updated by AIs itself to containing all strictly needed informations about the entire project to avoid repeated studies and next steps to do. In the meanwhile, update project's README.md

## Project status
- py/server.py contains the main central server with APIs
- py/server.py now supports API user tokens, container access controls (SSH/FTP), user/group management, and container connectivity features such as TCP proxying and shared mounts
- py/server.py also manages host/container package operations (apt + dnf) and firewall rules (ufw + firewalld) and README.md documents all APIs
- Master API key is optional (set via `FORTRESS_API_KEY`/`API_SECRET_KEY`) and should be disabled after bootstrap; delegated tokens are preferred long-term
- New recipe automation endpoints (`/recipes`, `/recipes/{name}`, `/recipes/apply`) allow "nix-like" install blueprints with dependencies, packages, and commands (templated with `{{param}}`), stored in `/var/lib/fortress/recipes.json`
- A new fortress.audit module powers the SQLite-based command register that captures all API activity plus container exec behaviour for investigation
- `py/fortress/recipes.py` holds recipe models, storage helpers, dependency resolution, and template rendering
- fortress-cli.py is a client utility that bootstraps a secure RSA keypair, stores encrypted API credentials/backup passwords, automates API calls (status, api-users, packages, backups), and locally decrypts encrypted backups
- api-v1.yaml documents the HTTP contract (OpenAPI 3.0.3) and README.md now lists request bodies/permissions for each endpoint

## Next steps
- Continue modularizing (auth utilities, container management) to shrink py/server.py and improve reuse
- Add automated tests (unit/integration) covering permission enforcement, command logging, and critical API flows
- Add CLI helpers for recipe creation/apply and support exporting/importing recipe bundles
