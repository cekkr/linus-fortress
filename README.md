# linus-fortress

Linus' Fortress is a FastAPI service that centralizes automation for LXD-based VPS deployments: container lifecycle, routing, encrypted backups, delegated API users, security hardening, and now firewall plus package orchestration for both Ubuntu (`apt`) and AlmaLinux (`dnf`) style hosts.

## Authentication

- `X-API-Key`: optional centralized master key with unrestricted access, best used only during bootstrap (set `FORTRESS_API_KEY` or `API_SECRET_KEY`). Disable it long-term to reduce blast radius.
- `X-User-Token`: delegated token created via `/api-users` endpoints. Each token carries its own permissions (`manage_containers`, `manage_routing`, `access_control`, `user_management`, `connectivity`, `manage_backups`, `restore_container`, `api_user_admin`, `firewall_admin`, `package_manage`, `recipes_manage`, `recipes_apply`, `read_status`) and optional `allowed_containers` scope.
- Either header grants access; if both are provided the master key takes precedence. Tokens scoped to containers must match the container(s) referenced by the request payload.

Once bootstrap tokens are created, unset `FORTRESS_API_KEY` (or keep the default placeholder) to disable the centralized key and reduce long-term risk.
If `FORTRESS_API_KEY` is unset or left as the default placeholder, `X-API-Key` authentication is disabled.

## API Reference

A full OpenAPI description is provided in [`api-v1.yaml`](api-v1.yaml) (import it into Swagger UI, Postman, Insomnia, etc.). The summaries below highlight each route, the permissions enforced by `py/server.py`, and the body/parameter semantics that `fortress-cli.py` uses under the hood.

All endpoints require either `X-API-Key` or `X-User-Token`. Permissions listed below map to the capabilities stored in the delegated API user records.

### Status & Routing

#### `GET /status` (permission `read_status`)
- No body or query params; returns `{status, ram, disk, containers}` strings straight from `free`, `df`, and `lxc list`.
- Example: `fortress-cli status`

#### `GET /monitoring/resources` (permission `read_status`)
- Optional query params to tune alerting thresholds: `host_memory_threshold` (default `90`), `host_disk_threshold` (`90`), `host_load_threshold` (`1.5` 1m load per CPU), `container_memory_threshold` (`85`), `container_disk_threshold` (`85`), `container_process_threshold` (`300`), `container_memory_absolute_mb` (`1024`), `container_disk_absolute_gb` (`5`).
- Returns structured host+container metrics with `alerts` and the thresholds applied, e.g.:
```json
{
  "timestamp": "2024-02-11T10:22:33Z",
  "host": {"memory": {"used_percent": 73.2}, "cpu": {"per_cpu_load_1m": 0.34}, "disk": {"used_percent": 61.8}, "alerts": []},
  "containers": [
    {"name": "web01", "memory": {"used_percent": 81.5}, "disk": {"used_percent": 62.1}, "processes": 44, "alerts": []}
  ],
  "alerts": {"host": [], "containers": {}}
}
```
- Designed for automation: anomalous usage (memory/disk saturation, runaway processes, high host load) surfaces in `alerts` so malware-like spikes can be intercepted by downstream tooling.

#### `POST /routing/add` (permission `manage_routing`, container scoped)
Body:
```json
{
  "domain": "app.example.com",
  "container_name": "web01",
  "container_port": 80
}
```
- `domain` (string, required)
- `container_name` (string, required)
- `container_port` (int, optional, default `80`)
- Creates an nginx vhost that proxies to the container IP+port and reloads nginx.

### Container Lifecycle

#### `POST /container/create` (permission `manage_containers`, scoped to `name`)
Body fields (defaults shown):
- `name` (**required** string) – LXD container name.
- `distro` (string, default `ubuntu:22.04`) – image alias to launch.
- `cpu_limit` (string, default `1`) – passed to `lxc config set limits.cpu`.
- `ram_limit` (string, default `512MB`).
- `disk_limit` (string, default `10GB`).

#### `DELETE /container/{name}` (permission `manage_containers`, scoped)
- Path parameter `name` is required; shuts down and deletes the container (`lxc delete --force`).

### API Users

#### `POST /api-users` (permission `api_user_admin`)
Body:
```json
{
  "username": "automation-bot",
  "permissions": ["manage_containers", "read_status"],
  "allowed_containers": ["web01", "db01"]
}
```
- Returns a generated token plus the stored record.

#### `GET /api-users` (permission `api_user_admin`)
- Lists every token with `username`, `permissions`, and scope.

#### `PUT /api-users/{token}` (permission `api_user_admin`)
Body may include:
- `permissions` (array of strings, optional)
- `allowed_containers` (array of strings, optional)

#### `DELETE /api-users/{token}` (permission `api_user_admin`)
- Removes the delegated token.

### External Access

#### `POST /access/external/open` (permission `access_control`, scoped to container)
Body:
```json
{
  "container_name": "web01",
  "service": "ssh",
  "host_port": 2222,
  "connect_port": 22,
  "bind_address": "0.0.0.0",
  "connect_address": "127.0.0.1",
  "device_name": "optional-custom-name"
}
```
- `service` is `ssh` or `ftp` and chooses default ports if `host_port`/`connect_port` unset.
- Returns the actual device name created on the container.

#### `POST /access/external/close` (permission `access_control`)
Body requires `container_name` plus either:
- `device_name` (string) **or**
- `service` (`ssh`/`ftp`) with optional `host_port` (int) to resolve the auto-generated name.

### Container Users & Groups (permission `user_management`, scoped)

#### `POST /container/users/create`
- Body: `{ "container_name": "...", "username": "...", "password": "optional", "groups": ["sudo","www-data"] }`
- Password is optional; if omitted the user is created without credentials.

#### `POST /container/users/password`
- Body requires `container_name`, `username`, and new `password`.

#### `POST /container/users/groups`
- Body requires `container_name`, `username`, and `groups` array. Replaces the user’s supplementary groups.

#### `DELETE /container/users`
- Body requires `container_name`, `username`, and optional `remove_home` (bool, default `false`).

#### `POST /container/groups`
- Body requires `container_name` and `group_name`; runs `groupadd -f`.

### Container Connectivity (permission `connectivity`)

#### `POST /containers/connect/tcp`
- Body:
```json
{
  "source_container": "app",
  "target_container": "db",
  "listen_port": 5432,
  "target_port": 5432,
  "bind_address": "0.0.0.0",
  "protocol": "tcp",
  "device_name": "optional-custom"
}
```
- Automatically resolves `target_container` IP and adds an LXD proxy device; returns `device_name`.

#### `POST /containers/connect/tcp/remove`
- Body requires `container_name` (proxy lives here) and `device_name`.

#### `POST /containers/connect/share`
- Body:
```json
{
  "share_name": "code",
  "containers": ["app", "worker"],
  "mount_path": "/srv/code",
  "source_path": "/srv/fortress/code"
}
```
- `source_path` optional; defaults to `${SHARED_STORAGE_DIR}/{share_name}` when omitted.
- Returns each attachment’s generated `device_name`.

#### `POST /containers/connect/share/remove`
- Body requires same `share_name` and the list of `containers` that should have the disk detached.

### Firewall Management (permission `firewall_admin`)

#### `POST /firewall/open` and `POST /firewall/close`
Common body:
```json
{
  "port": 443,
  "protocol": "tcp",
  "source": "203.0.113.0/24"
}
```
- `port` (int, required); `protocol` optional default `tcp`; `source` optional CIDR (only for ufw rich rule / firewalld rich rule).

### Package Management (permission `package_manage`, scoped if `container_name` set)

#### `POST /packages/install`
- Body contains `packages` (array of strings, **required**), optional `container_name`, and `update_index` (bool, default `true`).

#### `POST /packages/remove`
- Body: `{"packages": ["vim"], "container_name": "web01"}` (`container_name` optional).

#### `POST /packages/update`
- Body: `{"container_name": "web01", "full_upgrade": true}` – both fields optional (`full_upgrade` default `false`).

### Recipes & Automation (permissions `recipes_manage` and `recipes_apply`)

Recipes are "nix-like" automation blueprints stored in `/var/lib/fortress/recipes.json`. Each recipe can install packages, run commands, and depend on other recipes. Command strings and package names support `{{param}}` placeholders resolved from the supplied parameters.

#### `GET /recipes` (permission `recipes_manage`)
- Lists available recipes with dependency counts and parameter keys.

#### `POST /recipes` (permission `recipes_manage`)
Body:
```json
{
  "name": "base-python",
  "description": "Install python runtime",
  "packages": ["python3", "python3-pip"],
  "commands": ["python3 --version"],
  "parameters": {},
  "required_parameters": []
}
```

#### `PUT /recipes/{name}` (permission `recipes_manage`)
- Updates the recipe fields you provide; send empty arrays to clear lists.

#### `DELETE /recipes/{name}` (permission `recipes_manage`)
- Removes a recipe unless other recipes still depend on it.

#### `POST /recipes/apply` (permission `recipes_apply`, scoped if `container_name` set)
Body:
```json
{
  "recipe_name": "app-bootstrap",
  "container_name": "web01",
  "parameters": {"app_user": "deploy"},
  "include_dependencies": true,
  "update_index": true
}
```
- Applies dependencies first, then installs packages and runs commands for each recipe in order.
- Use `{{app_user}}` inside commands/packages to parameterize installs.

Example dependency recipe:
```json
{
  "name": "app-bootstrap",
  "dependencies": ["base-python"],
  "commands": ["useradd -m {{app_user}}", "mkdir -p /srv/{{app_user}}"],
  "parameters": {"app_user": "deploy"},
  "required_parameters": ["app_user"]
}
```

### Backup & Restore

#### `POST /backup/{container_name}` (permission `manage_backups`, scoped)
- Path parameter `container_name`; no body. Starts encrypted backup task.

#### `GET /backup/list` (permission `manage_backups`)
- Returns `{ "backups": ["container_20240101.tar.gz.enc", ...] }`.

#### `GET /backup/download/{filename}` (permission `manage_backups`)
- Streams the encrypted archive bytes; combine with `fortress-cli backup download`.

#### `POST /restore` (permission `restore_container`, scoped)
- Query parameter `container_name` and multipart form body containing `file` (encrypted `.enc` upload). The service decrypts with the server-side Fernet key and runs `lxc import`.

### Command Register & Auditing
- Every API call records an immutable entry into `command_log.db` (see `COMMAND_LOG_DB`), capturing `actor`, endpoint, action, target, and sanitized payload details.
- Internal behaviours such as `lxc exec` commands are also logged with command metadata (sensitive arguments are redacted) so operators can trace suspicious cross-container activity.
- The register lives alongside other Fortress state under `/var/lib/fortress`; query it via `sqlite3 /var/lib/fortress/command_log.db 'select * from command_log order by id desc limit 20;'`.

## Deployment Notes

- Server listens via uvicorn (`HOST_INTERFACE`, `HOST_PORT`). For production, terminate TLS via web server or provide `ssl_keyfile`/`ssl_certfile`.
- Set filesystem paths (`BACKUP_DIR`, `NGINX_CONFIG_DIR`, `API_USERS_DB`, `RECIPES_DB`, `SHARED_STORAGE_DIR`) to match your host.
- Configure secrets via env vars (`FORTRESS_API_KEY`, `FORTRESS_BACKUP_PASSWORD`) instead of hardcoding defaults.
- Ensure the runtime user has permission to run `lxc`, manage firewall (`ufw` or `firewall-cmd`), and package commands (`apt-get` or `dnf`).

## Client CLI (`fortress-cli.py`)

`fortress-cli.py` is a companion script that securely stores API credentials, automates the HTTPS calls to the server, and handles encrypted backup archives.

1. Run `python fortress-cli.py setup --server https://fortress.example.com:8443` to generate a 4096‑bit RSA keypair (protected by a passphrase) and enter the API master key, delegated user token, and/or backup password. Everything is saved under `~/.fortress-cli` (override via `FORTRESS_HOME`).
2. Subsequent commands unlock the private key (either interactively or via `--passphrase`/`FORTRESS_PASSPHRASE`) and reuse the stored credentials:
   - `python fortress-cli.py status` → GET `/status`
   - `python fortress-cli.py call POST /packages/install --json '{"packages":["vim"]}'`
   - `python fortress-cli.py backup list|trigger|download|decrypt ...`
   - `python fortress-cli.py api-users create alice --permissions manage_containers read_status`
   - `python fortress-cli.py recipes list|create|apply ...`
3. Encrypted backups can be downloaded and decrypted locally via `python fortress-cli.py backup download foo.enc --dest ./foo.enc` followed by `python fortress-cli.py backup decrypt ./foo.enc --output ./foo.tar.gz`.

Recipe CLI examples:
- Create a recipe: `python fortress-cli.py recipes create --name base-python --package python3 --package python3-pip`
- Apply to a container: `python fortress-cli.py recipes apply base-python --container web01`

By default TLS certificates are verified; pass `--insecure` during `setup` only if you are pointing at a self-signed lab server. Use the CLI’s `info` command to inspect the stored metadata without revealing secrets.

## Testing

- `python -m unittest discover -s tests`

## Roadmap

- Continue modularizing `py/server.py` (auth/storage) now that container APIs live in `py/fortress/api/containers.py`.
- Extend recipe automation with versioning and export/import bundles.
- Add automated tests or contract tests for each API route.
