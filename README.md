# linus-fortress

Linus' Fortress is a FastAPI service that centralizes automation for LXD-based deployments: container lifecycle, routing, encrypted backups, delegated API users, monitoring and audit trails, recipe automation, and firewall/package orchestration for Ubuntu (`apt`) and AlmaLinux (`dnf`) style hosts. It also supports SSH-based host provisioning and VM-based test environments.

## Security posture

The system assumes capable adversaries and focuses on least privilege, scoped credentials, audit trails, and safe rollback behavior when applying changes.

### Threat model (concise)
- Stolen or leaked API tokens that could be used to manage containers or exfiltrate data.
- Malicious or compromised containers attempting lateral movement to the host or other containers.
- Abuse of exposed ports/routing to pivot into internal services.
- Unauthorized SSH or provisioning access to managed hosts or VMs.
- Supply chain risk via package installs or recipe execution.

### Hardening checklist (operator)
- Disable the master API key after bootstrap; rely on delegated tokens with minimal permissions and `allowed_containers`.
- Bind the API to a private interface; terminate TLS at a trusted proxy; rotate credentials regularly.
- Set `FORTRESS_BACKUP_PASSWORD` and store it outside the host; verify backup restores.
- Keep host OS and LXD patched; apply security updates before provisioning new containers.
- Restrict firewall rules and `POST /containers/expose` to known allowlists; prefer specific bind addresses.
- Run the service under a dedicated user with a tight sudoers policy for the required system commands.
- Keep audit logs (`/var/lib/fortress/command_log.db`) and ship them off-host for retention.
- Use SSH keys only for host/VM provisioning; disable password login for privileged accounts.

## Authentication

- `X-API-Key`: optional centralized master key with unrestricted access, best used only during bootstrap (set `FORTRESS_API_KEY` or `API_SECRET_KEY`). Disable it long-term to reduce blast radius.
- `X-User-Token`: delegated token created via `/api-users` endpoints. Each token carries its own permissions (`manage_containers`, `manage_routing`, `access_control`, `user_management`, `connectivity`, `manage_backups`, `restore_container`, `api_user_admin`, `firewall_admin`, `package_manage`, `recipes_manage`, `recipes_apply`, `read_status`, `vm_read`, `vm_manage`, `host_read`, `host_manage`) and optional `allowed_containers` scope.
- Either header grants access; if both are provided the master key takes precedence. Tokens scoped to containers must match the container(s) referenced by the request payload.

Once bootstrap tokens are created, unset `FORTRESS_API_KEY` (or keep the default placeholder) to disable the centralized key and reduce long-term risk.
If `FORTRESS_API_KEY` is unset or left as the default placeholder, `X-API-Key` authentication is disabled.

## Code map (selected)

- `py/server.py`: FastAPI routes and orchestration.
- `py/fortress/auth.py`: master key resolution, delegated token checks, container scope enforcement.
- `py/fortress/storage.py`: JSON load/save helpers for API users, recipes, hosts, and VMs.
- `py/fortress/routing.py`: nginx routing config rendering, domain validation, TLS path checks.
- `py/fortress/recipes.py`: recipe models, dependency resolution, and template rendering.
- `ui/`: optional Node/Express Lizard UI with modular app directories in `ui/apps`.

## Optional Lizard UI (Node/Express)

The `ui/` directory ships an optional app-based web interface inspired by the legacy Lizardim control panel. It runs on a separate port and proxies calls to the Fortress API.

Quick start:
- `cd ui`
- `npm install`
- `FORTRESS_UI_API_KEY=... FORTRESS_API_URL=https://127.0.0.1:8443 npm start`

Environment variables:
- `FORTRESS_UI_HOST` (default `127.0.0.1`) and `FORTRESS_UI_PORT` (default `8090`).
- `FORTRESS_API_URL` (default `https://127.0.0.1:8443`).
- `FORTRESS_UI_API_KEY` or `FORTRESS_UI_USER_TOKEN` for authentication.
- `FORTRESS_UI_INSECURE_TLS=1` to allow self-signed TLS when proxying to the API.

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
  "container_port": 8080,
  "container_interface": "eth0",
  "listen_address": "192.0.2.10",
  "listen_port": 8080,
  "tls": {
    "cert_path": "/etc/letsencrypt/live/app.example.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/app.example.com/privkey.pem",
    "chain_path": "/etc/letsencrypt/live/app.example.com/chain.pem",
    "listen_port": 443,
    "redirect_http": true
  }
}
```
- `domain` (string, required)
- `container_name` (string, required)
- `container_port` (int, optional, default `80`) – target port inside the container.
- `container_interface` (string, optional, default `eth0`) – which container NIC to resolve for upstream traffic.
- `listen_address` / `listen_port` (optional, default `0.0.0.0:80`) – bind nginx to a specific host interface/port.
- `tls` (object, optional) – enable HTTPS termination on the host.
  - `cert_path` / `key_path` (string, required when `tls` set) – absolute paths to PEM files.
  - `chain_path` (string, optional) – additional trust chain.
  - `listen_port` (int, optional, default `443`) – HTTPS listen port (must differ from `listen_port`).
  - `redirect_http` (bool, optional, default `true`) – redirect HTTP to HTTPS instead of proxying plain HTTP.
- Creates an nginx vhost that proxies to the container IP+port and reloads nginx. Useful for dual-homed hosts or segmented container networks.
- Routes are tracked in `/var/lib/fortress/routes.json` and written to `/etc/nginx/sites-available` with symlinks in `/etc/nginx/sites-enabled`.

#### `GET /routing` (permission `manage_routing`)
- Returns stored routing entries plus an `enabled` flag for the nginx symlink.

#### `DELETE /routing/{domain}` (permission `manage_routing`, container scoped)
- Removes the nginx vhost for the given domain and reloads nginx.

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

### VM Testing (QEMU/VirtualBox)

VM records let you spin up real OS test environments (QEMU/UTM or VirtualBox) and keep SSH access + snapshots for deeper integration tests.
Provisioning uses SSH to run the install-from-scratch scripts in `scripts/provision/provision_ubuntu.sh` and `scripts/provision/provision_fedora.sh`.

#### `GET /vms` (permission `vm_read`)
- Returns VM summaries (`name`, `provider`, `state`, `installed`, `ssh_host`, labels).

#### `POST /vms` (permission `vm_manage`)
Body (excerpt):
```json
{
  "name": "lab-ubuntu",
  "provider": "qemu",
  "cpu_cores": 2,
  "memory_mb": 4096,
  "disk_gb": 30,
  "iso_path": "/var/lib/isos/ubuntu.iso",
  "network_mode": "user",
  "ssh_forward_port": 2222,
  "ssh": {"host": "127.0.0.1", "username": "ubuntu", "port": 2222, "key_path": "/root/.ssh/id_rsa"}
}
```
- QEMU uses `qemu-img` + `qemu-system-*`, VirtualBox uses `VBoxManage`. UTM is treated as QEMU.

#### `POST /vms/{name}/start` + `POST /vms/{name}/stop` (permission `vm_manage`)
- Start/stop VMs, optionally booting from ISO on start.

#### `GET /vms/{name}/status` (permission `vm_read`)
- Returns `running`/`stopped` based on provider status checks.

#### `POST /vms/{name}/snapshots` (permission `vm_manage`)
Body: `{ "name": "baseline", "description": "clean install" }`

#### `POST /vms/{name}/snapshots/{snapshot}/restore` (permission `vm_manage`)
- Restores a saved snapshot to continue testing from a known state.

#### `POST /vms/{name}/provision` (permission `vm_manage`)
Body (excerpt):
```json
{
  "profile": "ubuntu",
  "repo_url": "https://github.com/your-org/linus-fortress.git",
  "branch": "main",
  "install_dir": "/opt/linus-fortress",
  "service_name": "fortress",
  "fortress_port": 8443
}
```
- Pushes the provisioning script over SSH and installs Linus' Fortress on a fresh VM.

#### `POST /vms/{name}/probe` (permission `vm_read`)
- SSH probe for hostname, OS, kernel, IP, CPU, memory, disk, and fortress service status.
- Use `save_as` to keep a named state in `/vms/{name}/states`.

CLI examples:
- `fortress-cli vms create --name lab-ubuntu --provider qemu --iso /var/lib/isos/ubuntu.iso --ssh-host 127.0.0.1 --ssh-user ubuntu --ssh-port 2222 --ssh-key ~/.ssh/id_rsa`
- `fortress-cli vms start lab-ubuntu --use-iso`
- `fortress-cli vms provision lab-ubuntu --profile ubuntu --repo-url https://github.com/your-org/linus-fortress.git`
- `fortress-cli vms probe lab-ubuntu --save-as baseline`

### Host Provisioning (SSH)

Host records reuse the same provisioning/probing scripts for production or staging machines over SSH. Scripts live in `scripts/provision` and are shared with VM workflows.
Provisioning pulls fast-forward updates when the repo is clean; set `force_reset` (API/CLI) or `FORCE_RESET=1` (script) to overwrite local changes.

#### `GET /hosts` (permission `host_read`)
- Returns host summaries (`name`, `installed`, `ssh_host`, labels).

#### `POST /hosts` (permission `host_manage`)
Body (excerpt):
```json
{
  "name": "prod-eu-1",
  "os_type": "ubuntu",
  "service_name": "fortress",
  "ssh": {"host": "198.51.100.10", "username": "root", "key_path": "/root/.ssh/id_rsa"}
}
```

#### `POST /hosts/{name}/provision` (permission `host_manage`)
- Pushes the provisioning script over SSH and installs Linus' Fortress on the remote host.

#### `POST /hosts/{name}/probe` (permission `host_read`)
- SSH probe for hostname, OS, kernel, IP, CPU, memory, disk, and fortress service status.
- Use `save_as` to keep a named state in `/hosts/{name}/states`.

CLI examples:
- `fortress-cli hosts create --name prod-eu-1 --ssh-host 198.51.100.10 --ssh-user root --ssh-key ~/.ssh/id_rsa`
- `fortress-cli hosts provision prod-eu-1 --profile ubuntu --repo-url https://github.com/your-org/linus-fortress.git`
- `fortress-cli hosts probe prod-eu-1 --save-as baseline`


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
  "connect_interface": "eth1",
  "device_name": "optional-custom-name"
}
```
- `service` is `ssh` or `ftp` and chooses default ports if `host_port`/`connect_port` unset.
- `connect_interface` (optional) resolves the container IP on that NIC instead of providing `connect_address` manually.
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
  "target_interface": "eth1",
  "target_address": "10.10.0.25",
  "device_name": "optional-custom"
}
```
- Either `target_address` (explicit IP) or `target_interface` (default `eth0`) is used to pick the upstream IP when connecting to the target container.
- Automatically resolves `target_container` IP and adds an LXD proxy device; returns `device_name`.

#### `POST /containers/connect/tcp/remove`
- Body requires `container_name` (proxy lives here) and `device_name`.

#### `POST /containers/expose`
- Body:
```json
{
  "container_name": "web01",
  "exposures": [
    {
      "protocol": "tcp",
      "bind_address": "0.0.0.0",
      "host_ports": [8080, 8443],
      "container_port": 8080,
      "target_interface": "eth0",
      "device_name_prefix": "public",
      "open_firewall": true,
      "allow_sources": ["203.0.113.0/24"]
    },
    {
      "protocol": "udp",
      "port_range": {"start": 5000, "end": 5003},
      "target_interface": "eth1",
      "target_address": "10.10.0.25",
      "open_firewall": false
    }
  ]
}
```
- `host_ports` (array) or `port_range` (object `{start,end}`) defines which host ports to bind (max 50 per request). If neither is set, `container_port` is used for both sides.
- `container_port` defaults to the same as each host port; set explicitly to map many host ports to one container port.
- `target_interface` or `target_address` chooses the container NIC/IP to route toward (default `eth0`).
- `open_firewall` applies host firewall rules (`ufw`/`firewalld`) for each bound port, optionally restricted to `allow_sources`. Rolls back devices and firewall rules on failure.
- Returns created device names, bound ports, and firewall rules applied.

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

See `ROADMAP.md` for the detailed development paths and sequencing.
