# linus-fortress

Linus' Fortress is a FastAPI service that centralizes automation for LXD-based deployments: container lifecycle, routing, encrypted backups, delegated API users, monitoring and audit trails, recipe automation, and firewall/package orchestration for Ubuntu/Debian (`apt`) and AlmaLinux/RHEL (`dnf`/`yum`) style hosts. It also supports SSH-based host provisioning and VM-based test environments.

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
- Run the service under a dedicated user with a tight sudoers policy for the required system commands (see Run Server Script).
- Keep audit logs (`/var/lib/fortress/command_log.db`) and ship them off-host for retention.
- Use SSH keys only for host/VM provisioning; disable password login for privileged accounts.

## Authentication

- `X-API-Key`: optional centralized master key with unrestricted access, best used only during bootstrap (set `FORTRESS_API_KEY` or `API_SECRET_KEY`). Disable it long-term to reduce blast radius.
- `X-User-Token`: delegated token created via `/api-users` endpoints. Each token carries its own permissions (`manage_containers`, `manage_routing`, `access_control`, `user_management`, `connectivity`, `manage_backups`, `restore_container`, `api_user_admin`, `firewall_admin`, `package_manage`, `recipes_manage`, `recipes_apply`, `read_status`, `vm_read`, `vm_manage`, `host_read`, `host_manage`, `sites_read`, `sites_manage`, `migration_admin`) and optional `allowed_containers` scope.
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

When no UI credentials are set via environment, the UI prompts for a delegated token and stores it server-side in a session cookie (tokens never persist in the browser).

Environment variables:
- `FORTRESS_UI_HOST` (default `127.0.0.1`) and `FORTRESS_UI_PORT` (default `8090`).
- `FORTRESS_API_URL` (default `https://127.0.0.1:8443`).
- `FORTRESS_UI_API_KEY` or `FORTRESS_UI_USER_TOKEN` for authentication.
- `FORTRESS_UI_INSECURE_TLS=1` to allow self-signed TLS when proxying to the API.
- `FORTRESS_UI_SESSION_TTL` (seconds, default `43200`) and `FORTRESS_UI_SESSION_COOKIE` to tune UI session lifetimes.
- `FORTRESS_UI_COOKIE_SECURE=1` to set Secure on the UI session cookie when served via HTTPS.
- Admin security: `FORTRESS_UI_ADMIN_DB`, `FORTRESS_UI_ADMIN_AUDIT_LOG`, `FORTRESS_UI_ADMIN_SESSION_COOKIE`, `FORTRESS_UI_ADMIN_SESSION_TTL`, `FORTRESS_UI_PASSWORD_MIN_LENGTH`, `FORTRESS_UI_LOCKOUT_THRESHOLD`, `FORTRESS_UI_LOCKOUT_MINUTES`, `FORTRESS_UI_TOTP_ISSUER`, `FORTRESS_UI_TOTP_WINDOW`, `FORTRESS_UI_ADMIN_ENABLED=0` to disable enforcement (not recommended).

For full LAMP automation and routing flows, the delegated token should include `manage_containers`, `manage_routing`, `recipes_manage`, `recipes_apply`, and `sites_manage`.

The UI service enforces admin login (password policy + lockout + audit log + optional TOTP) before allowing delegated-token sessions. If no admin exists yet, the UI presents a bootstrap form backed by `/api/admin/bootstrap`. Admin sessions are stored in a UI-only cookie (`FORTRESS_UI_ADMIN_SESSION_COOKIE`).

First run (UI admin bootstrap):
- Open the WebUI and use the “Create admin” form shown on first load, or
- `POST /api/admin/bootstrap` with `{ "username": "...", "password": "..." }` to create the first UI admin.
Note: the UI admin store is local to the UI server process (default `/var/lib/fortress/ui_admins.json` when running as root; `~/.fortress-ui/ui_admins.json` when running as an unprivileged user). If you run the UI locally, you must bootstrap a local admin on that machine.
The admin store file is initialized on the first UI request, even before bootstrap, so you can verify the path exists.

Delegated token notes:
- The WebUI validates delegated tokens by calling `GET /status`, so the token must include `read_status`.
- You can generate a token with `fortress-cli api-users create ...` or let `run-server.sh`/`run-client.sh` prompt for one.
- Typed tokens (`user-token:<token>` / `api-key:<key>`) are accepted and shown in copy/paste helpers.
- `fortress-cli` also honors `FORTRESS_API_KEY` / `FORTRESS_USER_TOKEN` environment variables (handy if the local keypair was reset).

LAMP stack apps appear when a container is tagged with `user.lizard.stack=lamp` (or `user.fortress.stack=lamp`) via LXD config, or when the container name includes `lamp`.
Optional service hints can be supplied with `user.lizard.services=apache,mysql,ftp` (comma-separated) to remove the install badge.
The UI can probe service availability via `POST /containers/probe` (permission `manage_containers`) and update the LXD labels automatically.
The file manager install uses Tiny File Manager under `/var/www/html/filemanager` and prompts for `fm_user`/`fm_password`.
Recipe apply results now surface `probe.health_checks` with pass/fail/skipped badges and per-check summaries in the recipes views.
The Packages app includes a guided System Upgrade wizard that runs `/system/upgrade` preflight (`dry_run=true`) and requires backup confirmation before execution.

## Run Server Script

`run-server.sh` bootstraps the host, writes `/etc/fortress/fortress.env`, and starts the API (and optional UI) in foreground, `screen`, or systemd service mode.
Use `--reset` to delete the saved env file and re-run the first-run configuration prompts. If an existing Fortress process or service is detected, the script will prompt to stop it before starting.
When the API/UI bind to a non-loopback address, the script opens the corresponding ports via firewalld (RHEL/AlmaLinux) or ufw (Ubuntu) if the firewall is active.
If `--mode service` is selected and the repo lives under `/root` or `/home` (or on a `noexec` mount), the script offers to relocate the clone to `/opt/linus-fortress` to avoid systemd/SELinux execution failures.
On first run, the script can also generate a delegated token for copy/paste into the CLI or WebUI configuration.
Debug responses (default enabled) can be toggled with `./run-server.sh --debug-enable` or `./run-server.sh --debug-disable`.
If systemd fails to start the UI due to a Node.js path (common when `node` points to `/root/.nvm/...`), install system Node.js and/or set `FORTRESS_NODE_BIN=/usr/bin/node` before re-running `./run-server.sh --mode service`.

Host assumptions:
- Linux distro with `apt`, `dnf`, or `yum` (Ubuntu/Debian or AlmaLinux/RHEL-like).
- `nginx` plus `ufw` (apt) or `firewalld` (dnf/yum) for routing and firewall ops.
- `lxc`/`lxd` for container APIs; on AlmaLinux the script installs LXD via snap (snapd) when missing and ensures `/snap/bin` is reachable for service/screen runs. It can run `lxd init --auto` if LXD is installed.
- `certbot` for automated Let's Encrypt issuance/renewal (the script attempts to install it when possible).
- The script checks for missing OS packages on each run and installs them when possible.
- On SELinux-enforcing hosts (AlmaLinux/RHEL), systemd may need proper file contexts; if you run as a service from `/root` or `/home`, consider moving the repo to `/opt/linus-fortress` or relabeling it.

AlmaLinux hardening (first-run prompt):
- Optional SSH hardening can create a sudo admin user, generate a 24-32 character A-Z/a-z/0-9 password by default, and disable root SSH login (plus optional password authentication disable).
- Always test SSH access as the new user before ending the root session.
- When the UI is bound to a non-loopback address on AlmaLinux, the script can prompt to open the UI port in firewalld.

Least-privilege setup:
- Use `scripts/setup-service-user.sh` (run as root) to create a service user and install a sudoers entry, or apply `scripts/fortress-sudoers.template` manually.
- Ensure `run-server.sh` is root-owned and not group/other writable before granting sudo rights.

## Run Client Script

`run-client.sh` is an interactive helper for configuring local access to a remote Fortress API.

Quick start:
- `./run-client.sh` to run `fortress-cli setup` with prompts.
- You can pass a plain IP/hostname via `--server` (defaults to `https://<addr>:8443`).
- `./run-client.sh --server <ip> --token user-token:<token>` for a one-line remote bootstrap.
- `./run-client.sh --webui` to generate a local WebUI env file and print steps to run the UI locally against a remote API.
- `./run-client.sh --issue-token` to create a delegated token after setup (requires an API key or a token with `api_user_admin`).
- `./run-client.sh --reset-keys` to regenerate the CLI RSA keypair.
- TLS helpers:
  - Default for public hosts is strict TLS verification; Let's Encrypt works out-of-the-box.
  - `--pin-cert` fetches the server cert and stores it under `~/.fortress-cli/api-ca.pem` (preferred for self-signed).
  - `--ca-bundle /path/to/ca.pem` reuses an existing CA bundle (stored in CLI config and exported to the WebUI via `NODE_EXTRA_CA_CERTS`).
  - Use `--insecure` only if you explicitly want to skip verification.
During `--webui`, the script also prompts to bootstrap a local UI admin (use `--no-bootstrap-admin` to skip).
Tip: `fortress-cli setup --show-keys` prints the key paths (and `--show-passphrase` prints the passphrase when keys are regenerated).

## Remote server + local client (recommended flow)

### 1) Server (remote host)
1. Run `./run-server.sh --configure` and answer:
   - API host interface: use `0.0.0.0` if the API is remote.
   - API port: default `8443`.
   - Enable master API key for bootstrap (recommended).
   - Enable admin UI server only if you want a **server-side** UI.
   - If UI is enabled, choose whether to make it public (bind `0.0.0.0`).
2. If you make the UI public, the script will **offer to open the firewall** for the UI port.
3. If run mode is `service`, the script asks whether to run the UI as a systemd service too.
4. When prompted, create an initial delegated token (default permissions now `*`; tighten later).

### 2) Client (your laptop)
CLI:
- For public domains/IPs, just run `./run-client.sh --server <host>` (strict TLS by default).
- For self-signed TLS, prefer `./run-client.sh --server <host> --pin-cert` to pin the certificate, or reuse a bundle with `--ca-bundle <pem>`. Fall back to `--insecure` only if pinning is not possible.
- Point to the remote API (a bare IP/hostname is enough; it expands to `https://<addr>:8443`).
- Use the master API key (or a delegated token with `api_user_admin`) to create delegated tokens.

Local WebUI (recommended):
1. `./run-client.sh --webui`
2. It writes `ui/.env.local` with `FORTRESS_API_URL=https://<server-ip>:8443` and TLS settings.
3. Start the UI: `cd ui && npm install && npm start`
4. The **UI admin is local** to your laptop. Bootstrap it once using the form.
5. Enter a delegated token (must include `read_status`).

Server-side WebUI (optional):
- Only use if you want the UI hosted on the server.
- Make sure the firewall allows the UI port and consider additional access controls (VPN, IP allowlist, reverse proxy auth).

## Fast remote demo (server + client + remote WebUI)

Goal: quickest secure-ish setup for a remote server with a **server-hosted WebUI**, plus a local CLI client.

### Server (remote host) — first time or reconfigure
1. Reconfigure (keeps repo, rewrites env):  
   `./run-server.sh --configure`
2. Recommended answers:
   - API host interface: `0.0.0.0`
   - API port: `8443`
   - Enable master API key for bootstrap: **Yes**
   - Enable admin UI server: **Yes**
   - Make admin UI public (bind `0.0.0.0`): **Yes**
   - Admin UI port: `8090`
   - Admin UI API URL: `https://127.0.0.1:8443`
   - Allow UI to trust self-signed TLS from API: **Yes** (if using self-signed)
   - Create initial delegated token: **Yes** (default permissions `*`)
   - Run mode: `service` (recommended)
   - Run admin UI as a systemd service too: **Yes**

Security recommendations (fast but safer):
- Use a strong master API key; disable it after you create delegated tokens.
- Prefer delegated tokens with least privilege + `read_status` for the UI.
- If the UI is public, restrict access (VPN, IP allowlist, reverse proxy auth).
- Rotate tokens if you pasted them into terminals or chat.

### Client (your laptop)
1. Configure CLI against the remote API (self-signed? use `--insecure`):  
   `./run-client.sh --server <server-ip> --token user-token:<token> --insecure`
2. Create a delegated token (if you didn’t already):  
   `./run-client.sh --issue-token --insecure`

### Remote WebUI usage
1. Open `http://<server-ip>:8090` (or your chosen UI port).
2. Bootstrap the **UI admin** (first visit).
3. Paste the delegated token (must include `read_status`; `user-token:<token>` accepted).

Tip: If you only want a **local WebUI**, use `./run-client.sh --webui` instead and keep the UI port closed on the server.

## API Reference

A full OpenAPI description is provided in [`api-v1.yaml`](api-v1.yaml) (import it into Swagger UI, Postman, Insomnia, etc.). The summaries below highlight each route, the permissions enforced by `py/server.py`, and the body/parameter semantics that `fortress-cli.py` uses under the hood.

All endpoints require either `X-API-Key` or `X-User-Token`. Typed tokens (`api-key:<key>` or `user-token:<token>`) are accepted in either header and normalized by the API. Permissions listed below map to the capabilities stored in the delegated API user records.

### Status & Routing

#### `GET /status` (permission `read_status`)
- No body or query params; returns `{status, ram, disk, containers}` strings straight from `free`, `df`, and `lxc list`.
- Example: `fortress-cli status`

#### `GET /monitoring/resources` (permission `read_status`)
- Optional query params to tune alerting thresholds: `host_memory_threshold` (default `90`), `host_disk_threshold` (`90`), `host_load_threshold` (`1.5` 1m load per CPU), `container_memory_threshold` (`85`), `container_disk_threshold` (`85`), `container_process_threshold` (`300`), `container_memory_absolute_mb` (`1024`), `container_disk_absolute_gb` (`5`).
- Anomaly and history controls: `history_limit` (`120`, set `0` to disable history retention), `anomaly_baseline_samples` (`6`), `anomaly_host_cpu_multiplier` (`2.5`), `anomaly_host_cpu_min_percent` (`75`), `anomaly_host_network_multiplier` (`3`), `anomaly_host_network_min_bytes_per_sec` (`5242880`), `anomaly_container_cpu_multiplier` (`2.5`), `anomaly_container_cpu_min_cores` (`0.5`), `anomaly_container_network_multiplier` (`3`), `anomaly_container_network_min_bytes_per_sec` (`5242880`).
- Returns structured host+container metrics with `alerts`, `anomalies`, and the thresholds applied (snapshots are persisted for baseline comparisons), e.g.:
```json
{
  "timestamp": "2024-02-11T10:22:33Z",
  "host": {
    "memory": {"used_percent": 73.2},
    "cpu": {"per_cpu_load_1m": 0.34},
    "disk": {"used_percent": 61.8},
    "network": {"bytes_received": 123456, "bytes_sent": 654321},
    "alerts": []
  },
  "containers": [
    {
      "name": "web01",
      "memory": {"used_percent": 81.5},
      "disk": {"used_percent": 62.1},
      "network": {"bytes_received": 112233, "bytes_sent": 221133},
      "processes": 44,
      "alerts": []
    }
  ],
  "alerts": {"host": [], "containers": {}},
  "anomalies": {"host": [], "containers": {}},
  "history": {"count": 12, "limit": 120}
}
```
- Designed for automation: anomalous usage (memory/disk saturation, runaway processes, high host load) surfaces in `alerts`, while rate spikes (CPU/network deltas) appear in `anomalies` for downstream tooling.

#### `POST /routing/add` (permission `manage_routing`, container scoped)
Body:
```json
{
  "domain": "app.example.com",
  "domains": ["www.app.example.com", "*.app.example.com"],
  "container_name": "web01",
  "container_port": 8080,
  "container_interface": "eth0",
  "listen_address": "192.0.2.10",
  "listen_port": 8080,
  "tls": {
    "mode": "manual",
    "cert_path": "/etc/letsencrypt/live/app.example.com/fullchain.pem",
    "key_path": "/etc/letsencrypt/live/app.example.com/privkey.pem",
    "chain_path": "/etc/letsencrypt/live/app.example.com/chain.pem",
    "listen_port": 443,
    "redirect_http": true
  }
}
```
- `domain` (string, required)
- `domains` (string array, optional) – additional server names; supports wildcard entries like `*.example.com`.
- `container_name` (string, required)
- `container_port` (int, optional, default `80`) – target port inside the container.
- `container_interface` (string, optional, default `eth0`) – which container NIC to resolve for upstream traffic.
- `listen_address` / `listen_port` (optional, default `0.0.0.0:80`) – bind nginx to a specific host interface/port.
- `tls` (object, optional) – enable HTTPS termination on the host.
  - `mode` (`manual|letsencrypt`, default `manual`).
  - `cert_path` / `key_path` (string, required for `mode=manual`) – absolute paths to PEM files.
  - `chain_path` (string, optional) – additional trust chain.
  - `listen_port` (int, optional, default `443`) – HTTPS listen port (must differ from `listen_port`).
  - `redirect_http` (bool, optional, default `true`) – redirect HTTP to HTTPS instead of proxying plain HTTP.
  - `email` (string, required for `mode=letsencrypt`) – notification email for certificate issuance.
  - `staging` (bool, optional) – use the Let's Encrypt staging CA.
  - `cert_name` (string, optional) – override the certbot certificate name (defaults to primary domain).
- Creates an nginx vhost that proxies to the container IP+port and reloads nginx. Useful for dual-homed hosts or segmented container networks.
- Routes are tracked in `/var/lib/fortress/routes.json` and written to `/etc/nginx/sites-available` with symlinks in `/etc/nginx/sites-enabled`.
- Conflicting domains (including wildcard overlaps) return HTTP 409 with conflict details.
- Let's Encrypt mode requires port 80 reachability and certbot installed on the host.

#### `GET /routing` (permission `manage_routing`)
- Returns stored routing entries plus an `enabled` flag for the nginx symlink.

#### `POST /routing/refresh` (permission `manage_routing`, container scoped)
- Rebuilds nginx configs from stored routing entries to pick up updated container IPs.
- Optional query param `domain` to refresh a single routing entry (primary domain only).

#### `DELETE /routing/{domain}` (permission `manage_routing`, container scoped)
- Removes the nginx vhost for the given domain and reloads nginx.

#### `POST /tls/renew` (permission `manage_routing`)
Body:
```json
{
  "domain": "app.example.com",
  "dry_run": false
}
```
- Renews Let's Encrypt certificates via certbot.
- Provide `domain` to target a specific site/route; omit to renew all managed certs.
- Optional `cert_name` overrides the certbot cert name when needed.

### Website Management

#### `GET /sites` (permission `sites_read`)
- Returns a list of managed websites.

#### `POST /sites` (permission `sites_manage`)
Body:
```json
{
  "name": "app",
  "primary_domain": "app.example.com",
  "domains": ["www.app.example.com"],
  "container_name": "web01",
  "docroot": "/var/www/app",
  "runtime": {"php_version": "8.2", "php_ini_overrides": {"memory_limit": "256M"}},
  "database": {"engine": "mariadb", "name": "app_db", "username": "app_user", "password": "strong-secret", "root_password": "db-root"},
  "tls": {"mode": "manual", "cert_path": "/etc/ssl/certs/app.pem", "key_path": "/etc/ssl/private/app.key"}
}
```
- Creates the site record, configures routing/TLS, and provisions DB credentials when enabled (requires `database.password`).
- `database.root_password` is optional and used to provision DB users/databases when root authentication requires a password.
- When `runtime.php_ini_overrides` is provided, Fortress writes a per-site ini file inside the container and restarts PHP-FPM.
- `tls.mode=letsencrypt` provisions certificates via certbot (HTTP-01) and populates `cert_path`/`key_path` automatically (requires port 80 reachability and certbot installed).

#### `GET /sites/{site_id}` / `PUT /sites/{site_id}` / `DELETE /sites/{site_id}` (permission `sites_manage`)
- Retrieve, update, or remove a website definition.
- Updating `runtime.php_ini_overrides` rewrites the site ini override file and restarts PHP-FPM.

#### `POST /sites/{site_id}/deploy` (permission `sites_manage`)
Body:
```json
{
  "source_type": "git",
  "source": "https://github.com/example/app.git",
  "ref": "main",
  "restart_services": true
}
```
- Deploys code, runs optional post-deploy commands, and restarts services as requested.

#### `POST /sites/{site_id}/backup` (permission `sites_manage`)
- Creates a site-level backup (files plus optional database).

#### `POST /sites/{site_id}/rollback` (permission `sites_manage`)
- Restores a site from a prior backup id.

#### `GET /sites/{site_id}/logs` (permission `sites_read`)
- Query params: `service` (`apache|nginx|php-fpm|app`), `lines` (default `200`), optional `since` timestamp.

#### `GET /sites/{site_id}/health` (permission `sites_read`)
- Returns health check status and any failed checks.

#### `POST /sites/{site_id}/services/restart` (permission `sites_manage`)
- Restarts one or more site services (defaults to web + PHP-FPM).

### Container Lifecycle

#### `POST /container/create` (permission `manage_containers`, scoped to `name`)
Body fields (defaults shown):
- `name` (**required** string) – LXD container name.
- `distro` (string, default `ubuntu:lts`) – image alias to launch (`ubuntu:lts` resolves to the latest LTS available on the `ubuntu:` remote).
- `cpu_limit` (string, default `1`) – passed to `lxc config set limits.cpu`.
- `ram_limit` (string, default `512MB`).
- `disk_limit` (string, default `10GB`).

#### `GET /containers/images/popular` (permission `manage_containers`)
- Returns popular image presets, resolved aliases, availability on configured LXD remotes, and the latest Ubuntu LTS alias (if the `ubuntu:` remote is configured).

#### `POST /containers/images/popular` (permission `manage_containers`)
Body:
```json
{"name": "images:almalinux/9/cloud", "label": "AlmaLinux 9"}
```
- Adds or updates a preset (saved in `/var/lib/fortress/container_images.json`).

#### `POST /containers/images/popular/remove` (permission `manage_containers`)
Body:
```json
{"name": "images:almalinux/9/cloud"}
```
- Removes a preset entry.

#### `POST /containers/probe` (permission `manage_containers`, container scoped)
Body (example):
```json
{
  "container_name": "web01",
  "services": ["apache", "nginx", "mysql", "ftp", "filemanager"],
  "update_labels": true
}
```
- `container_name` (**required** string) – target container.
- `services` (array of strings, optional) – defaults to probing Apache, Nginx, MySQL/MariaDB, FTP, and file manager.
- `update_labels` (bool, optional, default `false`) – write `user.lizard.services` and `user.fortress.services` LXD labels from the detected services.
- Returns `services` (map), `available`, `missing`, and optional `label_value`.

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

### UI Admin (UI service)

The UI runs its own admin session cookie (see `FORTRESS_UI_ADMIN_SESSION_COOKIE`) and does not store tokens in the browser.

#### `POST /api/admin/bootstrap`
- Bootstraps the first UI admin account (only when no admins exist).

#### `POST /api/admin/login`
- Validates credentials (and optional TOTP) and returns session metadata (cookie-based auth).
- When TOTP is enabled for the admin, include `totp` in the request body.

#### `POST /api/admin/logout`
- Destroys the current UI admin session.

#### `GET /api/admin/session`
- Returns the active UI admin session details.

#### `GET /api/admin/users` / `POST /api/admin/users`
- Lists or creates UI admin accounts (session required).

#### `PUT /api/admin/users/{username}` / `DELETE /api/admin/users/{username}`
- Updates or removes a UI admin account (session required).

#### `POST /api/admin/totp/enroll`
- Starts TOTP enrollment for the signed-in admin and returns the secret + otpauth URL.

#### `POST /api/admin/totp/verify`
- Verifies a TOTP code to enable MFA for the signed-in admin.

#### `POST /api/admin/totp/disable`
- Disables TOTP for the signed-in admin (requires a valid code).

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

#### `GET /firewall/status`
- Returns firewall backend (`ufw`/`firewalld`), active state, defaults, and rule counts.

#### `GET /firewall/rules`
- Optional query params: `port`, `protocol`, `source`.

#### `POST /firewall/rules/apply`
Body:
```json
{
  "mode": "merge",
  "dry_run": false,
  "rules": [
    {"port": 443, "protocol": "tcp", "source": "203.0.113.0/24", "action": "allow"}
  ]
}
```
- Applies a bulk ruleset and returns a rollback id when changes are made.

#### `POST /firewall/rollback`
- Body: `{"rollback_id": "fw-20240301-120000"}`.

#### `GET /firewall/ddos` and `PUT /firewall/ddos`
- Manage anti-DDoS profiles (rate limits, connection caps, ban lists, allowlists) with safe rollback and observability. `conn_limit` uses iptables when available.

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
- Lists available recipes with dependency counts and parameter keys, plus lifecycle metadata (`version`, `history_count`, `updated_at`).

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
- New recipes are initialized with semantic version `1.0.0`, timestamps, and a change-history entry.

#### `POST /recipes/seed` (permission `recipes_manage`)
Body:
```json
{"bundle": "lamp", "overwrite": false}
```
- Seeds curated recipe bundles (for example, LAMP stack recipes) into `/var/lib/fortress/recipes.json`.
- With `overwrite=true`, existing recipes are updated with semantic version bumps and history entries.

#### `POST /recipes/export` (permission `recipes_manage`)
Body:
```json
{"names": ["lamp-apache"], "include_history": true, "include_signature": true}
```
- Exports recipes to a portable bundle payload (`format: fortress.recipe-bundle.v1`) for backup/transfer.
- Omitting `names` exports all recipes.
- Bundles include `checksum` by default; set `FORTRESS_RECIPE_BUNDLE_SIGNING_KEY` (active key) to enable HMAC signatures, and optionally `FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS` (comma-separated previous keys) for rotation-aware verification.

#### `POST /recipes/import` (permission `recipes_manage`)
Body:
```json
{
  "bundle": {
    "format": "fortress.recipe-bundle.v1",
    "checksum": "<sha256>",
    "signature": "<hmac-sha256>",
    "recipes": [
      {"name": "base-python", "packages": ["python3"], "version": "1.0.0"}
    ]
  },
  "overwrite": false,
  "preserve_history": true,
  "require_signature": true
}
```
- Imports recipe bundles with dependency/cycle validation.
- `overwrite=true` replaces existing definitions; `preserve_history=false` resets imported history to a single import event.
- `require_signature=true` enforces signature verification; use `false` only for trusted unsigned bundles.
- Signature verification checks the active key first, then any keys provided in `FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS`.

#### `PUT /recipes/{name}` (permission `recipes_manage`)
- Updates the recipe fields you provide; send empty arrays to clear lists.
- Optional payload fields: `version_bump` (`major|minor|patch|none`, default `patch`) and `change_note` for history entries.

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
  "update_index": true,
  "dry_run": false,
  "probe_services": true
}
```
- Applies dependencies first, then installs packages and runs commands for each recipe in order.
- Use `{{app_user}}` inside commands/packages to parameterize installs.
- Response includes a deterministic `plan` list plus optional `probe` results when service checks are enabled.
- LAMP recipes additionally include `probe.health_checks` with structured `service_status`, `port_probe`, and `config_validation` results plus pass/fail/skipped summary counters.

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

#### `POST /recipes/plan` (permission `recipes_apply`)
- Same body as `/recipes/apply`; returns the ordered plan without executing commands.

### Backup & Restore

#### `POST /backup/{container_name}` (permission `manage_backups`, scoped)
- Path parameter `container_name`; no body. Starts encrypted backup task.

#### `GET /backup/list` (permission `manage_backups`)
- Returns `{ "backups": ["container_20240101.tar.gz.enc", ...] }`.

#### `GET /backup/download/{filename}` (permission `manage_backups`)
- Streams the encrypted archive bytes; combine with `fortress-cli backup download`.

#### `POST /restore` (permission `restore_container`, scoped)
- Query parameter `container_name` and multipart form body containing `file` (encrypted `.enc` upload). The service decrypts with the server-side Fernet key and runs `lxc import`.

### Migrations & Upgrades (permission `migration_admin`)

#### `GET /migrations/status`
- Returns schema versions per JSON store and whether migrations are pending.

#### `POST /migrations/plan`
Body (optional):
```json
{"stores": ["api_users", "recipes"], "dry_run": true}
```
- Computes a change plan without writing files.

#### `POST /migrations/apply`
- Applies pending migrations, emits a patch id, and records backups.

#### `POST /migrations/rollback`
- Body: `{"patch_id": "patch-20240301-120000", "dry_run": false}`.

#### `GET /migrations/ledger`
- Lists applied patches with timestamps and backup references.

#### `POST /system/upgrade` (permission `migration_admin` + `package_manage`)
Body:
```json
{
  "update_packages": true,
  "full_upgrade": false,
  "apply_migrations": true,
  "dry_run": false
}
```
- Performs a host package update and then applies pending migrations in one call.
- Set `dry_run=true` to preview the package command and migration plan without changes.

### Command Register & Auditing
- Every API call records an immutable entry into `command_log.db` (see `COMMAND_LOG_DB`), capturing `actor`, endpoint, action, target, and sanitized payload details.
- Internal behaviours such as `lxc exec` commands are also logged with command metadata (sensitive arguments are redacted) so operators can trace suspicious cross-container activity.
- The register lives alongside other Fortress state under `/var/lib/fortress`; query it via `sqlite3 /var/lib/fortress/command_log.db 'select * from command_log order by id desc limit 20;'`.

## Deployment Notes

- Server listens via uvicorn (`HOST_INTERFACE`, `HOST_PORT`). For production, terminate TLS via web server or provide `ssl_keyfile`/`ssl_certfile`.
- Set filesystem paths (`BACKUP_DIR`, `NGINX_CONFIG_DIR`, `API_USERS_DB`, `RECIPES_DB`, `SHARED_STORAGE_DIR`) to match your host.
- Migration schemas default to `./schemas`; override with `FORTRESS_SCHEMA_DIR` if you relocate them.
- Site backups default to `/var/lib/fortress/site_backups`; ensure the service user can read/write.
- Configure secrets via env vars (`FORTRESS_API_KEY`, `FORTRESS_BACKUP_PASSWORD`) instead of hardcoding defaults.
- Configure `FORTRESS_RECIPE_BUNDLE_SIGNING_KEY` as the active signing key for recipe exports; optional `FORTRESS_RECIPE_BUNDLE_SIGNING_KEYS` supports signature verification during key rotation.
- Optional runtime paths: `FORTRESS_LOG_PATH` overrides the API log file target and `FORTRESS_COMMAND_LOG_DB` overrides the SQLite audit DB path.
- ACME HTTP-01 challenges are served from `/var/lib/fortress/acme-challenges`; override via `FORTRESS_ACME_CHALLENGE_DIR`.
- Ensure the runtime user has permission to run `lxc`, manage firewall (`ufw` or `firewall-cmd`), manage nginx reloads, invoke `certbot`, and run package commands (`apt-get`, `dnf`, or `yum`).

## Client CLI (`fortress-cli.py`)

`fortress-cli.py` is a companion script that securely stores API credentials, automates the HTTPS calls to the server, and handles encrypted backup archives.

Common helpers include `recipes *`, `sites *`, `migrations *`, `system upgrade`, and `tls renew` for one-command maintenance flows.

1. Run `python fortress-cli.py setup --server https://fortress.example.com:8443` to generate a 4096‑bit RSA keypair (protected by a passphrase) and enter the API master key, delegated user token, and/or backup password. Everything is saved under `~/.fortress-cli` (override via `FORTRESS_HOME`).
2. Subsequent commands unlock the private key (either interactively or via `--passphrase`/`FORTRESS_PASSPHRASE`) and reuse the stored credentials:
   - `python fortress-cli.py status` → GET `/status`
   - `python fortress-cli.py call POST /packages/install --json '{"packages":["vim"]}'`
   - `python fortress-cli.py backup list|trigger|download|decrypt ...`
   - `python fortress-cli.py api-users create alice --permissions manage_containers read_status`
   - `python fortress-cli.py recipes list|create|apply ...`
   - `python fortress-cli.py recipes seed|plan|export|import ...`
   - `python fortress-cli.py firewall status|rules|apply|rollback|ddos ...`
   - `python fortress-cli.py sites list|create|deploy|backup|rollback|logs|health|restart ...`
   - `python fortress-cli.py migrations status|plan|apply|rollback|ledger ...`
3. Encrypted backups can be downloaded and decrypted locally via `python fortress-cli.py backup download foo.enc --dest ./foo.enc` followed by `python fortress-cli.py backup decrypt ./foo.enc --output ./foo.tar.gz`.

Recipe CLI examples:
- Create a recipe: `python fortress-cli.py recipes create --name base-python --package python3 --package python3-pip`
- Apply to a container: `python fortress-cli.py recipes apply base-python --container web01`
- Seed LAMP bundle: `python fortress-cli.py recipes seed lamp`
- LAMP PHP version: `python fortress-cli.py recipes apply lamp-apache --container web01 --param php_version=8.2`
- LAMP params: `python fortress-cli.py recipes apply lamp-mysql --container web01 --param db_name=app_db --param db_user=app_user --param db_password=strong-pass --param db_root_password=admin-pass`
- Dry-run plan: `python fortress-cli.py recipes plan app-bootstrap --container web01`
- Export recipes: `python fortress-cli.py recipes export --name lamp-stack`
- Import recipes: `python fortress-cli.py recipes import --bundle-file ./recipes-bundle.json --overwrite`
- Export unsigned bundle (only if needed): `python fortress-cli.py recipes export --name lamp-stack --no-signature`
- Import unsigned bundle (trusted sources only): `python fortress-cli.py recipes import --bundle-file ./recipes-bundle.json --allow-unsigned`

By default TLS certificates are verified; pass `--insecure` during `setup` only if you are pointing at a self-signed lab server. Use the CLI’s `info` command to inspect the stored metadata without revealing secrets.

## Testing

- `python -m unittest discover -s tests`
- `python -m unittest discover -s tests -p 'test_permissions_matrix.py'` for route-level permission matrix checks.
- Permission matrix coverage includes recipes, system upgrade, routing, sites, and firewall endpoint sequences.

## Roadmap

See `ROADMAP.md` for the detailed development paths and sequencing.
