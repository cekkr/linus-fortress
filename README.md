# linus-fortress

Linus' Fortress is a FastAPI service that centralizes automation for LXD-based VPS deployments: container lifecycle, routing, encrypted backups, delegated API users, security hardening, and now firewall plus package orchestration for both Ubuntu (`apt`) and AlmaLinux (`dnf`) style hosts.

## Authentication

- `X-API-Key`: master key with unrestricted access (set `API_SECRET_KEY` in `py/server.py` or better via env vars).
- `X-User-Token`: delegated token created via `/api-users` endpoints. Each token carries its own permissions (`manage_containers`, `manage_routing`, `access_control`, `user_management`, `connectivity`, `manage_backups`, `restore_container`, `api_user_admin`, `firewall_admin`, `package_manage`, `read_status`) and optional `allowed_containers` scope.
- Either header grants access; if both are provided the master key takes precedence. Tokens scoped to containers must match the container(s) referenced by the request payload.

## API Reference

### Status and Routing
- `GET /status` – returns RAM, disk, and container list (requires `read_status`).
- `POST /routing/add` – builds an Nginx reverse proxy for a container IP (requires `manage_routing`).

### Container Lifecycle
- `POST /container/create` – launch LXD container with CPU/RAM limits (requires `manage_containers` plus scope).
- `DELETE /container/{name}` – stop and remove container (requires `manage_containers` plus scope).

### API Users
- `POST /api-users` – create delegated token, returns generated token string (requires `api_user_admin`).
- `GET /api-users` – list all delegated tokens (requires `api_user_admin`).
- `PUT /api-users/{token}` – adjust permissions or container scopes (requires `api_user_admin`).
- `DELETE /api-users/{token}` – revoke a token (requires `api_user_admin`).

### External Access + Users Inside Containers
- `POST /access/external/open` – expose container SSH/FTP via LXD proxy devices (requires `access_control`).
- `POST /access/external/close` – remove proxy device (requires `access_control`).
- `POST /container/users/create` – add Unix user inside container with optional groups/password (requires `user_management`).
- `POST /container/users/password` – change container user password (requires `user_management`).
- `POST /container/users/groups` – update user group memberships (requires `user_management`).
- `DELETE /container/users` – remove user, optional home removal (requires `user_management`).
- `POST /container/groups` – ensure group exists (requires `user_management`).

### Container Connectivity
- `POST /containers/connect/tcp` – create LXD proxy from one container to another (requires `connectivity`).
- `POST /containers/connect/tcp/remove` – delete proxy device (requires `connectivity`).
- `POST /containers/connect/share` – mount shared host storage into multiple containers (requires `connectivity`).
- `POST /containers/connect/share/remove` – detach shared mount (requires `connectivity`).

### Backup & Restore
- `POST /backup/{container_name}` – start encrypted backup in background (requires `manage_backups` plus scope).
- `GET /backup/list` – list encrypted archives (requires `manage_backups`).
- `GET /backup/download/{filename}` – download encrypted archive (requires `manage_backups`).
- `POST /restore` – decrypt uploaded archive and import into LXD (requires `restore_container` plus scope).

### Firewall Management (Ubuntu + AlmaLinux)
- `POST /firewall/open` – open a port via UFW or firewalld, optionally restricted to a source CIDR (requires `firewall_admin`).
- `POST /firewall/close` – remove the rule/port so access is closed (requires `firewall_admin`).

### Package Management (apt + dnf)
- `POST /packages/install` – install packages on host or on a scoped container (`container_name` optional). Handles `apt-get` and `dnf` with optional `update_index` step (requires `package_manage`).
- `POST /packages/remove` – remove packages on host or container (`package_manage`).
- `POST /packages/update` – run upgrade/update (set `full_upgrade=true` for `apt dist-upgrade` / `dnf upgrade`) on host or container (`package_manage`).

### Command Register & Auditing
- Every API call records an immutable entry into `command_log.db` (see `COMMAND_LOG_DB`), capturing `actor`, endpoint, action, target, and sanitized payload details.
- Internal behaviours such as `lxc exec` commands are also logged with command metadata (sensitive arguments are redacted) so operators can trace suspicious cross-container activity.
- The register lives alongside other Fortress state under `/var/lib/fortress`; query it via `sqlite3 /var/lib/fortress/command_log.db 'select * from command_log order by id desc limit 20;'`.

## Deployment Notes

- Server listens via uvicorn (`HOST_INTERFACE`, `HOST_PORT`). For production, terminate TLS via web server or provide `ssl_keyfile`/`ssl_certfile`.
- Set filesystem paths (`BACKUP_DIR`, `NGINX_CONFIG_DIR`, `API_USERS_DB`, `SHARED_STORAGE_DIR`) to match your host.
- Ensure the runtime user has permission to run `lxc`, manage firewall (`ufw` or `firewall-cmd`), and package commands (`apt-get` or `dnf`).

## Roadmap

- Split `py/server.py` into modular packages (auth, containers, storage) for maintainability.
- Add automated tests or contract tests for each API route.
