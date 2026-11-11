// Deterministic, read-only stub of the Fortress API used to render Lizard UI with
// realistic demo data (screenshots, local demos). It never touches the host: every
// mutating request is acknowledged without side effects. All names, domains, and
// addresses are documentation placeholders (example.com, 192.0.2.0/24, 10.0.0.0/8).
import { createServer } from "node:http";

const NOW = "2026-11-11T09:30:00Z";

function lxcContainer(name, status, ip, extra = {}) {
  return {
    name,
    status,
    type: "container",
    architecture: "x86_64",
    state: {
      status,
      network:
        status === "Running"
          ? { eth0: { addresses: [{ family: "inet", address: ip }, { family: "inet6", address: "fd42::1" }] } }
          : {},
    },
    config: extra.config || {},
    expanded_config: {},
  };
}

export function buildDemoData() {
  const containers = [
    lxcContainer("lamp-shop", "Running", "10.42.0.11", {
      config: { "user.lizard.stack": "lamp", "user.lizard.services": "apache,mysql,ftp,filemanager" },
    }),
    lxcContainer("api-gateway", "Running", "10.42.0.12"),
    lxcContainer("worker-queue", "Running", "10.42.0.13"),
    lxcContainer("staging-blog", "Stopped", null, {
      config: { "user.lizard.stack": "lamp", "user.lizard.services": "apache,mysql" },
    }),
  ];

  const routes = [
    {
      domain: "shop.example.com",
      aliases: ["www.shop.example.com"],
      enabled: true,
      container_name: "lamp-shop",
      container_port: 80,
      container_ip: "10.42.0.11",
      listen_address: "0.0.0.0",
      listen_port: 80,
      tls: { mode: "letsencrypt", listen_port: 443, redirect_http: true },
    },
    {
      domain: "api.example.com",
      aliases: [],
      enabled: true,
      container_name: "api-gateway",
      container_port: 8080,
      container_ip: "10.42.0.12",
      listen_address: "0.0.0.0",
      listen_port: 80,
      tls: { mode: "manual", listen_port: 443 },
    },
    {
      domain: "*.preview.example.com",
      aliases: [],
      enabled: false,
      container_name: "staging-blog",
      container_port: 80,
      listen_address: "0.0.0.0",
      listen_port: 8081,
      tls: { mode: "none" },
    },
  ];

  const recipes = [
    { name: "lamp-stack", description: "Apache + PHP-FPM + MariaDB + FTP + file manager", version: "1.4.0", dependencies_count: 4, packages_count: 9, commands_count: 6, parameter_keys: ["php_version", "db_name", "db_user"] },
    { name: "lamp-apache", description: "Apache with PHP-FPM handler", version: "1.2.1", dependencies_count: 0, packages_count: 4, commands_count: 2, parameter_keys: ["php_version"] },
    { name: "lamp-mysql", description: "MariaDB server with root bootstrap", version: "1.1.0", dependencies_count: 0, packages_count: 2, commands_count: 2, parameter_keys: ["db_root_password", "db_name"] },
    { name: "baseline-hardening", description: "unattended-upgrades, fail2ban, sshd baseline", version: "0.3.2", dependencies_count: 0, packages_count: 3, commands_count: 4, parameter_keys: [] },
  ];

  const healthSeries = [0, 0, 1, 0, 0, 2, 0, 0, 0, 1, 0, 0].map((failed, index) => ({
    timestamp: `2026-11-${String(index + 1).padStart(2, "0")}T08:00:00Z`,
    passed: 14 - failed,
    failed,
    skipped: 1,
  }));
  const recipeHealthHistory = {
    entries: [
      { requested_recipe: "lamp-stack", timestamp: "2026-11-11T08:00:00Z", summary: { passed: 14, failed: 0, skipped: 1 } },
      { requested_recipe: "lamp-stack", timestamp: "2026-11-10T08:00:00Z", summary: { passed: 13, failed: 1, skipped: 1 } },
      { requested_recipe: "lamp-apache", timestamp: "2026-11-09T08:00:00Z", summary: { passed: 6, failed: 0, skipped: 0 } },
    ],
    trend: {
      runs: healthSeries.length,
      failed_runs: healthSeries.filter((item) => item.failed > 0).length,
      pass_rate: 75,
      totals: { passed: 164, failed: 4, skipped: 12 },
      series: healthSeries,
    },
  };

  const monitoring = {
    host: { cpu_percent: 41.6, memory_percent: 63.2, disk_percent: 48.9, load_average: [0.82, 0.71, 0.66] },
    containers: {
      "lamp-shop": { cpu_percent: 23.4, memory_percent: 45.1, disk_percent: 41.0, process_count: 61 },
      "api-gateway": { cpu_percent: 12.9, memory_percent: 31.8, disk_percent: 22.4, process_count: 18 },
      "worker-queue": { cpu_percent: 87.2, memory_percent: 52.7, disk_percent: 35.6, process_count: 24 },
    },
    alerts: {
      host: [],
      containers: { "lamp-shop": [], "api-gateway": [], "worker-queue": ["cpu_percent above 85"] },
    },
    anomalies: { containers: { "worker-queue": ["cpu delta spike"] } },
    history_samples: [28, 31, 35, 33, 38, 44, 40, 37, 42, 41.6].map((cpu) => ({ host: { cpu_percent: cpu } })),
  };

  const firewallRules = [
    { action: "allow", port: "22", protocol: "tcp", source: "10.0.0.0/8", interface: "eth0" },
    { action: "allow", port: "80", protocol: "tcp", source: "any", interface: "eth0" },
    { action: "allow", port: "443", protocol: "tcp", source: "any", interface: "eth0" },
    { action: "allow", port: "8443", protocol: "tcp", source: "192.0.2.0/24", interface: "eth0" },
    { action: "deny", port: "23", protocol: "tcp", source: "any", interface: "eth0" },
  ];

  const hosts = [
    { name: "edge-01", ssh_host: "192.0.2.11", ssh_port: 22, username: "fortress", installed: true, os_type: "ubuntu", last_probe: { ok: true, at: NOW } },
    { name: "edge-02", ssh_host: "192.0.2.12", ssh_port: 22, username: "fortress", installed: false, os_type: "almalinux" },
  ];

  const vms = [
    { name: "alma-lab", provider: "qemu", status: "running", profile: "fedora", memory_mb: 4096, cpus: 2, disk_gb: 30, snapshots: ["clean-install", "pre-upgrade"] },
    { name: "ubuntu-lab", provider: "qemu", status: "stopped", profile: "ubuntu", memory_mb: 2048, cpus: 2, disk_gb: 20, snapshots: ["boot"] },
  ];

  const sites = [
    { id: "shop", primary_domain: "shop.example.com", container_name: "lamp-shop", status: "active" },
    { id: "blog", primary_domain: "blog.example.com", container_name: "staging-blog", status: "inactive" },
  ];
  const siteDetails = {
    shop: {
      id: "shop",
      primary_domain: "shop.example.com",
      domains: ["www.shop.example.com"],
      container_name: "lamp-shop",
      status: "active",
      docroot: "/var/www/shop/public",
      runtime: { php_version: "8.3", fpm_pool: { pm: "dynamic", max_children: 12 } },
      routing: { listen_address: "0.0.0.0", listen_port: 80, container_interface: "eth0", container_port: 80 },
      tls: { mode: "letsencrypt", cert_name: "shop.example.com" },
      tls_status: { status: "valid", expires_at: "2027-01-20T00:00:00Z", days_remaining: 70 },
      database: { engine: "mariadb", name: "shop", username: "shop_app", password: "********" },
    },
    blog: {
      id: "blog",
      primary_domain: "blog.example.com",
      domains: [],
      container_name: "staging-blog",
      status: "inactive",
      docroot: "/var/www/html",
      runtime: { php_version: "8.2" },
      routing: { listen_address: "0.0.0.0", listen_port: 8081, container_interface: "eth0", container_port: 80 },
      tls: { mode: "none" },
      database: {},
    },
  };
  const siteBackups = {
    shop: [
      { backup_id: "shop-20261111-0400", created_at: "2026-11-11T04:00:00Z", include_database: true, label: "nightly" },
      { backup_id: "shop-20261110-0400", created_at: "2026-11-10T04:00:00Z", include_database: true, label: "nightly" },
    ],
    blog: [{ backup_id: "blog-20261101-1200", created_at: "2026-11-01T12:00:00Z", include_database: false }],
  };

  const images = {
    images: [
      { name: "ubuntu:lts", label: "Ubuntu (latest LTS)", resolved_name: "ubuntu:24.04", available: true, remote: "ubuntu", source: "lxd-cli" },
      { name: "debian:12", label: "Debian 12", resolved_name: "images:debian/12/cloud", available: true, remote: "images", source: "lxd-cli" },
      { name: "images:almalinux/9/cloud", label: "AlmaLinux 9 (cloud)", resolved_name: "images:almalinux/9/cloud", available: true, remote: "images", source: "lxd-cli" },
      { name: "images:fedora/41/cloud", label: "Fedora 41 (cloud)", resolved_name: "images:fedora/41/cloud", available: true, remote: "images", source: "lxd-cli" },
      { name: "images:alpine/3.20", label: "Alpine 3.20", resolved_name: "images:alpine/3.20", available: false, remote: "images", source: "lxd-cli", reason: "not published for this architecture" },
    ],
    remotes: ["ubuntu", "images"],
    latest: { ubuntu_lts: "ubuntu:24.04" },
    refreshed_at: NOW,
  };

  return { containers, routes, recipes, recipeHealthHistory, monitoring, firewallRules, hosts, vms, sites, siteDetails, siteBackups, images };
}

function jsonResponse(res, payload, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

export function startDemoApi(port, options = {}) {
  const data = buildDemoData();
  const unmatched = new Set();
  const server = createServer((req, res) => {
    const url = new URL(req.url || "/", `http://127.0.0.1:${port}`);
    const raw = url.pathname;
    const p = raw.length > 1 && raw.endsWith("/") ? raw.slice(0, -1) : raw;
    const method = req.method || "GET";
    // Drain bodies; the demo API never acts on them.
    req.resume();

    if (p === "/status") return jsonResponse(res, { status: "ok", containers: data.containers });
    if (p === "/containers/images/popular" && method === "GET") return jsonResponse(res, data.images);
    if (p === "/routing") return jsonResponse(res, { routes: data.routes });
    if (p === "/recipes" && method === "GET") return jsonResponse(res, { recipes: data.recipes });
    if (p === "/recipes/health-history") return jsonResponse(res, data.recipeHealthHistory);
    if (p === "/monitoring/resources") return jsonResponse(res, data.monitoring);
    if (p === "/firewall/status") return jsonResponse(res, { backend: "ufw", active: true, default_incoming: "deny" });
    if (p === "/firewall/rules") return jsonResponse(res, { backend: "ufw", rules: data.firewallRules });
    if (p === "/firewall/rules/diff") return jsonResponse(res, { added: [], removed: [], unchanged: data.firewallRules });
    if (p === "/firewall/ddos") return jsonResponse(res, { enabled: true, profile: "standard", conn_limit: 80, allowlist: ["10.0.0.0/8"] });
    if (p === "/hosts") return jsonResponse(res, { hosts: data.hosts });
    if (p === "/vms") return jsonResponse(res, { vms: data.vms });
    if (p === "/sites") return jsonResponse(res, { sites: data.sites });
    if (/^\/sites\/[^/]+\/backups$/.test(p)) {
      const id = decodeURIComponent(p.split("/")[2]);
      return jsonResponse(res, { backups: data.siteBackups[id] || [] });
    }
    if (/^\/sites\/[^/]+\/tls\/status$/.test(p)) {
      const id = decodeURIComponent(p.split("/")[2]);
      return jsonResponse(res, (data.siteDetails[id] || {}).tls_status || { status: "none" });
    }
    if (/^\/sites\/[^/]+$/.test(p)) {
      const id = decodeURIComponent(p.split("/")[2]);
      const site = data.siteDetails[id];
      return jsonResponse(res, site ? { site } : { error: "not found" }, site ? 200 : 404);
    }
    if (/^\/containers\/[^/]+\/snapshots$/.test(p)) {
      return jsonResponse(res, { snapshots: ["pre-deploy", "nightly-2026-11-10"] });
    }
    if (p === "/containers/probe") {
      return jsonResponse(res, { services: { apache: true, mysql: true, ftp: true, filemanager: true } });
    }
    if (p === "/migrations/status") return jsonResponse(res, { stores: {}, pending: [] });
    if (p === "/backup/list") return jsonResponse(res, { backups: [] });
    if (p === "/api-users") return jsonResponse(res, { users: [] });

    if (method !== "GET") {
      return jsonResponse(res, { message: "demo API: request acknowledged, nothing changed" });
    }
    unmatched.add(`${method} ${p}`);
    if (options.onUnmatched) {
      options.onUnmatched(`${method} ${p}`);
    }
    return jsonResponse(res, { error: "not available in demo API" }, 404);
  });

  return new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", () => resolve({ server, unmatched }));
    server.on("error", reject);
  });
}
