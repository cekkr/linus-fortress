const state = {
  nodes: [],
  nodesById: new Map(),
  rootId: "home",
  selectedId: null,
  containers: [],
  containerIndex: new Map(),
  monitoring: null,
  monitoringLoading: false,
  firewall: { backend: null, rules: [] },
  firewallLoading: false,
  vms: [],
  vmsLoading: false,
  routes: [],
  routesLoading: false,
  recipes: [],
  recipesLoading: false,
  hosts: [],
  hostsLoading: false,
  fortress: { status: "unknown" },
  auth: {
    active: false,
    mode: "none",
    session: false,
  },
  admin: {
    active: false,
    username: null,
    bootstrapRequired: false,
    tokenSession: false,
    bootstrapNotified: false,
    storePath: null,
    error: null,
  },
  events: [],
  probedContainers: new Set(),
  probeInFlight: false,
  wizard: {
    active: false,
    mode: null,
    step: 0,
    busy: false,
    error: null,
    context: {
      container: null,
    },
    form: {
      name: "",
      distro: "ubuntu:22.04",
      cpu_limit: "1",
      ram_limit: "512MB",
      disk_limit: "10GB",
    },
    routing: {
      domain: "",
      container_name: "",
      container_port: "80",
      container_interface: "eth0",
      listen_address: "0.0.0.0",
      listen_port: "80",
      tls_mode: "manual",
      cert_path: "",
      key_path: "",
      chain_path: "",
      tls_port: "443",
      redirect_http: true,
      tls_email: "",
      tls_staging: false,
    },
    packages: {
      mode: "install",
      target: "",
      packages: "",
      update_index: true,
      full_upgrade: false,
    },
    recipe: {
      name: "",
      target: "",
      parameters: "",
      dry_run: false,
      include_dependencies: true,
      update_index: true,
    },
    network: {
      container_name: "",
      protocol: "tcp",
      bind_address: "0.0.0.0",
      host_port: "",
      container_port: "",
      target_interface: "eth0",
      target_address: "",
      open_firewall: true,
    },
    firewall: {
      mode: "open",
      port: "",
      protocol: "tcp",
      source: "",
    },
    host: {
      name: "",
      host: "",
      username: "",
      port: "22",
      key_path: "",
      password: "",
      os_type: "",
      notes: "",
    },
    filemanager: {
      username: "",
      password: "",
      install_path: "/var/www/html/filemanager",
    },
  },
};

const elements = {
  tree: document.getElementById("tree"),
  grid: document.getElementById("app-grid"),
  preview: document.getElementById("preview"),
  wizard: document.getElementById("wizard"),
  eventLog: document.getElementById("event-log"),
  breadcrumb: document.getElementById("breadcrumb"),
  statusLine: document.getElementById("status-line"),
  fortressStatus: document.getElementById("fortress-status"),
  authOverlay: document.getElementById("auth-overlay"),
  authForm: document.getElementById("auth-form"),
  authToken: document.getElementById("auth-token"),
  authMessage: document.getElementById("auth-message"),
  adminOverlay: document.getElementById("admin-overlay"),
  adminSubtitle: document.getElementById("admin-subtitle"),
  adminForm: document.getElementById("admin-form"),
  adminUsername: document.getElementById("admin-username"),
  adminPassword: document.getElementById("admin-password"),
  adminTotp: document.getElementById("admin-totp"),
  adminBootstrapForm: document.getElementById("admin-bootstrap-form"),
  adminBootstrapUsername: document.getElementById("admin-bootstrap-username"),
  adminBootstrapPassword: document.getElementById("admin-bootstrap-password"),
  adminBootstrapConfirm: document.getElementById("admin-bootstrap-confirm"),
  adminMessage: document.getElementById("admin-message"),
  adminBootstrapButton: document.getElementById("admin-bootstrap"),
  logoutButton: document.getElementById("logout"),
};

const iconMap = {
  compass: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="9"></circle>
      <path d="M9 15l6-6"></path>
      <path d="M10 10l4 4"></path>
    </svg>
  `,
  cube: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z"></path>
      <path d="M12 12l8-4.5"></path>
      <path d="M12 12L4 7.5"></path>
    </svg>
  `,
  crate: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <rect x="4" y="4" width="16" height="16" rx="2"></rect>
      <path d="M4 9h16"></path>
      <path d="M9 4v16"></path>
    </svg>
  `,
  pulse: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M3 12h4l2-5 4 10 2-5h4"></path>
    </svg>
  `,
  link: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M9 7h-2a4 4 0 000 8h2"></path>
      <path d="M15 7h2a4 4 0 010 8h-2"></path>
      <path d="M8 12h8"></path>
    </svg>
  `,
  radar: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="8"></circle>
      <path d="M12 12l5-5"></path>
      <path d="M12 4v8"></path>
    </svg>
  `,
  stack: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4 7l8-4 8 4-8 4-8-4z"></path>
      <path d="M4 12l8 4 8-4"></path>
      <path d="M4 16l8 4 8-4"></path>
    </svg>
  `,
  wand: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M4 20l10-10"></path>
      <path d="M15 5l2-2"></path>
      <path d="M18 8l2-2"></path>
      <path d="M12 2l2 2"></path>
    </svg>
  `,
  vault: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <rect x="3" y="3" width="18" height="18" rx="2"></rect>
      <circle cx="12" cy="12" r="3"></circle>
      <path d="M12 9v6"></path>
    </svg>
  `,
  shield: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3l7 4v5c0 4.2-3 7.6-7 9-4-1.4-7-4.8-7-9V7l7-4z"></path>
    </svg>
  `,
  route: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="6" cy="6" r="2"></circle>
      <circle cx="18" cy="18" r="2"></circle>
      <path d="M7.5 7.5c3 3 6 6 8.5 8.5"></path>
    </svg>
  `,
  tower: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <rect x="8" y="3" width="8" height="18"></rect>
      <path d="M5 21h14"></path>
    </svg>
  `,
  hex: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M7 4h10l5 8-5 8H7l-5-8 5-8z"></path>
    </svg>
  `,
  lamp: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M8 18h8"></path>
      <path d="M9 21h6"></path>
      <path d="M6 10a6 6 0 0112 0c0 2-1 3-2 4-1 1-1 2-1 3H9c0-1 0-2-1-3-1-1-2-2-2-4z"></path>
    </svg>
  `,
  server: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <rect x="4" y="4" width="16" height="6" rx="2"></rect>
      <rect x="4" y="14" width="16" height="6" rx="2"></rect>
      <path d="M8 7h.01"></path>
      <path d="M8 17h.01"></path>
    </svg>
  `,
  globe: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="9"></circle>
      <path d="M3 12h18"></path>
      <path d="M12 3c2.8 3 2.8 15 0 18"></path>
      <path d="M12 3c-2.8 3-2.8 15 0 18"></path>
    </svg>
  `,
  database: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <ellipse cx="12" cy="5" rx="7" ry="3"></ellipse>
      <path d="M5 5v10c0 1.7 3.1 3 7 3s7-1.3 7-3V5"></path>
      <path d="M5 10c0 1.7 3.1 3 7 3s7-1.3 7-3"></path>
    </svg>
  `,
  transfer: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M7 7h8"></path>
      <path d="M7 7l3-3"></path>
      <path d="M7 7l3 3"></path>
      <path d="M17 17h-8"></path>
      <path d="M17 17l-3-3"></path>
      <path d="M17 17l-3 3"></path>
    </svg>
  `,
  folder: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M3 7h7l2 2h9v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"></path>
    </svg>
  `,
  lock: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <rect x="6" y="11" width="12" height="9" rx="2"></rect>
      <path d="M8 11V8a4 4 0 018 0v3"></path>
    </svg>
  `,
};

function buildRecipeDefinition(name, description, commands, dependencies = []) {
  return {
    name,
    description,
    dependencies,
    packages: [],
    commands,
    parameters: {},
    required_parameters: [],
  };
}

const FILEMANAGER_COMMAND = [
  "FM_DIR=\"/var/www/html/filemanager\"",
  "FM_FILE=\"$FM_DIR/index.php\"",
  "mkdir -p \"$FM_DIR\"",
  "curl -fsSL https://raw.githubusercontent.com/prasathmani/tinyfilemanager/master/tinyfilemanager.php -o \"$FM_FILE\"",
  "FM_USER=\"{{fm_user}}\" FM_PASS=\"{{fm_password}}\" FM_FILE=\"$FM_FILE\" php -r '$file=getenv(\"FM_FILE\"); $user=getenv(\"FM_USER\"); $pass=getenv(\"FM_PASS\"); $hash=password_hash($pass, PASSWORD_DEFAULT); $u=addcslashes($user, \"\\\\\\\"\\\\$\"); $h=addcslashes($hash, \"\\\\\\\"\\\\$\"); $replacement=\"\\$auth_users = array(\\\"{$u}\\\" => \\\"{$h}\\\");\"; $pattern=\"/\\\\\\$auth_users\\\\s*=\\\\s*array\\\\(.*?\\\\);/s\"; $content=file_get_contents($file); $content=preg_replace_callback($pattern, function() use ($replacement) { return $replacement; }, $content, 1, $count); if ($count===0){$content=\"<?php\\\\n\".$replacement.\"\\\\n?>\\\\n\".$content;} file_put_contents($file, $content);'",
].join(" && ");

const LAMP_STACK_NAME = "lamp-stack";
const LAMP_STACK_DEPENDENCIES = ["lamp-apache", "lamp-mysql", "lamp-ftp", "lamp-filemanager"];

const RECIPE_CATALOG = {
  "lamp-apache": buildRecipeDefinition(
    "lamp-apache",
    "Install Apache and PHP runtime.",
    [
      "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 apache2-utils libapache2-mod-php php php-cli php-mysql php-curl php-xml php-zip php-mbstring; systemctl enable --now apache2 >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y httpd httpd-tools php php-cli php-mysqlnd php-xml php-gd php-mbstring; systemctl enable --now httpd >/dev/null 2>&1 || true; elif command -v yum >/dev/null 2>&1; then yum makecache && yum install -y httpd httpd-tools php php-cli php-mysqlnd php-xml php-gd php-mbstring; systemctl enable --now httpd >/dev/null 2>&1 || true; fi",
    ]
  ),
  "lamp-nginx": buildRecipeDefinition(
    "lamp-nginx",
    "Install Nginx with PHP-FPM.",
    [
      "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y nginx php-fpm php-cli php-mysql php-curl php-xml php-zip php-mbstring; systemctl enable --now nginx php-fpm >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y nginx php-fpm php-cli php-mysqlnd php-xml php-gd php-mbstring; systemctl enable --now nginx php-fpm >/dev/null 2>&1 || true; elif command -v yum >/dev/null 2>&1; then yum makecache && yum install -y nginx php-fpm php-cli php-mysqlnd php-xml php-gd php-mbstring; systemctl enable --now nginx php-fpm >/dev/null 2>&1 || true; fi",
    ]
  ),
  "lamp-mysql": buildRecipeDefinition(
    "lamp-mysql",
    "Install MariaDB or MySQL engine.",
    [
      "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client; systemctl enable --now mariadb >/dev/null 2>&1 || systemctl enable --now mysql >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y mariadb-server mariadb; systemctl enable --now mariadb >/dev/null 2>&1 || true; elif command -v yum >/dev/null 2>&1; then yum makecache && yum install -y mariadb-server mariadb; systemctl enable --now mariadb >/dev/null 2>&1 || true; fi",
    ]
  ),
  "lamp-ftp": buildRecipeDefinition(
    "lamp-ftp",
    "Install vsftpd for legacy FTP.",
    [
      "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd; systemctl enable --now vsftpd >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y vsftpd; systemctl enable --now vsftpd >/dev/null 2>&1 || true; elif command -v yum >/dev/null 2>&1; then yum makecache && yum install -y vsftpd; systemctl enable --now vsftpd >/dev/null 2>&1 || true; fi",
    ]
  ),
  "lamp-filemanager": buildRecipeDefinition(
    "lamp-filemanager",
    "Install Tiny File Manager web panel.",
    [FILEMANAGER_COMMAND]
  ),
  [LAMP_STACK_NAME]: buildRecipeDefinition(
    LAMP_STACK_NAME,
    "Install Apache, database, FTP, and file manager tools.",
    [],
    LAMP_STACK_DEPENDENCIES
  ),
};

RECIPE_CATALOG["lamp-filemanager"].packages = ["curl", "php", "php-cli"];
RECIPE_CATALOG["lamp-filemanager"].parameters = { "fm_user": "", "fm_password": "" };
RECIPE_CATALOG["lamp-filemanager"].required_parameters = ["fm_user", "fm_password"];

const SERVICE_PROBE_LIST = ["apache", "nginx", "mysql", "ftp", "filemanager"];

const SERVICE_ACTIONS = {
  "install-apache": "lamp-apache",
  "install-nginx": "lamp-nginx",
  "install-mysql": "lamp-mysql",
  "install-ftp": "lamp-ftp",
  "install-filemanager": "lamp-filemanager",
};

function iconFor(name) {
  return iconMap[name] || iconMap.compass;
}

function buildNodeIndex(nodes) {
  state.nodesById = new Map(nodes.map((node) => [node.id, node]));
  state.containerIndex = new Map(state.containers.map((container) => [container.name, container]));
}

function getNode(id) {
  return state.nodesById.get(id) || null;
}

function getChildren(parentId) {
  return state.nodes
    .filter((node) => node.parent === parentId)
    .sort((a, b) => {
      const order = (a.order || 0) - (b.order || 0);
      if (order !== 0) {
        return order;
      }
      return a.title.localeCompare(b.title);
    });
}

function buildPath(id) {
  const path = [];
  let current = getNode(id);
  while (current) {
    path.unshift(current);
    if (!current.parent) {
      break;
    }
    current = getNode(current.parent);
  }
  return path;
}

function normalizeStatus(status) {
  if (!status) {
    return "unknown";
  }
  const lowered = status.toLowerCase();
  if (lowered.includes("running")) {
    return "running";
  }
  if (lowered.includes("stopped") || lowered.includes("stop")) {
    return "stopped";
  }
  return "unknown";
}

function resolveServiceState(service, containerMeta) {
  if (!service || !containerMeta) {
    return null;
  }
  const services = Array.isArray(containerMeta.services) ? containerMeta.services : [];
  if (!services.length) {
    return "unknown";
  }
  return services.includes(service) ? "available" : "missing";
}

function resetCreateWizard() {
  state.wizard.form = {
    name: "",
    distro: "ubuntu:22.04",
    cpu_limit: "1",
    ram_limit: "512MB",
    disk_limit: "10GB",
  };
}

function resetRoutingWizard(containerName) {
  state.wizard.routing = {
    domain: "",
    container_name: containerName || (state.containers[0] ? state.containers[0].name : ""),
    container_port: "80",
    container_interface: "eth0",
    listen_address: "0.0.0.0",
    listen_port: "80",
    tls_mode: "manual",
    cert_path: "",
    key_path: "",
    chain_path: "",
    tls_port: "443",
    redirect_http: true,
    tls_email: "",
    tls_staging: false,
  };
  state.wizard.context.container = containerName || null;
}

function resetFilemanagerWizard() {
  state.wizard.filemanager = {
    username: "",
    password: "",
    install_path: "/var/www/html/filemanager",
  };
}

function resetPackagesWizard(mode, targetContainer) {
  state.wizard.packages = {
    mode: mode || "install",
    target: targetContainer || "",
    packages: "",
    update_index: true,
    full_upgrade: false,
  };
  state.wizard.context.container = targetContainer || null;
}

function resetRecipeWizard(targetContainer) {
  state.wizard.recipe = {
    name: "",
    target: targetContainer || "",
    parameters: "",
    dry_run: false,
    include_dependencies: true,
    update_index: true,
  };
  state.wizard.context.container = targetContainer || null;
}

function resetHostWizard() {
  state.wizard.host = {
    name: "",
    host: "",
    username: "",
    port: "22",
    key_path: "",
    password: "",
    os_type: "",
    notes: "",
  };
  state.wizard.context.container = null;
}

function resetNetworkWizard(containerName) {
  state.wizard.network = {
    container_name: containerName || "",
    protocol: "tcp",
    bind_address: "0.0.0.0",
    host_port: "",
    container_port: "",
    target_interface: "eth0",
    target_address: "",
    open_firewall: true,
  };
  state.wizard.context.container = containerName || null;
}

function resetFirewallWizard(mode = "open") {
  state.wizard.firewall = {
    mode,
    port: "",
    protocol: "tcp",
    source: "",
  };
  state.wizard.context.container = null;
}

function openWizard(mode, contextContainer, options = {}) {
  state.wizard.active = true;
  state.wizard.mode = mode;
  state.wizard.step = 0;
  state.wizard.busy = false;
  state.wizard.error = null;
  if (mode === "create-container") {
    resetCreateWizard();
    state.wizard.context.container = null;
  } else if (mode === "routing") {
    resetRoutingWizard(contextContainer);
  } else if (mode === "filemanager") {
    resetFilemanagerWizard();
    state.wizard.context.container = contextContainer || null;
  } else if (mode === "packages") {
    resetPackagesWizard(options.packageMode || "install", contextContainer || null);
  } else if (mode === "recipe-apply") {
    resetRecipeWizard(contextContainer || null);
  } else if (mode === "host-create") {
    resetHostWizard();
  } else if (mode === "network") {
    resetNetworkWizard(contextContainer || null);
  } else if (mode === "firewall") {
    resetFirewallWizard(options.firewallMode || "open");
  }
  renderWizard();
}

function renderTree() {
  const path = buildPath(state.selectedId || state.rootId);
  elements.tree.innerHTML = path
    .map((node, index) => {
      const active = index === path.length - 1 ? "active" : "";
      return `
        <button class="tree-item ${active}" data-node-id="${node.id}">
          <span class="tree-index">${index + 1}</span>
          <span>${node.title}</span>
        </button>
      `;
    })
    .join("");
  elements.breadcrumb.textContent = path.map((node) => node.title).join(" / ");
}

function renderStatusLine() {
  const count = state.containers.length;
  const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const authLabel = state.auth.mode === "none" ? "Auth: locked" : `Auth: ${state.auth.mode}`;
  elements.statusLine.textContent = `Containers: ${count} | ${authLabel} | Last sync: ${time}`;
  if (state.fortress.status === "error") {
    elements.fortressStatus.textContent = `Fortress: offline`;
    elements.fortressStatus.classList.add("error");
  } else {
    elements.fortressStatus.textContent = `Fortress: online`;
    elements.fortressStatus.classList.remove("error");
  }
}

function renderCard(node, index) {
  const actions = Array.isArray(node.actions) ? node.actions.slice(0, 3) : [];
  const status = node.meta && node.meta.status ? normalizeStatus(node.meta.status) : null;
  const badgeClass = node.badge ? node.badge.toLowerCase().replace(/[^a-z0-9]+/g, "-") : null;
  const selected = node.id === state.selectedId ? "selected" : "";
  const delay = `${index * 0.05}s`;
  return `
    <div class="app-card ${selected}" data-node-id="${node.id}" style="animation-delay: ${delay}">
      <div class="card-icon">${iconFor(node.icon)}</div>
      <div class="card-title">${node.title}</div>
      <div class="card-desc">${node.description || ""}</div>
      <div class="card-meta">
        ${status ? `<span class="pill ${status}">${status}</span>` : ""}
        ${badgeClass ? `<span class="pill ${badgeClass}">${node.badge}</span>` : ""}
        ${node.meta && node.meta.ip ? `<span class="pill">${node.meta.ip}</span>` : ""}
      </div>
      ${
        actions.length
          ? `
        <div class="card-actions">
          ${actions
            .map(
              (action) =>
                `<button class="action ${action.variant || ""}" data-action-id="${action.id}" data-node-id="${node.id}">${action.label}</button>`
            )
            .join("")}
        </div>
      `
          : ""
      }
    </div>
  `;
}

function renderGrid() {
  const children = getChildren(state.selectedId || state.rootId);
  elements.grid.innerHTML = children.map(renderCard).join("");
}

function renderRoutingPreview(node) {
  let body = "";
  if (state.routesLoading) {
    body = `<div>Loading routes...</div>`;
  } else if (!state.routes.length) {
    body = `<div>No routes configured yet. Use Add Route to create one.</div>`;
  } else {
    body = state.routes
      .map((route) => {
        const enabledPill = route.enabled ? `<span class="pill running">enabled</span>` : `<span class="pill stopped">disabled</span>`;
        const tlsMode = route.tls && route.tls.mode ? route.tls.mode : "http";
        const tlsPill = `<span class="pill">${tlsMode}</span>`;
        const targetLabel = route.container_name
          ? `${route.container_name}:${route.container_port}`
          : `host:${route.container_port || 80}`;
        const listenLabel = `${route.listen_address || "0.0.0.0"}:${route.listen_port || 80}`;
        return `
          <div class="event-item">
            <div><strong>${route.domain}</strong> → ${targetLabel}</div>
            <div class="card-meta">
              ${enabledPill}
              ${tlsPill}
              <span class="pill">${listenLabel}</span>
            </div>
            <div class="card-actions">
              <button class="action ghost" data-action-id="route-refresh" data-domain="${route.domain}" data-node-id="${node.id}">Refresh</button>
              <button class="action danger ghost" data-action-id="route-delete" data-domain="${route.domain}" data-node-id="${node.id}">Delete</button>
            </div>
          </div>
        `;
      })
      .join("");
  }
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>${node.description || ""}</div>
    ${body}
  `;
}

function renderRecipesPreview(node) {
  let body = "";
  if (state.recipesLoading) {
    body = `<div>Loading recipes...</div>`;
  } else if (!state.recipes.length) {
    body = `<div>No recipes found. Use Seed LAMP to populate defaults.</div>`;
  } else {
    body = state.recipes
      .map((recipe) => {
        const deps = Array.isArray(recipe.dependencies) ? recipe.dependencies.length : recipe.dependencies_count || 0;
        const packagesCount = recipe.packages_count || 0;
        const commandsCount = recipe.commands_count || 0;
        const paramsCount = Array.isArray(recipe.parameter_keys) ? recipe.parameter_keys.length : 0;
        return `
          <div class="event-item">
            <div><strong>${recipe.name}</strong> — ${recipe.description || "No description"}</div>
            <div class="card-meta">
              <span class="pill">${deps} deps</span>
              <span class="pill">${packagesCount} packages</span>
              <span class="pill">${commandsCount} commands</span>
              <span class="pill">${paramsCount} params</span>
            </div>
            <div class="card-actions">
              <button class="action ghost" data-action-id="recipes-apply" data-recipe="${recipe.name}" data-node-id="${node.id}">Apply</button>
            </div>
          </div>
        `;
      })
      .join("");
  }
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>${node.description || ""}</div>
    ${body}
  `;
}

function renderPackagesPreview(node) {
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>${node.description || ""}</div>
    <div class="event-item">
      Host-level package management uses apt/dnf/yum. Choose Install, Remove, or Update to run against the host or any container.
    </div>
  `;
}

function renderMonitoringPreview(node) {
  if (state.monitoringLoading) {
    elements.preview.innerHTML = `<div class="preview-title">${node.title}</div><div>Loading monitoring snapshot...</div>`;
    return;
  }
  const snapshot = state.monitoring;
  if (!snapshot) {
    elements.preview.innerHTML = `<div class="preview-title">${node.title}</div><div>No snapshot yet. Click Refresh.</div>`;
    return;
  }
  const host = snapshot.host || {};
  const alerts = snapshot.alerts || {};
  const hostAlerts = (alerts.host || []).length;
  const containerAlerts = alerts.containers || {};
  const containerRows = Object.entries(snapshot.containers || {}).map(
    ([name, data]) => `
      <div class="event-item">
        <div><strong>${name}</strong> — CPU ${data.cpu_percent ?? "?"}% / RAM ${data.memory_percent ?? "?"}% / Disk ${data.disk_percent ?? "?"}%</div>
        <div class="card-meta">
          ${containerAlerts[name] && containerAlerts[name].length ? `<span class="pill danger">${containerAlerts[name].length} alerts</span>` : `<span class="pill running">ok</span>`}
          ${data.process_count ? `<span class="pill">${data.process_count} procs</span>` : ""}
        </div>
      </div>
    `
  );
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>Host CPU ${host.cpu_percent ?? "?"}% • RAM ${host.memory_percent ?? "?"}% • Disk ${host.disk_percent ?? "?"}%</div>
    <div class="card-meta">
      ${hostAlerts ? `<span class="pill danger">${hostAlerts} host alerts</span>` : `<span class="pill running">host ok</span>`}
      <span class="pill">${Object.keys(containerAlerts).length} container alerts tracked</span>
    </div>
    ${containerRows.join("")}
  `;
}

function renderFirewallPreview(node) {
  if (state.firewallLoading) {
    elements.preview.innerHTML = `<div class="preview-title">${node.title}</div><div>Loading firewall...</div>`;
    return;
  }
  const fw = state.firewall || {};
  const rules = Array.isArray(fw.rules) ? fw.rules : [];
  const body =
    rules.length === 0
      ? `<div>No firewall rules loaded. Use Open Port to add one.</div>`
      : rules
          .map(
            (rule) => `
      <div class="event-item">
        <div><strong>${rule.port}/${rule.protocol}</strong> — ${rule.source || "any"}</div>
        <div class="card-meta">
          <span class="pill">${rule.action || "allow"}</span>
          <span class="pill">${rule.interface || "all ifaces"}</span>
        </div>
      </div>
    `
          )
          .join("");
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>Backend: ${fw.backend || "unknown"} • Active: ${fw.active ? "yes" : "no"}</div>
    ${body}
  `;
}

function renderVmsPreview(node) {
  if (state.vmsLoading) {
    elements.preview.innerHTML = `<div class="preview-title">${node.title}</div><div>Loading VMs...</div>`;
    return;
  }
  const vms = Array.isArray(state.vms) ? state.vms : [];
  const body =
    vms.length === 0
      ? `<div>No VMs defined yet.</div>`
      : vms
          .map((vm) => {
            const status = vm.status || vm.state || "unknown";
            const pill = `<span class="pill ${status.includes("running") ? "running" : "stopped"}">${status}</span>`;
            return `
          <div class="event-item">
            <div><strong>${vm.name}</strong> — ${vm.profile || vm.provider || "vm"}</div>
            <div class="card-meta">
              ${pill}
              ${vm.memory_mb ? `<span class="pill">${vm.memory_mb} MB</span>` : ""}
              ${vm.disk_gb ? `<span class="pill">${vm.disk_gb} GB</span>` : ""}
            </div>
            <div class="card-actions">
              <button class="action ghost" data-action-id="vm-start" data-vm="${vm.name}" data-node-id="${node.id}">Start</button>
              <button class="action ghost" data-action-id="vm-stop" data-vm="${vm.name}" data-node-id="${node.id}">Stop</button>
              <button class="action ghost" data-action-id="vm-status" data-vm="${vm.name}" data-node-id="${node.id}">Status</button>
            </div>
          </div>
        `;
          })
          .join("");
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>${node.description || ""}</div>
    ${body}
  `;
}

function renderHostsPreview(node) {
  let body = "";
  if (state.hostsLoading) {
    body = `<div>Loading hosts...</div>`;
  } else if (!state.hosts.length) {
    body = `<div>No hosts registered yet. Add a host to begin provisioning and probes.</div>`;
  } else {
    body = state.hosts
      .map((host) => {
        const installedPill = host.installed ? `<span class="pill running">installed</span>` : `<span class="pill stopped">new</span>`;
        const osPill = host.os_type ? `<span class="pill">${host.os_type}</span>` : "";
        const updatedPill = host.updated_at ? `<span class="pill">${host.updated_at}</span>` : "";
        const sshLabel = host.ssh_host ? `${host.ssh_host}${host.ssh_port ? `:${host.ssh_port}` : ""}` : "ssh not set";
        return `
          <div class="event-item">
            <div><strong>${host.name}</strong> — ${sshLabel}</div>
            <div class="card-meta">
              ${installedPill}
              ${osPill}
              ${updatedPill}
            </div>
            <div class="card-actions">
              <button class="action ghost" data-action-id="host-probe" data-host="${host.name}" data-node-id="${node.id}">Probe</button>
              <button class="action ghost" data-action-id="host-provision" data-host="${host.name}" data-node-id="${node.id}">Provision</button>
              <button class="action danger ghost" data-action-id="host-delete" data-host="${host.name}" data-node-id="${node.id}">Delete</button>
            </div>
          </div>
        `;
      })
      .join("");
  }
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>${node.description || ""}</div>
    ${body}
  `;
}

function renderPreview() {
  const node = getNode(state.selectedId || state.rootId);
  if (!node) {
    elements.preview.textContent = "Select an app to preview.";
    return;
  }

  if (node.id === "routing") {
    renderRoutingPreview(node);
    return;
  }
  if (node.id === "recipes") {
    renderRecipesPreview(node);
    return;
  }
  if (node.id === "packages") {
    renderPackagesPreview(node);
    return;
  }
  if (node.id === "hosts") {
    renderHostsPreview(node);
    return;
  }
  if (node.id === "monitoring") {
    renderMonitoringPreview(node);
    return;
  }
  if (node.id === "firewall") {
    renderFirewallPreview(node);
    return;
  }
  if (node.id === "vms") {
    renderVmsPreview(node);
    return;
  }

  const actions = Array.isArray(node.actions) ? node.actions : [];
  const contextContainer = node.context ? node.context.container : null;
  const containerMeta = contextContainer ? state.containerIndex.get(contextContainer) : null;
  const status = containerMeta ? normalizeStatus(containerMeta.status) : null;
  const badgeClass = node.badge ? node.badge.toLowerCase().replace(/[^a-z0-9]+/g, "-") : null;
  const serviceState = resolveServiceState(node.service, containerMeta);
  const stackLabel = containerMeta && containerMeta.stack ? containerMeta.stack : null;
  const servicesLabel =
    containerMeta && Array.isArray(containerMeta.services) && containerMeta.services.length
      ? containerMeta.services.join(", ")
      : null;

  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>${node.description || ""}</div>
    <div class="card-meta">
      ${status ? `<span class="pill ${status}">${status}</span>` : ""}
      ${badgeClass ? `<span class="pill ${badgeClass}">${node.badge}</span>` : ""}
      ${contextContainer ? `<span class="pill">${contextContainer}</span>` : ""}
    </div>
    ${
      containerMeta
        ? `
      <div class="preview-meta">
        <div>
          <strong>Status</strong>
          <span>${containerMeta.status || "unknown"}</span>
        </div>
        <div>
          <strong>Primary IP</strong>
          <span>${containerMeta.ip || "n/a"}</span>
        </div>
        <div>
          <strong>Architecture</strong>
          <span>${containerMeta.architecture || "n/a"}</span>
        </div>
        <div>
          <strong>Type</strong>
          <span>${containerMeta.type || "container"}</span>
        </div>
        ${
          stackLabel
            ? `
        <div>
          <strong>Stack</strong>
          <span>${stackLabel}</span>
        </div>
        `
            : ""
        }
        ${
          servicesLabel
            ? `
        <div>
          <strong>Services</strong>
          <span>${servicesLabel}</span>
        </div>
        `
            : ""
        }
        ${
          node.service
            ? `
        <div>
          <strong>Service</strong>
          <span>${node.service}</span>
        </div>
        <div>
          <strong>Detected</strong>
          <span>${serviceState || "unknown"}</span>
        </div>
        `
            : ""
        }
      </div>
    `
        : ""
    }
    ${
      actions.length
        ? `
      <div class="card-actions">
        ${actions
          .map(
            (action) =>
              `<button class="action ${action.variant || ""}" data-action-id="${action.id}" data-node-id="${node.id}">${action.label}</button>`
          )
          .join("")}
      </div>
    `
        : ""
    }
  `;
}

function renderEvents() {
  if (!state.events.length) {
    elements.eventLog.innerHTML = "No actions yet.";
    return;
  }
  elements.eventLog.innerHTML = state.events
    .map(
      (event) => `
      <div class="event-item ${event.type === "error" ? "error" : ""}">
        <div>${event.message}</div>
        <div>${event.time}</div>
      </div>
    `
    )
    .join("");
}

function renderWizard() {
  const wizard = state.wizard;
  if (!wizard.active || !wizard.mode) {
    elements.wizard.innerHTML = `
      <div>Wizard idle. Choose a card action to start a guided flow.</div>
    `;
    return;
  }

  let steps = [];
  let bodyMarkup = "";
  let nextLabel = "Next";

  if (wizard.mode === "create-container") {
    steps = ["Identity", "Resources", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-name">Container name</label>
          <input id="wiz-name" name="name" data-wizard-group="form" value="${wizard.form.name}" placeholder="web-01" />
        </div>
        <div class="wizard-field">
          <label for="wiz-distro">Distro</label>
          <select id="wiz-distro" name="distro" data-wizard-group="form">
            <option value="ubuntu:22.04" ${wizard.form.distro === "ubuntu:22.04" ? "selected" : ""}>Ubuntu 22.04</option>
            <option value="ubuntu:20.04" ${wizard.form.distro === "ubuntu:20.04" ? "selected" : ""}>Ubuntu 20.04</option>
            <option value="debian:12" ${wizard.form.distro === "debian:12" ? "selected" : ""}>Debian 12</option>
            <option value="almalinux:9" ${wizard.form.distro === "almalinux:9" ? "selected" : ""}>AlmaLinux 9</option>
          </select>
        </div>
      `;
    } else if (wizard.step === 1) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-cpu">CPU limit</label>
          <input id="wiz-cpu" name="cpu_limit" data-wizard-group="form" value="${wizard.form.cpu_limit}" placeholder="2" />
        </div>
        <div class="wizard-field">
          <label for="wiz-ram">RAM limit</label>
          <input id="wiz-ram" name="ram_limit" data-wizard-group="form" value="${wizard.form.ram_limit}" placeholder="1GB" />
        </div>
        <div class="wizard-field">
          <label for="wiz-disk">Disk limit</label>
          <input id="wiz-disk" name="disk_limit" data-wizard-group="form" value="${wizard.form.disk_limit}" placeholder="10GB" />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Launching..." : "Launch";
      bodyMarkup = `
        <div>Confirm the container launch profile.</div>
        <div class="preview-meta">
          <div>
            <strong>Name</strong>
            <span>${wizard.form.name || "(missing)"}</span>
          </div>
          <div>
            <strong>Distro</strong>
            <span>${wizard.form.distro}</span>
          </div>
          <div>
            <strong>CPU</strong>
            <span>${wizard.form.cpu_limit}</span>
          </div>
          <div>
            <strong>RAM</strong>
            <span>${wizard.form.ram_limit}</span>
          </div>
          <div>
            <strong>Disk</strong>
            <span>${wizard.form.disk_limit}</span>
          </div>
        </div>
      `;
    }
  } else if (wizard.mode === "routing") {
    const routing = wizard.routing;
    const containerName = routing.container_name || wizard.context.container || "";
    const containerSelectDisabled = wizard.context.container ? "disabled" : "";
    const containerOptions = state.containers
      .map(
        (container) =>
          `<option value="${container.name}" ${container.name === containerName ? "selected" : ""}>${container.name}</option>`
      )
      .join("");
    const containerSelect = containerOptions
      ? `
        <div class="wizard-field">
          <label for="wiz-container-name">Container</label>
          <select id="wiz-container-name" name="container_name" data-wizard-group="routing" ${containerSelectDisabled}>
            ${containerOptions}
          </select>
        </div>
      `
      : `
        <div class="wizard-field">
          <label>Container</label>
          <div class="event-item error">No containers available. Create one first.</div>
        </div>
      `;
    steps = ["Domain", "TLS", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div>Route traffic for ${containerName || "a container"}.</div>
        ${containerSelect}
        <div class="wizard-field">
          <label for="wiz-domain">Domain</label>
          <input id="wiz-domain" name="domain" data-wizard-group="routing" value="${routing.domain}" placeholder="app.example.com" />
        </div>
        <div class="wizard-field">
          <label for="wiz-container-port">Container port</label>
          <input id="wiz-container-port" name="container_port" data-wizard-group="routing" value="${routing.container_port}" placeholder="80" />
        </div>
        <div class="wizard-field">
          <label for="wiz-container-iface">Container interface</label>
          <input id="wiz-container-iface" name="container_interface" data-wizard-group="routing" value="${routing.container_interface}" placeholder="eth0" />
        </div>
        <div class="wizard-field">
          <label for="wiz-listen-address">Listen address</label>
          <input id="wiz-listen-address" name="listen_address" data-wizard-group="routing" value="${routing.listen_address}" placeholder="0.0.0.0" />
        </div>
        <div class="wizard-field">
          <label for="wiz-listen-port">Listen port</label>
          <input id="wiz-listen-port" name="listen_port" data-wizard-group="routing" value="${routing.listen_port}" placeholder="80" />
        </div>
      `;
    } else if (wizard.step === 1) {
      const tlsMode = routing.tls_mode || "manual";
      const manualActive = tlsMode === "manual";
      const letsencryptActive = tlsMode === "letsencrypt";
      const tlsDisabled = tlsMode === "disabled" ? "disabled" : "";
      const manualHidden = manualActive ? "" : "hidden";
      const letsencryptHidden = letsencryptActive ? "" : "hidden";
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-tls-mode">TLS mode</label>
          <select id="wiz-tls-mode" name="tls_mode" data-wizard-group="routing">
            <option value="manual" ${tlsMode === "manual" ? "selected" : ""}>Manual cert paths</option>
            <option value="letsencrypt" ${tlsMode === "letsencrypt" ? "selected" : ""}>Let's Encrypt</option>
            <option value="disabled" ${tlsMode === "disabled" ? "selected" : ""}>Disabled</option>
          </select>
        </div>
        <div class="wizard-field" ${manualHidden}>
          <label for="wiz-cert-path">Cert path</label>
          <input id="wiz-cert-path" name="cert_path" data-wizard-group="routing" value="${routing.cert_path}" placeholder="/etc/letsencrypt/live/app/fullchain.pem" ${tlsDisabled} />
        </div>
        <div class="wizard-field" ${manualHidden}>
          <label for="wiz-key-path">Key path</label>
          <input id="wiz-key-path" name="key_path" data-wizard-group="routing" value="${routing.key_path}" placeholder="/etc/letsencrypt/live/app/privkey.pem" ${tlsDisabled} />
        </div>
        <div class="wizard-field" ${manualHidden}>
          <label for="wiz-chain-path">Chain path (optional)</label>
          <input id="wiz-chain-path" name="chain_path" data-wizard-group="routing" value="${routing.chain_path}" placeholder="/etc/letsencrypt/live/app/chain.pem" ${tlsDisabled} />
        </div>
        <div class="wizard-field" ${letsencryptHidden}>
          <label for="wiz-tls-email">Let's Encrypt email</label>
          <input id="wiz-tls-email" name="tls_email" data-wizard-group="routing" value="${routing.tls_email}" placeholder="admin@example.com" ${tlsDisabled} />
        </div>
        <div class="wizard-field" ${letsencryptHidden}>
          <label for="wiz-tls-staging">Use Let's Encrypt staging</label>
          <input id="wiz-tls-staging" type="checkbox" name="tls_staging" data-wizard-group="routing" ${routing.tls_staging ? "checked" : ""} ${tlsDisabled} />
        </div>
        <div class="wizard-field">
          <label for="wiz-tls-port">TLS listen port</label>
          <input id="wiz-tls-port" name="tls_port" data-wizard-group="routing" value="${routing.tls_port}" placeholder="443" ${tlsDisabled} />
        </div>
        <div class="wizard-field">
          <label for="wiz-redirect">Redirect HTTP to HTTPS</label>
          <input id="wiz-redirect" type="checkbox" name="redirect_http" data-wizard-group="routing" ${routing.redirect_http ? "checked" : ""} ${tlsDisabled} />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Applying..." : "Apply";
      bodyMarkup = `
        <div>Confirm HTTPS routing.</div>
        <div class="preview-meta">
          <div>
            <strong>Container</strong>
            <span>${containerName || "(missing)"}</span>
          </div>
          <div>
            <strong>Domain</strong>
            <span>${routing.domain || "(missing)"}</span>
          </div>
          <div>
            <strong>Container Port</strong>
            <span>${routing.container_port}</span>
          </div>
          <div>
            <strong>Listen</strong>
            <span>${routing.listen_address}:${routing.listen_port}</span>
          </div>
          <div>
            <strong>TLS</strong>
            <span>${routing.tls_mode || "disabled"}</span>
          </div>
          <div>
            <strong>TLS Port</strong>
            <span>${routing.tls_port}</span>
          </div>
        </div>
      `;
    }
  } else if (wizard.mode === "packages") {
    const pkg = wizard.packages;
    const actionLabel = pkg.mode === "remove" ? "Remove" : pkg.mode === "update" ? "Update" : "Install";
    steps = ["Details", "Confirm"];
    const targetOptions = [
      `<option value="" ${pkg.target ? "" : "selected"}>Host (this server)</option>`,
      ...state.containers.map(
        (container) =>
          `<option value="${container.name}" ${pkg.target === container.name ? "selected" : ""}>${container.name}</option>`
      ),
    ].join("");
    if (wizard.step === 0) {
      const packagesField =
        pkg.mode === "update"
          ? ""
          : `
        <div class="wizard-field">
          <label for="wiz-packages">Packages (space or comma separated)</label>
          <input id="wiz-packages" name="packages" data-wizard-group="packages" value="${pkg.packages}" placeholder="htop curl" />
        </div>
      `;
      const updateField =
        pkg.mode === "install"
          ? `
        <div class="wizard-field">
          <label for="wiz-update-index">Refresh package index first</label>
          <input id="wiz-update-index" type="checkbox" name="update_index" data-wizard-group="packages" ${pkg.update_index ? "checked" : ""} />
        </div>
      `
          : "";
      const fullUpgradeField =
        pkg.mode === "update"
          ? `
        <div class="wizard-field">
          <label for="wiz-full-upgrade">Full upgrade (dist-upgrade)</label>
          <input id="wiz-full-upgrade" type="checkbox" name="full_upgrade" data-wizard-group="packages" ${pkg.full_upgrade ? "checked" : ""} />
        </div>
      `
          : "";
      bodyMarkup = `
        <div>${actionLabel} packages on host or container.</div>
        <div class="wizard-field">
          <label for="wiz-package-target">Target</label>
          <select id="wiz-package-target" name="target" data-wizard-group="packages">
            ${targetOptions}
          </select>
        </div>
        ${packagesField}
        ${updateField}
        ${fullUpgradeField}
      `;
    } else {
      nextLabel = wizard.busy ? `${actionLabel}...` : actionLabel;
      const targetLabel = pkg.target ? `container ${pkg.target}` : "host";
      const packagesLabel = pkg.mode === "update" ? "(all packages)" : pkg.packages || "(none)";
      bodyMarkup = `
        <div>Confirm package ${pkg.mode}.</div>
        <div class="preview-meta">
          <div>
            <strong>Mode</strong>
            <span>${pkg.mode}</span>
          </div>
          <div>
            <strong>Target</strong>
            <span>${targetLabel}</span>
          </div>
          <div>
            <strong>Packages</strong>
            <span>${packagesLabel}</span>
          </div>
          ${
            pkg.mode === "install"
              ? `
          <div>
            <strong>Update index</strong>
            <span>${pkg.update_index ? "yes" : "no"}</span>
          </div>
          `
              : ""
          }
          ${
            pkg.mode === "update"
              ? `
          <div>
            <strong>Full upgrade</strong>
            <span>${pkg.full_upgrade ? "yes" : "no"}</span>
          </div>
          `
              : ""
          }
        </div>
      `;
    }
  } else if (wizard.mode === "filemanager") {
    const filemanager = wizard.filemanager;
    const containerName = wizard.context.container || "container";
    steps = ["Credentials", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div>Install Tiny File Manager on ${containerName}.</div>
        <div class="wizard-field">
          <label for="wiz-fm-user">Admin username</label>
          <input id="wiz-fm-user" name="username" data-wizard-group="filemanager" value="${filemanager.username}" placeholder="admin" />
        </div>
        <div class="wizard-field">
          <label for="wiz-fm-pass">Admin password</label>
          <input id="wiz-fm-pass" type="password" name="password" data-wizard-group="filemanager" value="${filemanager.password}" placeholder="change-me" />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Installing..." : "Install";
      bodyMarkup = `
        <div>Confirm file manager install.</div>
        <div class="preview-meta">
          <div>
            <strong>Container</strong>
            <span>${containerName}</span>
          </div>
          <div>
            <strong>Username</strong>
            <span>${filemanager.username || "(missing)"}</span>
          </div>
          <div>
            <strong>Install Path</strong>
            <span>${filemanager.install_path}</span>
          </div>
        </div>
      `;
    }
  } else if (wizard.mode === "recipe-apply") {
    const recipe = wizard.recipe;
    const recipeOptions = state.recipes
      .map((item) => `<option value="${item.name}" ${item.name === recipe.name ? "selected" : ""}>${item.name}</option>`)
      .join("");
    const targetOptions = [
      `<option value="" ${recipe.target ? "" : "selected"}>Host (this server)</option>`,
      ...state.containers.map(
        (container) => `<option value="${container.name}" ${recipe.target === container.name ? "selected" : ""}>${container.name}</option>`
      ),
    ].join("");
    steps = ["Target", "Parameters", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div>Select a recipe and where to run it.</div>
        <div class="wizard-field">
          <label for="wiz-recipe-name">Recipe</label>
          <select id="wiz-recipe-name" name="name" data-wizard-group="recipe">
            ${
              recipeOptions
                ? recipeOptions
                : `<option value="">No recipes found (seed LAMP to get started)</option>`
            }
          </select>
        </div>
        <div class="wizard-field">
          <label for="wiz-recipe-target">Target</label>
          <select id="wiz-recipe-target" name="target" data-wizard-group="recipe">
            ${targetOptions}
          </select>
        </div>
        <div class="wizard-field">
          <label for="wiz-recipe-deps">Include dependencies</label>
          <input id="wiz-recipe-deps" type="checkbox" name="include_dependencies" data-wizard-group="recipe" ${
            recipe.include_dependencies ? "checked" : ""
          } />
        </div>
        <div class="wizard-field">
          <label for="wiz-recipe-update-index">Refresh package index</label>
          <input id="wiz-recipe-update-index" type="checkbox" name="update_index" data-wizard-group="recipe" ${
            recipe.update_index ? "checked" : ""
          } />
        </div>
        <div class="wizard-field">
          <label for="wiz-recipe-dry-run">Plan only (dry run)</label>
          <input id="wiz-recipe-dry-run" type="checkbox" name="dry_run" data-wizard-group="recipe" ${
            recipe.dry_run ? "checked" : ""
          } />
        </div>
      `;
    } else if (wizard.step === 1) {
      bodyMarkup = `
        <div>Optional parameters (key=value per line or JSON object).</div>
        <div class="wizard-field">
          <label for="wiz-recipe-params">Parameters</label>
          <textarea id="wiz-recipe-params" name="parameters" data-wizard-group="recipe" rows="4" placeholder="db_user=app_user&#10;db_password=secret">${recipe.parameters}</textarea>
        </div>
      `;
    } else {
      const actionVerb = recipe.dry_run ? "Plan" : "Apply";
      nextLabel = wizard.busy ? `${actionVerb}...` : actionVerb;
      bodyMarkup = `
        <div>Confirm recipe ${actionVerb.toLowerCase()}.</div>
        <div class="preview-meta">
          <div>
            <strong>Recipe</strong>
            <span>${recipe.name || "(missing)"}</span>
          </div>
          <div>
            <strong>Target</strong>
            <span>${recipe.target ? `container ${recipe.target}` : "host"}</span>
          </div>
          <div>
            <strong>Include deps</strong>
            <span>${recipe.include_dependencies ? "yes" : "no"}</span>
          </div>
          <div>
            <strong>Update index</strong>
            <span>${recipe.update_index ? "yes" : "no"}</span>
          </div>
          <div>
            <strong>Dry run</strong>
            <span>${recipe.dry_run ? "yes" : "no"}</span>
          </div>
        </div>
      `;
    }
  } else if (wizard.mode === "network") {
    const net = wizard.network;
    const containerName = net.container_name || wizard.context.container || "";
    steps = ["Mapping", "Confirm"];
    if (wizard.step === 0) {
      const containerOptions = state.containers
        .map(
          (container) =>
            `<option value="${container.name}" ${container.name === containerName ? "selected" : ""}>${container.name}</option>`
        )
        .join("");
      bodyMarkup = `
        <div>Expose a host port to ${containerName || "a container"}.</div>
        <div class="wizard-field">
          <label for="wiz-net-container">Container</label>
          <select id="wiz-net-container" name="container_name" data-wizard-group="network">
            ${containerOptions}
          </select>
        </div>
        <div class="wizard-field">
          <label for="wiz-net-protocol">Protocol</label>
          <select id="wiz-net-protocol" name="protocol" data-wizard-group="network">
            <option value="tcp" ${net.protocol === "tcp" ? "selected" : ""}>TCP</option>
            <option value="udp" ${net.protocol === "udp" ? "selected" : ""}>UDP</option>
          </select>
        </div>
        <div class="wizard-field">
          <label for="wiz-net-container-port">Container port</label>
          <input id="wiz-net-container-port" name="container_port" data-wizard-group="network" value="${net.container_port}" placeholder="80" />
        </div>
        <div class="wizard-field">
          <label for="wiz-net-host-port">Host port</label>
          <input id="wiz-net-host-port" name="host_port" data-wizard-group="network" value="${net.host_port}" placeholder="8080" />
        </div>
        <div class="wizard-field">
          <label for="wiz-net-bind">Bind address</label>
          <input id="wiz-net-bind" name="bind_address" data-wizard-group="network" value="${net.bind_address}" placeholder="0.0.0.0" />
        </div>
        <div class="wizard-field">
          <label for="wiz-net-target-iface">Container interface</label>
          <input id="wiz-net-target-iface" name="target_interface" data-wizard-group="network" value="${net.target_interface}" placeholder="eth0" />
        </div>
        <div class="wizard-field">
          <label for="wiz-net-target-addr">Container address (optional)</label>
          <input id="wiz-net-target-addr" name="target_address" data-wizard-group="network" value="${net.target_address}" placeholder="" />
        </div>
        <div class="wizard-field">
          <label for="wiz-net-fw">Open firewall</label>
          <input id="wiz-net-fw" type="checkbox" name="open_firewall" data-wizard-group="network" ${net.open_firewall ? "checked" : ""} />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Exposing..." : "Expose";
      const hostPort = net.host_port || net.container_port;
      bodyMarkup = `
        <div>Confirm port exposure.</div>
        <div class="preview-meta">
          <div>
            <strong>Container</strong>
            <span>${containerName || "(missing)"}</span>
          </div>
          <div>
            <strong>Mapping</strong>
            <span>${net.bind_address}:${hostPort || "(host port)"} → ${net.target_interface || "eth0"}:${net.container_port || "(container port)"}</span>
          </div>
          <div>
            <strong>Protocol</strong>
            <span>${net.protocol}</span>
          </div>
          <div>
            <strong>Open firewall</strong>
            <span>${net.open_firewall ? "yes" : "no"}</span>
          </div>
        </div>
      `;
    }
  } else if (wizard.mode === "firewall") {
    const fw = wizard.firewall;
    const actionLabel = fw.mode === "close" ? "Close" : "Open";
    steps = ["Rule", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-fw-mode">Action</label>
          <select id="wiz-fw-mode" name="mode" data-wizard-group="firewall">
            <option value="open" ${fw.mode === "open" ? "selected" : ""}>Open</option>
            <option value="close" ${fw.mode === "close" ? "selected" : ""}>Close</option>
          </select>
        </div>
        <div class="wizard-field">
          <label for="wiz-fw-port">Port</label>
          <input id="wiz-fw-port" name="port" data-wizard-group="firewall" value="${fw.port}" placeholder="443" />
        </div>
        <div class="wizard-field">
          <label for="wiz-fw-protocol">Protocol</label>
          <select id="wiz-fw-protocol" name="protocol" data-wizard-group="firewall">
            <option value="tcp" ${fw.protocol === "tcp" ? "selected" : ""}>TCP</option>
            <option value="udp" ${fw.protocol === "udp" ? "selected" : ""}>UDP</option>
          </select>
        </div>
        <div class="wizard-field">
          <label for="wiz-fw-source">Source (CIDR, optional)</label>
          <input id="wiz-fw-source" name="source" data-wizard-group="firewall" value="${fw.source}" placeholder="0.0.0.0/0" />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? `${actionLabel}ing...` : actionLabel;
      bodyMarkup = `
        <div>Confirm firewall rule.</div>
        <div class="preview-meta">
          <div>
            <strong>Action</strong>
            <span>${fw.mode}</span>
          </div>
          <div>
            <strong>Port</strong>
            <span>${fw.port}</span>
          </div>
          <div>
            <strong>Protocol</strong>
            <span>${fw.protocol}</span>
          </div>
          <div>
            <strong>Source</strong>
            <span>${fw.source || "any"}</span>
          </div>
        </div>
      `;
    }
  } else if (wizard.mode === "host-create") {
    const host = wizard.host;
    steps = ["Identity", "SSH", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-host-name">Host name</label>
          <input id="wiz-host-name" name="name" data-wizard-group="host" value="${host.name}" placeholder="edge-01" />
        </div>
        <div class="wizard-field">
          <label for="wiz-host-os">OS type (optional)</label>
          <input id="wiz-host-os" name="os_type" data-wizard-group="host" value="${host.os_type || ""}" placeholder="ubuntu" />
        </div>
        <div class="wizard-field">
          <label for="wiz-host-notes">Notes</label>
          <input id="wiz-host-notes" name="notes" data-wizard-group="host" value="${host.notes || ""}" placeholder="ssh user has sudo" />
        </div>
      `;
    } else if (wizard.step === 1) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-host-address">SSH host</label>
          <input id="wiz-host-address" name="host" data-wizard-group="host" value="${host.host}" placeholder="192.0.2.10" />
        </div>
        <div class="wizard-field">
          <label for="wiz-host-user">SSH username</label>
          <input id="wiz-host-user" name="username" data-wizard-group="host" value="${host.username}" placeholder="fortress" />
        </div>
        <div class="wizard-field">
          <label for="wiz-host-port">SSH port</label>
          <input id="wiz-host-port" name="port" data-wizard-group="host" value="${host.port}" placeholder="22" />
        </div>
        <div class="wizard-field">
          <label for="wiz-host-key">SSH key path (optional)</label>
          <input id="wiz-host-key" name="key_path" data-wizard-group="host" value="${host.key_path || ""}" placeholder="/home/user/.ssh/id_rsa" />
        </div>
        <div class="wizard-field">
          <label for="wiz-host-pass">SSH password (optional)</label>
          <input id="wiz-host-pass" type="password" name="password" data-wizard-group="host" value="${host.password || ""}" placeholder="••••••" />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Creating..." : "Create";
      bodyMarkup = `
        <div>Confirm host record.</div>
        <div class="preview-meta">
          <div>
            <strong>Name</strong>
            <span>${host.name || "(missing)"}</span>
          </div>
          <div>
            <strong>OS</strong>
            <span>${host.os_type || "unknown"}</span>
          </div>
          <div>
            <strong>SSH</strong>
            <span>${host.username || "(user)"}@${host.host || "(host)"}:${host.port || "22"}</span>
          </div>
          <div>
            <strong>Key path</strong>
            <span>${host.key_path || "none"}</span>
          </div>
          <div>
            <strong>Notes</strong>
            <span>${host.notes || "none"}</span>
          </div>
        </div>
      `;
    }
  }

  const stepMarkup = steps
    .map((title, index) => {
      const active = index === wizard.step ? "active" : "";
      return `<div class="wizard-step ${active}">${title}</div>`;
    })
    .join("");

  const errorMarkup = wizard.error ? `<div class="event-item error">${wizard.error}</div>` : "";
  const backDisabled = wizard.step === 0 ? "disabled" : "";
  const nextDisabled = wizard.busy ? "disabled" : "";

  elements.wizard.innerHTML = `
    <div class="wizard-steps">${stepMarkup}</div>
    ${bodyMarkup}
    ${errorMarkup}
    <div class="wizard-actions">
      <button class="action ghost" data-wizard-action="close">Close</button>
      <button class="action ghost" data-wizard-action="back" ${backDisabled}>Back</button>
      <button class="action" data-wizard-action="next" ${nextDisabled}>${nextLabel}</button>
    </div>
  `;
}

function renderAll() {
  renderTree();
  renderStatusLine();
  renderGrid();
  renderPreview();
  renderWizard();
  renderEvents();
}

function selectNode(id) {
  state.selectedId = id;
  renderAll();
  hydrateNode(id).catch(() => {});
}

async function hydrateNode(id) {
  const nodeId = id || state.selectedId;
  if (!nodeId) {
    return;
  }
  try {
    if (nodeId === "routing") {
      await loadRoutes();
    } else if (nodeId === "recipes") {
      await loadRecipes();
    } else if (nodeId === "hosts") {
      await loadHosts();
    } else if (nodeId === "monitoring") {
      await loadMonitoring();
    } else if (nodeId === "firewall") {
      await loadFirewall();
    } else if (nodeId === "vms") {
      await loadVms();
    }
  } catch (err) {
    // Errors already logged.
  }
}

function logEvent(type, message) {
  const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  state.events.unshift({ type, message, time });
  state.events = state.events.slice(0, 6);
  renderEvents();
}

function parsePackagesInput(raw) {
  if (!raw) {
    return [];
  }
  return raw
    .split(/[\s,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseParametersInput(raw) {
  if (raw === null || raw === undefined) {
    return {};
  }
  const text = String(raw).trim();
  if (!text) {
    return {};
  }
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed;
    }
  } catch (err) {
    // Fall through to key=value parsing.
  }
  const params = {};
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }
    const idx = trimmed.indexOf("=");
    if (idx === -1) {
      continue;
    }
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    if (key) {
      params[key] = value;
    }
  }
  return params;
}

async function apiRequest(path, options = {}) {
  const response = await fetch(path, {
    headers: {
      "Content-Type": "application/json",
    },
    ...options,
  });
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (err) {
      data = text;
    }
  }
  if (!response.ok) {
    const error = new Error((data && data.error) || "Request failed");
    error.status = response.status;
    error.details = data;
    if (response.status === 401 || response.status === 403) {
      const message = (data && data.error) || "";
      if (message.toLowerCase().includes("admin")) {
        showAdminOverlay(message || "Admin session required.");
      } else {
        showAuthOverlay("Session required. Enter a delegated token.");
      }
    }
    throw error;
  }
  return data;
}

function setAdminState(payload) {
  state.admin.active = Boolean(payload && payload.active);
  state.admin.username = payload && payload.username ? payload.username : null;
  state.admin.bootstrapRequired = Boolean(payload && payload.bootstrap_required);
  state.admin.tokenSession = Boolean(payload && payload.token_session);
  state.admin.storePath = payload && payload.admin_db ? payload.admin_db : null;
  state.admin.error = payload && payload.error ? payload.error : null;
  if (!state.admin.bootstrapRequired) {
    state.admin.bootstrapNotified = false;
  }
  updateAdminUI();
  updateAuthUI();
}

function updateAdminUI() {
  const locked = !state.admin.active;
  const bootstrap = state.admin.bootstrapRequired;
  const storeHint = state.admin.storePath ? ` (store: ${state.admin.storePath})` : "";
  const hideForTokenGate = bootstrap && !state.admin.tokenSession;
  if (elements.adminOverlay) {
    elements.adminOverlay.hidden = !locked || hideForTokenGate;
  }
  if (elements.adminForm) {
    elements.adminForm.hidden = bootstrap || Boolean(state.admin.error);
  }
  if (elements.adminBootstrapForm) {
    elements.adminBootstrapForm.hidden = !bootstrap || Boolean(state.admin.error);
  }
  if (elements.adminBootstrapButton) {
    elements.adminBootstrapButton.hidden = !bootstrap || !state.admin.active;
  }
  if (elements.adminSubtitle) {
    if (state.admin.error) {
      elements.adminSubtitle.textContent = "UI admin store error.";
    } else {
      elements.adminSubtitle.textContent = bootstrap
        ? "Create the first UI admin for this UI server to continue."
        : "Sign in with a UI admin account to continue.";
    }
  }
  if (!locked && elements.adminMessage) {
    elements.adminMessage.textContent = "";
  }
  if (state.admin.error && elements.adminMessage) {
    elements.adminMessage.textContent = `${state.admin.error}${storeHint ? ` ${storeHint}` : ""}`;
  } else if (bootstrap && elements.adminMessage) {
    elements.adminMessage.textContent = `No UI admin exists for this UI server${storeHint}. Use the form below to create the first UI admin.`;
  }
  if (bootstrap && state.admin.active && !state.admin.bootstrapNotified) {
    state.admin.bootstrapNotified = true;
    logEvent(
      "error",
      `UI admin not initialized${storeHint}. Click "Create admin" in the header to finish setup.`
    );
  }
}

function showAdminOverlay(message) {
  state.admin.active = false;
  const msg = (message || "").toLowerCase();
  state.admin.bootstrapRequired = msg.includes("bootstrap");
  updateAdminUI();
  updateAuthUI();
  if (elements.adminMessage && !state.admin.bootstrapRequired && !state.admin.error) {
    elements.adminMessage.textContent = message || "";
  }
}

function setAuthState(payload) {
  state.auth.active = Boolean(payload && payload.active);
  state.auth.mode = payload && payload.mode ? payload.mode : "none";
  state.auth.session = Boolean(payload && payload.session);
  updateAuthUI();
}

function updateAuthUI() {
  const locked = state.auth.mode === "none";
  const allowTokenGate = state.admin.bootstrapRequired;
  if (elements.authOverlay) {
    elements.authOverlay.hidden = !locked || (!state.admin.active && !allowTokenGate);
  }
  if (elements.logoutButton) {
    elements.logoutButton.hidden = !state.auth.session;
  }
  if (!locked && elements.authMessage) {
    elements.authMessage.textContent = "";
  }
  if (locked && elements.authMessage && state.admin.active && !elements.authMessage.textContent) {
    elements.authMessage.textContent =
      "No delegated token yet. Create one with fortress-cli api-users create (requires master API key) and include read_status, or set FORTRESS_UI_API_KEY / FORTRESS_UI_USER_TOKEN for the UI.";
  }
}

function showAuthOverlay(message) {
  state.auth.active = false;
  state.auth.mode = "none";
  state.auth.session = false;
  if (elements.authOverlay) {
    elements.authOverlay.hidden = !state.admin.active;
  }
  if (elements.logoutButton) {
    elements.logoutButton.hidden = true;
  }
  if (elements.authMessage) {
    elements.authMessage.textContent = message || "";
  }
}

async function refreshAdminSession() {
  const payload = await apiRequest("/api/admin/session", { method: "GET" });
  setAdminState(payload);
  return payload;
}

async function refreshSession() {
  const payload = await apiRequest("/api/session", { method: "GET" });
  setAuthState(payload);
  return payload;
}

async function handleAdminLogin(event) {
  event.preventDefault();
  if (state.admin.bootstrapRequired) {
    if (elements.adminMessage) {
      elements.adminMessage.textContent = "Admin bootstrap required. Use the Create admin form below.";
    }
    return;
  }
  if (!elements.adminUsername || !elements.adminPassword) {
    return;
  }
  const username = elements.adminUsername.value.trim();
  const password = elements.adminPassword.value;
  const totp = elements.adminTotp ? elements.adminTotp.value.trim() : "";
  if (!username || !password) {
    if (elements.adminMessage) {
      elements.adminMessage.textContent = "Username and password are required.";
    }
    return;
  }
  if (elements.adminMessage) {
    elements.adminMessage.textContent = "Authenticating...";
  }
  try {
    await apiRequest("/api/admin/login", {
      method: "POST",
      body: JSON.stringify(totp ? { username, password, totp } : { username, password }),
    });
    elements.adminPassword.value = "";
    if (elements.adminTotp) {
      elements.adminTotp.value = "";
    }
    await refreshAdminSession();
    if (state.admin.active) {
      await refreshSession();
      if (state.auth.active) {
        await loadGraph();
      }
    }
  } catch (err) {
    if (elements.adminMessage) {
      elements.adminMessage.textContent = err.message || "Authentication failed.";
    }
  }
}

async function handleAdminBootstrap(event) {
  event.preventDefault();
  if (!elements.adminBootstrapUsername || !elements.adminBootstrapPassword || !elements.adminBootstrapConfirm) {
    return;
  }
  const username = elements.adminBootstrapUsername.value.trim();
  const password = elements.adminBootstrapPassword.value;
  const confirm = elements.adminBootstrapConfirm.value;
  if (!username || !password) {
    if (elements.adminMessage) {
      elements.adminMessage.textContent = "Username and password are required.";
    }
    return;
  }
  if (password !== confirm) {
    if (elements.adminMessage) {
      elements.adminMessage.textContent = "Passwords do not match.";
    }
    return;
  }
  if (elements.adminMessage) {
    elements.adminMessage.textContent = "Creating admin account...";
  }
  try {
    await apiRequest("/api/admin/bootstrap", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    await apiRequest("/api/admin/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    elements.adminBootstrapUsername.value = "";
    elements.adminBootstrapPassword.value = "";
    elements.adminBootstrapConfirm.value = "";
    await refreshAdminSession();
    if (state.admin.active) {
      await refreshSession();
      if (state.auth.active) {
        await loadGraph();
      }
    }
  } catch (err) {
    if (elements.adminMessage) {
      elements.adminMessage.textContent = err.message || "Admin bootstrap failed.";
    }
  }
}

async function handleLogin(event) {
  event.preventDefault();
  if (!elements.authToken) {
    return;
  }
  const token = elements.authToken.value.trim();
  if (!token) {
    if (elements.authMessage) {
      elements.authMessage.textContent = "Token is required.";
    }
    return;
  }
  if (elements.authMessage) {
    elements.authMessage.textContent = "Authenticating...";
  }
  try {
    await apiRequest("/api/session", {
      method: "POST",
      body: JSON.stringify({ user_token: token }),
    });
    elements.authToken.value = "";
    await refreshAdminSession();
    await refreshSession();
    if (state.auth.active) {
      await loadGraph();
    }
  } catch (err) {
    if (elements.authMessage) {
      elements.authMessage.textContent = err.message || "Authentication failed.";
    }
  }
}

async function handleLogout() {
  try {
    await apiRequest("/api/session", { method: "DELETE" });
    await apiRequest("/api/admin/logout", { method: "POST" });
  } catch (err) {
    logEvent("error", err.message || "Failed to sign out");
  }
  await refreshSession();
  await refreshAdminSession();
  if (state.auth.mode === "none") {
    showAuthOverlay("Session cleared. Enter a delegated token.");
  }
}

async function ensureRecipe(recipe) {
  if (!recipe) {
    throw new Error("Missing recipe definition");
  }
  try {
    await apiRequest(`/api/recipes/${recipe.name}`);
    return false;
  } catch (err) {
    if (err.status === 404) {
      await apiRequest("/api/recipes", {
        method: "POST",
        body: JSON.stringify(recipe),
      });
      return true;
    }
    throw err;
  }
}

async function applyRecipe(recipeName, containerName, parameters, options = {}) {
  const payload = {
    recipe_name: recipeName,
    container_name: containerName || options.container_name || undefined,
    parameters: parameters || options.parameters || undefined,
    include_dependencies:
      options.include_dependencies !== undefined ? options.include_dependencies : true,
    update_index: options.update_index !== undefined ? options.update_index : true,
    dry_run: Boolean(options.dry_run),
    probe_services: options.probe_services !== undefined ? options.probe_services : true,
  };
  return apiRequest("/api/recipes/apply", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

async function installRecipe(recipeName, containerName, parameters) {
  const recipe = RECIPE_CATALOG[recipeName];
  await ensureRecipe(recipe);
  return applyRecipe(recipeName, containerName, parameters);
}

async function installLampStack(containerName) {
  for (const dependency of LAMP_STACK_DEPENDENCIES) {
    await ensureRecipe(RECIPE_CATALOG[dependency]);
  }
  await ensureRecipe(RECIPE_CATALOG[LAMP_STACK_NAME]);
  return applyRecipe(LAMP_STACK_NAME, containerName);
}

async function probeContainerServices(containerName, options = {}) {
  const response = await apiRequest(`/api/containers/${containerName}/probe`, {
    method: "POST",
    body: JSON.stringify({
      services: SERVICE_PROBE_LIST,
      update_labels: options.updateLabels !== false,
    }),
  });
  state.probedContainers.add(containerName);
  if (options.log) {
    logEvent("success", `Service probe updated for ${containerName}`);
  }
  return response;
}

async function autoProbeContainers() {
  if (state.probeInFlight) {
    return;
  }
  const targets = state.containers.filter(
    (container) =>
      container.stack === "lamp" &&
      (!Array.isArray(container.services) || container.services.length === 0) &&
      !state.probedContainers.has(container.name)
  );
  if (!targets.length) {
    return;
  }
  state.probeInFlight = true;
  for (const container of targets) {
    try {
      await probeContainerServices(container.name, { updateLabels: true, log: false });
      state.probedContainers.add(container.name);
    } catch (err) {
      state.probedContainers.add(container.name);
    }
  }
  state.probeInFlight = false;
  await loadGraph({ skipProbe: true });
}

async function loadRoutes(options = {}) {
  state.routesLoading = true;
  renderPreview();
  try {
    const payload = await apiRequest("/api/routing");
    state.routes = payload && Array.isArray(payload.routes) ? payload.routes : [];
    if (options.log) {
      logEvent("success", "Routes refreshed");
    }
    return state.routes;
  } catch (err) {
    logEvent("error", err.message || "Failed to load routes");
    throw err;
  } finally {
    state.routesLoading = false;
    renderPreview();
  }
}

async function refreshRoute(domain) {
  const path = domain ? `/api/routing/refresh?domain=${encodeURIComponent(domain)}` : "/api/routing/refresh";
  const response = await apiRequest(path, { method: "POST" });
  logEvent("success", response.message || (domain ? `Route refreshed for ${domain}` : "Routes refreshed"));
  await loadRoutes();
  return response;
}

async function deleteRoute(domain) {
  const response = await apiRequest(`/api/routing/${encodeURIComponent(domain)}`, { method: "DELETE" });
  logEvent("success", response.message || `Route removed for ${domain}`);
  await loadRoutes();
  return response;
}

async function loadRecipes(options = {}) {
  state.recipesLoading = true;
  renderPreview();
  try {
    const payload = await apiRequest("/api/recipes");
    state.recipes = payload && Array.isArray(payload.recipes) ? payload.recipes : [];
    if (options.log) {
      logEvent("success", "Recipes refreshed");
    }
    return state.recipes;
  } catch (err) {
    logEvent("error", err.message || "Failed to load recipes");
    throw err;
  } finally {
    state.recipesLoading = false;
    renderPreview();
  }
}

async function seedRecipes(overwrite = false) {
  const response = await apiRequest("/api/recipes/seed", {
    method: "POST",
    body: JSON.stringify({ bundle: "lamp", overwrite }),
  });
  logEvent("success", response.message || "Recipes seeded");
  await loadRecipes();
  return response;
}

async function loadMonitoring(options = {}) {
  state.monitoringLoading = true;
  renderPreview();
  try {
    const payload = await apiRequest("/api/monitoring/resources");
    state.monitoring = payload || null;
    if (options.log) {
      logEvent("success", "Monitoring snapshot refreshed");
    }
    return state.monitoring;
  } catch (err) {
    logEvent("error", err.message || "Failed to load monitoring");
    throw err;
  } finally {
    state.monitoringLoading = false;
    renderPreview();
  }
}

async function loadFirewall(options = {}) {
  state.firewallLoading = true;
  renderPreview();
  try {
    const statusPayload = await apiRequest("/api/firewall/status");
    const rulesPayload = await apiRequest("/api/firewall/rules");
    state.firewall = {
      backend: statusPayload.backend || null,
      active: statusPayload.active,
      rules: (rulesPayload && rulesPayload.rules) || [],
    };
    if (options.log) {
      logEvent("success", "Firewall status refreshed");
    }
    return state.firewall;
  } catch (err) {
    logEvent("error", err.message || "Failed to load firewall");
    throw err;
  } finally {
    state.firewallLoading = false;
    renderPreview();
  }
}

async function loadVms(options = {}) {
  state.vmsLoading = true;
  renderPreview();
  try {
    const payload = await apiRequest("/api/vms");
    state.vms = payload && Array.isArray(payload.vms) ? payload.vms : [];
    if (options.log) {
      logEvent("success", "VMs refreshed");
    }
    return state.vms;
  } catch (err) {
    logEvent("error", err.message || "Failed to load VMs");
    throw err;
  } finally {
    state.vmsLoading = false;
    renderPreview();
  }
}

async function vmAction(name, action) {
  const path = action === "start" ? `/api/vms/${encodeURIComponent(name)}/start` : `/api/vms/${encodeURIComponent(name)}/stop`;
  const response = await apiRequest(path, { method: "POST" });
  logEvent("success", response.message || `VM ${action}: ${name}`);
  await loadVms();
  return response;
}

async function refreshVmStatus(name) {
  const response = await apiRequest(`/api/vms/${encodeURIComponent(name)}/status`);
  logEvent("success", `Status for ${name}: ${response.status || "ok"}`);
  await loadVms();
  return response;
}

async function loadHosts(options = {}) {
  state.hostsLoading = true;
  renderPreview();
  try {
    const payload = await apiRequest("/api/hosts");
    state.hosts = payload && Array.isArray(payload.hosts) ? payload.hosts : [];
    if (options.log) {
      logEvent("success", "Hosts refreshed");
    }
    return state.hosts;
  } catch (err) {
    logEvent("error", err.message || "Failed to load hosts");
    throw err;
  } finally {
    state.hostsLoading = false;
    renderPreview();
  }
}

async function probeHost(name) {
  const response = await apiRequest(`/api/hosts/${encodeURIComponent(name)}/probe`, {
    method: "POST",
    body: JSON.stringify({}),
  });
  logEvent("success", `Probe updated for ${name}`);
  await loadHosts();
  return response;
}

async function provisionHost(name) {
  const response = await apiRequest(`/api/hosts/${encodeURIComponent(name)}/provision`, {
    method: "POST",
    body: JSON.stringify({ profile: "ubuntu" }),
  });
  logEvent("success", response.message || `Provisioning triggered for ${name}`);
  await loadHosts();
  return response;
}

async function deleteHost(name) {
  const response = await apiRequest(`/api/hosts/${encodeURIComponent(name)}`, { method: "DELETE" });
  logEvent("success", response.message || `Host ${name} removed`);
  await loadHosts();
  return response;
}

async function handleAction(actionId, node, params = {}) {
  if (actionId === "refresh") {
    state.probedContainers.clear();
    await loadGraph();
    logEvent("success", "Synced fortress state");
    return;
  }

  if (actionId === "monitoring-refresh") {
    await loadMonitoring({ log: true });
    return;
  }

  if (actionId === "firewall-open") {
    openWizard("firewall", null, { firewallMode: "open" });
    return;
  }

  if (actionId === "firewall-close") {
    openWizard("firewall", null, { firewallMode: "close" });
    return;
  }

  if (actionId === "firewall-refresh") {
    await loadFirewall({ log: true });
    return;
  }

  if (actionId === "vms-refresh") {
    await loadVms({ log: true });
    return;
  }

  if (actionId === "vm-start" || actionId === "vm-stop" || actionId === "vm-status") {
    const name = params.vm;
    if (!name) {
      logEvent("error", "VM name missing");
      return;
    }
    if (actionId === "vm-status") {
      await refreshVmStatus(name);
    } else {
      await vmAction(name, actionId === "vm-start" ? "start" : "stop");
    }
    return;
  }

  if (actionId === "routing-add") {
    openWizard("routing");
    return;
  }

  if (actionId === "routing-refresh") {
    await refreshRoute();
    return;
  }

  if (actionId === "route-refresh") {
    const domain = params.domain;
    if (!domain) {
      logEvent("error", "Route domain missing");
      return;
    }
    await refreshRoute(domain);
    return;
  }

  if (actionId === "route-delete") {
    const domain = params.domain;
    if (!domain) {
      logEvent("error", "Route domain missing");
      return;
    }
    const confirmed = window.confirm(`Remove routing for ${domain}?`);
    if (!confirmed) {
      return;
    }
    await deleteRoute(domain);
    return;
  }

  if (actionId === "recipes-refresh") {
    await loadRecipes({ log: true });
    return;
  }

  if (actionId === "recipes-seed") {
    await seedRecipes(false);
    return;
  }

  if (actionId === "recipes-apply") {
    const contextContainer = node && node.context ? node.context.container : null;
    await loadRecipes();
    openWizard("recipe-apply", contextContainer);
    if (params.recipe) {
      state.wizard.recipe.name = params.recipe;
      renderWizard();
    }
    return;
  }

  if (actionId === "packages-install" || actionId === "packages-remove" || actionId === "packages-update") {
    const mode = actionId === "packages-remove" ? "remove" : actionId === "packages-update" ? "update" : "install";
    const contextContainer = node && node.context ? node.context.container : null;
    openWizard("packages", contextContainer, { packageMode: mode });
    return;
  }

  if (actionId === "hosts-refresh") {
    await loadHosts({ log: true });
    return;
  }

  if (actionId === "hosts-create") {
    openWizard("host-create");
    return;
  }

  if (actionId === "host-probe") {
    const hostName = params.host;
    if (!hostName) {
      logEvent("error", "Host name missing");
      return;
    }
    await probeHost(hostName);
    return;
  }

  if (actionId === "host-provision") {
    const hostName = params.host;
    if (!hostName) {
      logEvent("error", "Host name missing");
      return;
    }
    await provisionHost(hostName);
    return;
  }

  if (actionId === "host-delete") {
    const hostName = params.host;
    if (!hostName) {
      logEvent("error", "Host name missing");
      return;
    }
    const confirmed = window.confirm(`Delete host ${hostName}?`);
    if (!confirmed) {
      return;
    }
    await deleteHost(hostName);
    return;
  }

  if (actionId === "open-routing") {
    const contextContainer = node && node.context ? node.context.container : null;
    if (contextContainer) {
      openWizard("routing", contextContainer);
      return;
    }
    if (state.nodesById.has("routing")) {
      selectNode("routing");
    } else {
      logEvent("error", "Routing app not available");
    }
    return;
  }

  if (actionId === "create-container") {
    openWizard("create-container");
    return;
  }

  const contextContainer = node && node.context ? node.context.container : null;
  if (!contextContainer) {
    logEvent("error", "No container selected for this action");
    return;
  }

  if (actionId === "network-expose") {
    openWizard("network", contextContainer);
    return;
  }

  if (actionId === "probe-services") {
    await probeContainerServices(contextContainer, { updateLabels: true, log: true });
    await loadGraph({ skipProbe: true });
    return;
  }

  if (actionId === "install-lamp") {
    const response = await installLampStack(contextContainer);
    logEvent("success", response.message || `LAMP stack applied to ${contextContainer}`);
    await probeContainerServices(contextContainer, { updateLabels: true, log: false });
    await loadGraph({ skipProbe: true });
    return;
  }

  if (actionId === "install-filemanager") {
    openWizard("filemanager", contextContainer);
    return;
  }

  const serviceRecipe = SERVICE_ACTIONS[actionId];
  if (serviceRecipe) {
    const response = await installRecipe(serviceRecipe, contextContainer);
    logEvent("success", response.message || `${serviceRecipe} applied to ${contextContainer}`);
    await probeContainerServices(contextContainer, { updateLabels: true, log: false });
    await loadGraph({ skipProbe: true });
    return;
  }

  if (actionId === "open-ssh" || actionId === "open-ftp") {
    const service = actionId === "open-ftp" ? "ftp" : "ssh";
    const response = await apiRequest(`/api/containers/${contextContainer}/access`, {
      method: "POST",
      body: JSON.stringify({ service }),
    });
    logEvent("success", response.message || `Access opened for ${contextContainer}`);
    return;
  }

  if (actionId === "backup-container") {
    const response = await apiRequest(`/api/containers/${contextContainer}/backup`, { method: "POST" });
    logEvent("success", response.message || `Backup triggered for ${contextContainer}`);
    return;
  }

  if (actionId === "delete-container") {
    const confirmed = window.confirm(`Delete container ${contextContainer}?`);
    if (!confirmed) {
      return;
    }
    const response = await apiRequest(`/api/containers/${contextContainer}`, { method: "DELETE" });
    logEvent("success", response.message || `Deleted ${contextContainer}`);
    await loadGraph();
    return;
  }

  logEvent("error", `Unhandled action: ${actionId}`);
}

async function handleWizardAction(action) {
  if (!state.wizard.active) {
    return;
  }
  if (action === "close") {
    state.wizard.active = false;
    state.wizard.error = null;
    state.wizard.mode = null;
    renderWizard();
    return;
  }
  if (action === "back") {
    state.wizard.step = Math.max(0, state.wizard.step - 1);
    renderWizard();
    return;
  }
  if (action === "next") {
    const stepCounts = {
      "create-container": 3,
      routing: 3,
      filemanager: 2,
      packages: 2,
      "recipe-apply": 3,
      "host-create": 3,
      network: 2,
      firewall: 2,
    };
    const steps = stepCounts[state.wizard.mode] || 1;
    if (state.wizard.step < steps - 1) {
      state.wizard.step += 1;
      renderWizard();
      return;
    }
    state.wizard.busy = true;
    state.wizard.error = null;
    renderWizard();
    try {
      if (state.wizard.mode === "create-container") {
        const payload = {
          name: state.wizard.form.name.trim(),
          distro: state.wizard.form.distro,
          cpu_limit: state.wizard.form.cpu_limit,
          ram_limit: state.wizard.form.ram_limit,
          disk_limit: state.wizard.form.disk_limit,
        };
        if (!payload.name) {
          throw new Error("Container name is required");
        }
        await apiRequest("/api/containers", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        logEvent("success", `Container ${payload.name} created`);
        state.wizard.active = false;
        state.wizard.mode = null;
        await loadGraph();
      } else if (state.wizard.mode === "routing") {
        const routing = state.wizard.routing;
        const containerName = routing.container_name || state.wizard.context.container;
        if (!containerName) {
          throw new Error("Container is required for routing");
        }
        if (!routing.domain.trim()) {
          throw new Error("Domain is required");
        }
        const payload = {
          domain: routing.domain.trim(),
          container_name: containerName,
          container_port: Number.parseInt(routing.container_port, 10) || 80,
          container_interface: routing.container_interface || "eth0",
          listen_address: routing.listen_address || "0.0.0.0",
          listen_port: Number.parseInt(routing.listen_port, 10) || 80,
        };
        const tlsMode = routing.tls_mode || "manual";
        let tlsPayload = null;
        if (tlsMode !== "disabled") {
          tlsPayload = {
            mode: tlsMode,
            listen_port: Number.parseInt(routing.tls_port, 10) || 443,
            redirect_http: Boolean(routing.redirect_http),
          };
          if (tlsMode === "manual") {
            tlsPayload.cert_path = routing.cert_path.trim();
            tlsPayload.key_path = routing.key_path.trim();
            tlsPayload.chain_path = routing.chain_path.trim() || undefined;
          } else if (tlsMode === "letsencrypt") {
            tlsPayload.email = routing.tls_email.trim();
            tlsPayload.staging = Boolean(routing.tls_staging);
          }
        }
        payload.tls = tlsPayload;
        if (tlsMode === "manual" && tlsPayload && (!tlsPayload.cert_path || !tlsPayload.key_path)) {
          throw new Error("TLS cert and key paths are required");
        }
        if (tlsMode === "letsencrypt" && tlsPayload && !tlsPayload.email) {
          throw new Error("Let's Encrypt email is required");
        }
        if (tlsPayload && tlsPayload.listen_port === payload.listen_port) {
          throw new Error("TLS listen port must differ from HTTP listen port");
        }
        await apiRequest("/api/routing", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        logEvent("success", `Routing applied for ${payload.domain}`);
        state.wizard.active = false;
        state.wizard.mode = null;
        await loadRoutes();
      } else if (state.wizard.mode === "packages") {
        const pkg = state.wizard.packages;
        const mode = pkg.mode;
        const target = pkg.target && pkg.target.trim() ? pkg.target.trim() : "";
        const packages = pkg.packages ? parsePackagesInput(pkg.packages) : [];
        if (mode !== "update" && packages.length === 0) {
          throw new Error("At least one package is required");
        }
        let response;
        if (mode === "install") {
          response = await apiRequest("/api/packages/install", {
            method: "POST",
            body: JSON.stringify({
              packages,
              container_name: target || undefined,
              update_index: Boolean(pkg.update_index),
            }),
          });
        } else if (mode === "remove") {
          response = await apiRequest("/api/packages/remove", {
            method: "POST",
            body: JSON.stringify({
              packages,
              container_name: target || undefined,
            }),
          });
        } else {
          response = await apiRequest("/api/packages/update", {
            method: "POST",
            body: JSON.stringify({
              container_name: target || undefined,
              full_upgrade: Boolean(pkg.full_upgrade),
            }),
          });
        }
        logEvent("success", response.message || `Packages ${mode} on ${target || "host"}`);
        state.wizard.active = false;
        state.wizard.mode = null;
      } else if (state.wizard.mode === "recipe-apply") {
        const recipe = state.wizard.recipe;
        const recipeName = recipe.name ? recipe.name.trim() : "";
        if (!recipeName) {
          throw new Error("Recipe name is required");
        }
        const target = recipe.target && recipe.target.trim() ? recipe.target.trim() : "";
        const parameters = parseParametersInput(recipe.parameters);
        const response = await applyRecipe(recipeName, target || null, parameters, {
          include_dependencies: Boolean(recipe.include_dependencies),
          update_index: Boolean(recipe.update_index),
          dry_run: Boolean(recipe.dry_run),
          probe_services: true,
        });
        logEvent(
          "success",
          response.message ||
            (recipe.dry_run ? `Plan generated for ${recipeName}` : `Recipe ${recipeName} applied`)
        );
        if (target) {
          await probeContainerServices(target, { updateLabels: true, log: false });
          await loadGraph({ skipProbe: true });
        }
        state.wizard.active = false;
        state.wizard.mode = null;
      } else if (state.wizard.mode === "host-create") {
        const host = state.wizard.host;
        const payload = {
          name: host.name ? host.name.trim() : "",
          os_type: host.os_type ? host.os_type.trim() : undefined,
          notes: host.notes ? host.notes.trim() : undefined,
        };
        if (!payload.name) {
          throw new Error("Host name is required");
        }
        const sshHost = host.host ? host.host.trim() : "";
        const sshUser = host.username ? host.username.trim() : "";
        if (!sshHost || !sshUser) {
          throw new Error("SSH host and username are required");
        }
        payload.ssh = {
          host: sshHost,
          username: sshUser,
          port: Number.parseInt(host.port, 10) || 22,
          key_path: host.key_path ? host.key_path.trim() : undefined,
          password: host.password || undefined,
        };
        const response = await apiRequest("/api/hosts", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        logEvent("success", response.message || `Host ${payload.name} created`);
        state.wizard.active = false;
        state.wizard.mode = null;
        await loadHosts();
      } else if (state.wizard.mode === "network") {
        const net = state.wizard.network;
        const containerName = net.container_name || state.wizard.context.container;
        if (!containerName) {
          throw new Error("Container is required");
        }
        const containerPort = Number.parseInt(net.container_port, 10) || null;
        const hostPort = Number.parseInt(net.host_port || net.container_port, 10) || null;
        if (!containerPort || !hostPort) {
          throw new Error("Container and host ports are required");
        }
        const exposure = {
          protocol: net.protocol || "tcp",
          bind_address: net.bind_address || "0.0.0.0",
          host_ports: [hostPort],
          container_port: containerPort,
          target_interface: net.target_interface || "eth0",
          target_address: net.target_address || undefined,
          open_firewall: Boolean(net.open_firewall),
        };
        await apiRequest("/api/containers/expose", {
          method: "POST",
          body: JSON.stringify({ container_name: containerName, exposures: [exposure] }),
        });
        logEvent("success", `Port ${hostPort} exposed to ${containerName}:${containerPort}`);
        state.wizard.active = false;
        state.wizard.mode = null;
      } else if (state.wizard.mode === "firewall") {
        const fw = state.wizard.firewall;
        const port = Number.parseInt(fw.port, 10);
        if (!port) {
          throw new Error("Port is required");
        }
        const payload = {
          port,
          protocol: fw.protocol || "tcp",
          source: fw.source || undefined,
        };
        const path = fw.mode === "close" ? "/api/firewall/close" : "/api/firewall/open";
        const response = await apiRequest(path, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        logEvent("success", response.message || `Firewall ${fw.mode} ${port}/${payload.protocol}`);
        state.wizard.active = false;
        state.wizard.mode = null;
        await loadFirewall();
      } else if (state.wizard.mode === "filemanager") {
        const containerName = state.wizard.context.container;
        if (!containerName) {
          throw new Error("Container is required for file manager install");
        }
        if (!state.wizard.filemanager.username.trim()) {
          throw new Error("File manager username is required");
        }
        if (!state.wizard.filemanager.password) {
          throw new Error("File manager password is required");
        }
        const response = await installRecipe("lamp-filemanager", containerName, {
          fm_user: state.wizard.filemanager.username.trim(),
          fm_password: state.wizard.filemanager.password,
        });
        logEvent("success", response.message || `File manager installed on ${containerName}`);
        await probeContainerServices(containerName, { updateLabels: true, log: false });
        await loadGraph({ skipProbe: true });
        state.wizard.active = false;
        state.wizard.mode = null;
      }
    } catch (err) {
      state.wizard.error = err.message || "Wizard action failed";
    } finally {
      state.wizard.busy = false;
      renderWizard();
    }
  }
}

async function loadGraph(options = {}) {
  if (!state.auth.active) {
    showAuthOverlay("Session required. Enter a delegated token.");
    return;
  }
  const response = await apiRequest("/api/apps", { method: "GET" });
  state.nodes = response.nodes || [];
  state.rootId = response.rootId || "home";
  state.containers = response.containers || [];
  state.fortress = response.fortress || { status: "unknown" };
  buildNodeIndex(state.nodes);
  if (!state.selectedId || !state.nodesById.has(state.selectedId)) {
    state.selectedId = state.rootId;
  }
  renderAll();
  if (["routing", "recipes", "hosts", "monitoring", "firewall", "vms"].includes(state.selectedId)) {
    await hydrateNode(state.selectedId);
  }
  if (!options.skipProbe) {
    autoProbeContainers().catch(() => {});
  }
}

function bindEvents() {
  document.addEventListener("click", async (event) => {
    const action = event.target.closest("[data-action-id]");
    if (action) {
      event.stopPropagation();
      const nodeId = action.getAttribute("data-node-id");
      const node = nodeId ? getNode(nodeId) : getNode(state.selectedId);
      const params = { ...action.dataset };
      delete params.actionId;
      delete params.nodeId;
      try {
        await handleAction(action.getAttribute("data-action-id"), node, params);
      } catch (err) {
        logEvent("error", err.message || "Action failed");
      }
      return;
    }

    const card = event.target.closest(".app-card");
    if (card) {
      selectNode(card.getAttribute("data-node-id"));
      return;
    }

    const treeItem = event.target.closest(".tree-item");
    if (treeItem) {
      selectNode(treeItem.getAttribute("data-node-id"));
    }
  });

  elements.wizard.addEventListener("click", (event) => {
    const action = event.target.closest("[data-wizard-action]");
    if (!action) {
      return;
    }
    handleWizardAction(action.getAttribute("data-wizard-action"));
  });

  elements.wizard.addEventListener("input", (event) => {
    const target = event.target;
    if (!target.name) {
      return;
    }
    const group = target.getAttribute("data-wizard-group") || "form";
    const value = target.type === "checkbox" ? target.checked : target.value;
    if (group === "routing") {
      state.wizard.routing[target.name] = value;
      if (target.name === "tls_mode") {
        renderWizard();
      }
    } else if (group === "filemanager") {
      state.wizard.filemanager[target.name] = value;
    } else if (group === "packages") {
      state.wizard.packages[target.name] = value;
    } else if (group === "recipe") {
      state.wizard.recipe[target.name] = value;
    } else if (group === "host") {
      state.wizard.host[target.name] = value;
    } else if (group === "network") {
      state.wizard.network[target.name] = value;
    } else if (group === "firewall") {
      state.wizard.firewall[target.name] = value;
    } else {
      state.wizard.form[target.name] = value;
    }
  });
}

window.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  if (elements.authForm) {
    elements.authForm.addEventListener("submit", handleLogin);
  }
  if (elements.adminForm) {
    elements.adminForm.addEventListener("submit", handleAdminLogin);
  }
  if (elements.adminBootstrapForm) {
    elements.adminBootstrapForm.addEventListener("submit", handleAdminBootstrap);
  }
  if (elements.logoutButton) {
    elements.logoutButton.addEventListener("click", handleLogout);
  }
  if (elements.adminBootstrapButton) {
    elements.adminBootstrapButton.addEventListener("click", () => {
      showAdminOverlay("Admin bootstrap required. Use the Create admin form below.");
    });
  }
  refreshAdminSession()
    .then((payload) => {
      if (payload && payload.active) {
        return refreshSession();
      }
      return null;
    })
    .then(() => {
      if (state.auth.active && state.admin.active) {
        return loadGraph();
      }
      return null;
    })
    .catch((err) => {
      logEvent("error", err.message || "Failed to load apps");
    });
});
