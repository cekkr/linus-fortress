const state = {
  nodes: [],
  nodesById: new Map(),
  rootId: "home",
  selectedId: null,
  containers: [],
  containerIndex: new Map(),
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
      container_port: "80",
      container_interface: "eth0",
      listen_address: "0.0.0.0",
      listen_port: "80",
      tls_enabled: true,
      cert_path: "",
      key_path: "",
      chain_path: "",
      tls_port: "443",
      redirect_http: true,
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
  adminForm: document.getElementById("admin-form"),
  adminUsername: document.getElementById("admin-username"),
  adminPassword: document.getElementById("admin-password"),
  adminTotp: document.getElementById("admin-totp"),
  adminMessage: document.getElementById("admin-message"),
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
      "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y apache2 apache2-utils libapache2-mod-php php php-cli php-mysql php-curl php-xml php-zip php-mbstring; systemctl enable --now apache2 >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y httpd httpd-tools php php-cli php-mysqlnd php-xml php-gd php-mbstring; systemctl enable --now httpd >/dev/null 2>&1 || true; fi",
    ]
  ),
  "lamp-nginx": buildRecipeDefinition(
    "lamp-nginx",
    "Install Nginx with PHP-FPM.",
    [
      "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y nginx php-fpm php-cli php-mysql php-curl php-xml php-zip php-mbstring; systemctl enable --now nginx php-fpm >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y nginx php-fpm php-cli php-mysqlnd php-xml php-gd php-mbstring; systemctl enable --now nginx php-fpm >/dev/null 2>&1 || true; fi",
    ]
  ),
  "lamp-mysql": buildRecipeDefinition(
    "lamp-mysql",
    "Install MariaDB or MySQL engine.",
    [
      "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client; systemctl enable --now mariadb >/dev/null 2>&1 || systemctl enable --now mysql >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y mariadb-server mariadb; systemctl enable --now mariadb >/dev/null 2>&1 || true; fi",
    ]
  ),
  "lamp-ftp": buildRecipeDefinition(
    "lamp-ftp",
    "Install vsftpd for legacy FTP.",
    [
      "if command -v apt-get >/dev/null 2>&1; then apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y vsftpd; systemctl enable --now vsftpd >/dev/null 2>&1 || true; elif command -v dnf >/dev/null 2>&1; then dnf makecache && dnf install -y vsftpd; systemctl enable --now vsftpd >/dev/null 2>&1 || true; fi",
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
    container_port: "80",
    container_interface: "eth0",
    listen_address: "0.0.0.0",
    listen_port: "80",
    tls_enabled: true,
    cert_path: "",
    key_path: "",
    chain_path: "",
    tls_port: "443",
    redirect_http: true,
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

function openWizard(mode, contextContainer) {
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

function renderPreview() {
  const node = getNode(state.selectedId || state.rootId);
  if (!node) {
    elements.preview.textContent = "Select an app to preview.";
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
    const containerName = wizard.context.container || "container";
    steps = ["Domain", "TLS", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div>Route HTTPS for ${containerName}.</div>
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
      const tlsDisabled = routing.tls_enabled ? "" : "disabled";
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-tls-enabled">Enable TLS</label>
          <input id="wiz-tls-enabled" type="checkbox" name="tls_enabled" data-wizard-group="routing" ${routing.tls_enabled ? "checked" : ""} />
        </div>
        <div class="wizard-field">
          <label for="wiz-cert-path">Cert path</label>
          <input id="wiz-cert-path" name="cert_path" data-wizard-group="routing" value="${routing.cert_path}" placeholder="/etc/letsencrypt/live/app/fullchain.pem" ${tlsDisabled} />
        </div>
        <div class="wizard-field">
          <label for="wiz-key-path">Key path</label>
          <input id="wiz-key-path" name="key_path" data-wizard-group="routing" value="${routing.key_path}" placeholder="/etc/letsencrypt/live/app/privkey.pem" ${tlsDisabled} />
        </div>
        <div class="wizard-field">
          <label for="wiz-chain-path">Chain path (optional)</label>
          <input id="wiz-chain-path" name="chain_path" data-wizard-group="routing" value="${routing.chain_path}" placeholder="/etc/letsencrypt/live/app/chain.pem" ${tlsDisabled} />
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
            <span>${containerName}</span>
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
            <span>${routing.tls_enabled ? "enabled" : "disabled"}</span>
          </div>
          <div>
            <strong>TLS Port</strong>
            <span>${routing.tls_port}</span>
          </div>
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
}

function logEvent(type, message) {
  const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  state.events.unshift({ type, message, time });
  state.events = state.events.slice(0, 6);
  renderEvents();
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
  updateAdminUI();
}

function updateAdminUI() {
  const locked = !state.admin.active;
  if (elements.adminOverlay) {
    elements.adminOverlay.hidden = !locked;
  }
  if (!locked && elements.adminMessage) {
    elements.adminMessage.textContent = "";
  }
  if (state.admin.bootstrapRequired && elements.adminMessage) {
    elements.adminMessage.textContent = "Admin bootstrap required. Use the /api/admin/bootstrap endpoint.";
  }
}

function showAdminOverlay(message) {
  state.admin.active = false;
  if (elements.adminOverlay) {
    elements.adminOverlay.hidden = false;
  }
  if (elements.adminMessage) {
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
  if (elements.authOverlay) {
    elements.authOverlay.hidden = !locked || !state.admin.active;
  }
  if (elements.logoutButton) {
    elements.logoutButton.hidden = !state.auth.session;
  }
  if (!locked && elements.authMessage) {
    elements.authMessage.textContent = "";
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

async function applyRecipe(recipeName, containerName, parameters) {
  return apiRequest("/api/recipes/apply", {
    method: "POST",
    body: JSON.stringify({
      recipe_name: recipeName,
      container_name: containerName,
      parameters: parameters || undefined,
      include_dependencies: true,
      update_index: true,
    }),
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

async function handleAction(actionId, node) {
  if (actionId === "refresh") {
    state.probedContainers.clear();
    await loadGraph();
    logEvent("success", "Synced fortress state");
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
        const containerName = state.wizard.context.container;
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
          tls: routing.tls_enabled
            ? {
                cert_path: routing.cert_path.trim(),
                key_path: routing.key_path.trim(),
                chain_path: routing.chain_path.trim() || undefined,
                listen_port: Number.parseInt(routing.tls_port, 10) || 443,
                redirect_http: Boolean(routing.redirect_http),
              }
            : null,
        };
        if (payload.tls && (!payload.tls.cert_path || !payload.tls.key_path)) {
          throw new Error("TLS cert and key paths are required");
        }
        if (payload.tls && payload.tls.listen_port === payload.listen_port) {
          throw new Error("TLS listen port must differ from HTTP listen port");
        }
        await apiRequest("/api/routing", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        logEvent("success", `Routing applied for ${payload.domain}`);
        state.wizard.active = false;
        state.wizard.mode = null;
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
      try {
        await handleAction(action.getAttribute("data-action-id"), node);
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
      if (target.name === "tls_enabled") {
        renderWizard();
      }
    } else if (group === "filemanager") {
      state.wizard.filemanager[target.name] = value;
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
  if (elements.logoutButton) {
    elements.logoutButton.addEventListener("click", handleLogout);
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
