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
  firewallPreviousRules: [],
  vms: [],
  vmsLoading: false,
  containerSnapshots: new Map(),
  containerSnapshotLoading: new Set(),
  siteDetails: new Map(),
  siteDetailsLoading: new Set(),
  siteBackups: new Map(),
  siteBackupsLoading: new Set(),
  sites: [],
  sitesLoading: false,
  routes: [],
  routesLoading: false,
  recipes: [],
  recipesLoading: false,
  recipeReports: new Map(),
  recipeReportOrder: [],
  hosts: [],
  hostsLoading: false,
  systemUpgrade: {
    lastPreflight: null,
    lastExecution: null,
    lastUpdateReload: null,
  },
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
  debug: {
    lastError: null,
  },
  probedContainers: new Set(),
  probeInFlight: false,
  images: {
    popular: [],
    remotes: [],
    latest: null,
    refreshedAt: null,
    loading: false,
    error: null,
    remoteFilter: "all",
    hideUnavailable: false,
  },
  ui: {
    fastActions: [],
    expandedCardId: null,
    cardsAnimated: false,
  },
  wizard: {
    active: false,
    mode: null,
    step: 0,
    prevStep: 0,
    maxStep: 0,
    busy: false,
    error: null,
    context: {
      container: null,
    },
    form: {
      name: "",
      distro: "ubuntu:lts",
      cpu_limit: "1",
      ram_limit: "512MB",
      disk_limit: "10GB",
    },
    imagePreset: {
      alias: "",
      label: "",
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
    upgrade: {
      update_packages: true,
      full_upgrade: false,
      apply_migrations: true,
      preflight: null,
      migration_status: null,
      backups: [],
      backup_confirmation: false,
      preflight_at: null,
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
    vmSnapshot: {
      name: "",
    },
    containerSnapshot: {
      name: "",
      stateful: false,
    },
    exec: {
      command: "",
      user: "",
      workdir: "",
      environment: "",
    },
    siteCreate: {
      name: "",
      primary_domain: "",
      domains: "",
      container_name: "",
      docroot: "/var/www/html",
      php_version: "",
      create_database: true,
      create_user: true,
    },
    siteDeploy: {
      site_id: "",
      source_type: "git",
      source: "",
      ref: "",
      subdir: "",
      strip_components: 0,
      post_deploy_commands: "",
      restart_services: true,
    },
    siteBackup: {
      site_id: "",
      include_database: true,
      label: "",
    },
    siteRollback: {
      site_id: "",
      backup_id: "",
      restart_services: true,
    },
    siteServices: {
      site_id: "",
      services: "",
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
  layout: document.getElementById("layout"),
  tree: document.getElementById("tree"),
  fastActions: document.getElementById("fast-actions"),
  grid: document.getElementById("app-grid"),
  imageCatalog: document.getElementById("image-catalog"),
  wizardStage: document.getElementById("wizard-stage"),
  preview: document.getElementById("preview"),
  wizard: document.getElementById("wizard"),
  operation: document.getElementById("operation"),
  eventLog: document.getElementById("event-log"),
  debugPanel: document.getElementById("debug-panel"),
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

const FAST_ACTION_STORAGE_KEY = "lizard.fast-actions.v1";
const IMAGE_CATALOG_REFRESH_INTERVAL_MS = 10 * 60 * 1000;
let imageCatalogRefreshTimer = null;
let gridResizeTimer = null;
const CARD_SWITCH_SEQUENCE_MS = 500;
const CARD_OPEN_SEQUENCE_MS = 420;
let cardTransitionTimer = null;
let cardTransitionBusy = false;
let queuedExpandNodeId = null;
const FAST_ACTION_OPTIONS = [
  {
    id: "refresh",
    label: "Sync Deck",
    variant: "ghost",
    description: "Reload cards and latest API state.",
  },
  {
    id: "create-container",
    label: "New Container",
    variant: "primary",
    description: "Open the container creation wizard.",
  },
  {
    id: "system-update-reload",
    label: "Check Update + Reload",
    variant: "primary",
    description: "Pull latest git changes, run migrations, and reload services.",
  },
  {
    id: "system-upgrade",
    label: "System Upgrade",
    variant: "ghost",
    description: "Run guided package + migration host upgrade.",
  },
  {
    id: "monitoring-refresh",
    label: "Refresh Monitoring",
    variant: "ghost",
    description: "Fetch latest host/container resource telemetry.",
  },
  {
    id: "routing-refresh",
    label: "Refresh Routes",
    variant: "ghost",
    description: "Reload current routing records from API.",
  },
  {
    id: "firewall-refresh",
    label: "Refresh Firewall",
    variant: "ghost",
    description: "Reload firewall rules and diff view.",
  },
  {
    id: "recipes-refresh",
    label: "Refresh Recipes",
    variant: "ghost",
    description: "Reload the recipe catalog.",
  },
  {
    id: "hosts-refresh",
    label: "Refresh Hosts",
    variant: "ghost",
    description: "Reload SSH-managed host inventory.",
  },
  {
    id: "vms-refresh",
    label: "Refresh VMs",
    variant: "ghost",
    description: "Reload VM lab list and statuses.",
  },
  {
    id: "sites-refresh",
    label: "Refresh Sites",
    variant: "ghost",
    description: "Reload sites and backup metadata.",
  },
];
const FAST_ACTION_DEFAULT_IDS = [
  "refresh",
  "create-container",
  "system-update-reload",
  "system-upgrade",
  "monitoring-refresh",
];

const WIZARD_STEP_COUNTS = {
  "create-container": 3,
  routing: 3,
  filemanager: 2,
  packages: 2,
  "system-upgrade": 4,
  "recipe-apply": 3,
  "host-create": 3,
  network: 2,
  firewall: 2,
  "vm-snapshot": 2,
  "container-snapshot": 2,
  exec: 2,
  "site-create": 3,
  "site-deploy": 3,
  "site-backup": 2,
  "site-rollback": 2,
  "site-services": 2,
};

const WIZARD_MODE_LABELS = {
  "create-container": "Create Container",
  routing: "Configure Routing",
  filemanager: "Install File Manager",
  packages: "Package Operation",
  "system-upgrade": "System Upgrade",
  "recipe-apply": "Apply Recipe",
  "host-create": "Add Host",
  network: "Expose Network Port",
  firewall: "Firewall Rule",
  "vm-snapshot": "VM Snapshot",
  "container-snapshot": "Container Snapshot",
  exec: "Container Exec",
  "site-create": "Create Site",
  "site-deploy": "Deploy Site",
  "site-backup": "Site Backup",
  "site-rollback": "Site Rollback",
  "site-services": "Restart Site Services",
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
  gear: `
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="3"></circle>
      <path d="M19.4 15a1 1 0 00.2 1.1l.1.1a1 1 0 01-1.4 1.4l-.1-.1a1 1 0 00-1.1-.2 1 1 0 00-.6.9V20a1 1 0 01-2 0v-.2a1 1 0 00-.6-.9 1 1 0 00-1.1.2l-.1.1a1 1 0 01-1.4-1.4l.1-.1a1 1 0 00.2-1.1 1 1 0 00-.9-.6H8a1 1 0 010-2h.2a1 1 0 00.9-.6 1 1 0 00-.2-1.1l-.1-.1a1 1 0 011.4-1.4l.1.1a1 1 0 001.1.2 1 1 0 00.6-.9V8a1 1 0 012 0v.2a1 1 0 00.6.9 1 1 0 001.1-.2l.1-.1a1 1 0 011.4 1.4l-.1.1a1 1 0 00-.2 1.1 1 1 0 00.9.6H20a1 1 0 010 2h-.2a1 1 0 00-.4.1z"></path>
    </svg>
  `,
};

function fastActionOptionById(id) {
  return FAST_ACTION_OPTIONS.find((item) => item.id === id) || null;
}

function normalizeFastActions(rawActions) {
  const source = Array.isArray(rawActions) ? rawActions : [];
  const knownIds = new Set(FAST_ACTION_OPTIONS.map((item) => item.id));
  const normalized = [];
  for (const raw of source) {
    const id = String(raw || "").trim();
    if (!id || !knownIds.has(id) || normalized.includes(id)) {
      continue;
    }
    normalized.push(id);
  }
  return normalized.length ? normalized : FAST_ACTION_DEFAULT_IDS.slice();
}

function loadFastActionsPreference() {
  try {
    if (typeof window === "undefined" || !window.localStorage) {
      state.ui.fastActions = FAST_ACTION_DEFAULT_IDS.slice();
      return;
    }
    const raw = window.localStorage.getItem(FAST_ACTION_STORAGE_KEY);
    if (!raw) {
      state.ui.fastActions = FAST_ACTION_DEFAULT_IDS.slice();
      return;
    }
    const parsed = JSON.parse(raw);
    state.ui.fastActions = normalizeFastActions(parsed);
  } catch (err) {
    state.ui.fastActions = FAST_ACTION_DEFAULT_IDS.slice();
  }
}

function persistFastActionsPreference() {
  try {
    if (typeof window === "undefined" || !window.localStorage) {
      return;
    }
    window.localStorage.setItem(FAST_ACTION_STORAGE_KEY, JSON.stringify(state.ui.fastActions || []));
  } catch (err) {
    // Ignore storage errors.
  }
}

function updateFastActions(nextActions) {
  state.ui.fastActions = normalizeFastActions(nextActions);
  persistFastActionsPreference();
}

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
  const latest = state.images && state.images.latest && state.images.latest.ubuntu_lts ? state.images.latest.ubuntu_lts : "ubuntu:lts";
  state.wizard.form = {
    name: "",
    distro: latest,
    cpu_limit: "1",
    ram_limit: "512MB",
    disk_limit: "10GB",
  };
  state.wizard.imagePreset = { alias: "", label: "" };
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

function resetUpgradeWizard() {
  state.wizard.upgrade = {
    update_packages: true,
    full_upgrade: false,
    apply_migrations: true,
    preflight: null,
    migration_status: null,
    backups: [],
    backup_confirmation: false,
    preflight_at: null,
  };
  state.wizard.context.container = null;
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

function resetVmSnapshotWizard(vmName) {
  state.wizard.vmSnapshot = {
    name: "",
  };
  state.wizard.context.vm = vmName || null;
}

function resetContainerSnapshotWizard(containerName) {
  state.wizard.containerSnapshot = {
    name: "",
    stateful: false,
  };
  state.wizard.context.container = containerName || null;
}

function resetExecWizard(containerName) {
  state.wizard.exec = {
    command: "",
    user: "",
    workdir: "",
    environment: "",
  };
  state.wizard.context.container = containerName || null;
}

function resetSiteCreateWizard() {
  state.wizard.siteCreate = {
    name: "",
    primary_domain: "",
    domains: "",
    container_name: state.containers[0] ? state.containers[0].name : "",
    docroot: "/var/www/html",
    php_version: "",
    create_database: true,
    create_user: true,
  };
  state.wizard.context.container = null;
}

function resetSiteDeployWizard(siteId) {
  state.wizard.siteDeploy = {
    site_id: siteId || "",
    source_type: "git",
    source: "",
    ref: "",
    subdir: "",
    strip_components: 0,
    post_deploy_commands: "",
    restart_services: true,
  };
}

function resetSiteBackupWizard(siteId) {
  state.wizard.siteBackup = {
    site_id: siteId || "",
    include_database: true,
    label: "",
  };
}

function resetSiteRollbackWizard(siteId) {
  state.wizard.siteRollback = {
    site_id: siteId || "",
    backup_id: "",
    restart_services: true,
  };
}

function resetSiteServicesWizard(siteId) {
  state.wizard.siteServices = {
    site_id: siteId || "",
    services: "",
  };
}

function openWizard(mode, contextContainer, options = {}) {
  state.wizard.active = true;
  state.wizard.mode = mode;
  state.wizard.step = 0;
  state.wizard.prevStep = 0;
  state.wizard.maxStep = 0;
  state.wizard.busy = false;
  state.wizard.error = null;
  if (mode === "create-container") {
    resetCreateWizard();
    state.wizard.context.container = null;
    loadPopularImages().catch(() => {});
  } else if (mode === "routing") {
    resetRoutingWizard(contextContainer);
  } else if (mode === "filemanager") {
    resetFilemanagerWizard();
    state.wizard.context.container = contextContainer || null;
  } else if (mode === "packages") {
    resetPackagesWizard(options.packageMode || "install", contextContainer || null);
  } else if (mode === "system-upgrade") {
    resetUpgradeWizard();
  } else if (mode === "recipe-apply") {
    resetRecipeWizard(contextContainer || null);
  } else if (mode === "host-create") {
    resetHostWizard();
  } else if (mode === "network") {
    resetNetworkWizard(contextContainer || null);
  } else if (mode === "firewall") {
    resetFirewallWizard(options.firewallMode || "open");
  } else if (mode === "vm-snapshot") {
    resetVmSnapshotWizard(options.vmName || null);
  } else if (mode === "container-snapshot") {
    resetContainerSnapshotWizard(contextContainer || null);
  } else if (mode === "exec") {
    resetExecWizard(contextContainer || null);
  } else if (mode === "site-create") {
    resetSiteCreateWizard();
  } else if (mode === "site-deploy") {
    resetSiteDeployWizard(options.siteId || "");
  } else if (mode === "site-backup") {
    resetSiteBackupWizard(options.siteId || "");
  } else if (mode === "site-rollback") {
    resetSiteRollbackWizard(options.siteId || "");
  } else if (mode === "site-services") {
    resetSiteServicesWizard(options.siteId || "");
  }
  renderWizard();
}

function setWizardStep(nextStep) {
  const total = Math.max(1, wizardStepTotal(state.wizard.mode));
  const parsed = Number.parseInt(String(nextStep), 10);
  const target = Number.isFinite(parsed) ? parsed : 0;
  const bounded = Math.max(0, Math.min(total - 1, target));
  state.wizard.prevStep = state.wizard.step;
  state.wizard.step = bounded;
  state.wizard.maxStep = Math.max(state.wizard.maxStep || 0, bounded);
}

function closeWizardState() {
  state.wizard.active = false;
  state.wizard.error = null;
  state.wizard.mode = null;
  state.wizard.busy = false;
}

function renderBreadcrumb(wizardSteps = []) {
  const path = buildPath(state.selectedId || state.rootId);
  const pathMarkup = path
    .map((node, index) => {
      const active = index === path.length - 1;
      const activeClass = active ? "active" : "";
      const disabled = active ? "disabled" : "";
      const separator = index < path.length - 1 ? `<span class="breadcrumb-sep">/</span>` : "";
      return `
        <button class="breadcrumb-node ${activeClass}" data-nav-node-id="${node.id}" ${disabled}>${escapeHtml(node.title)}</button>
        ${separator}
      `;
    })
    .join("");

  const wizard = state.wizard;
  let wizardMarkup = "";
  if (wizard.active && wizard.mode) {
    const fallbackSteps = Array.from({ length: wizardStepTotal(wizard.mode) }, (_, index) => `Step ${index + 1}`);
    const stepTitles = Array.isArray(wizardSteps) && wizardSteps.length ? wizardSteps : fallbackSteps;
    const totalSteps = Math.max(stepTitles.length, 1);
    const stepMarkup = stepTitles
      .map((title, index) => {
        const active = index === wizard.step ? "active" : "";
        const done = index <= wizard.maxStep ? "done" : "";
        const locked = index > wizard.maxStep ? "locked" : "";
        const disabled = wizard.busy || index > wizard.maxStep ? "disabled" : "";
        return `<button class="wizard-crumb-step ${active} ${done} ${locked}" data-wizard-action="goto-step" data-step-index="${index}" ${disabled}>${
          index + 1
        }. ${escapeHtml(title)}</button>`;
      })
      .join("");
    wizardMarkup = `
      <div class="wizard-crumb-box">
        <div class="wizard-crumb-head">
          <div class="wizard-crumb-title">${escapeHtml(wizardModeLabel(wizard.mode))}</div>
          <span class="pill">${wizard.step + 1}/${totalSteps}</span>
        </div>
        <div class="wizard-crumb-steps">${stepMarkup}</div>
      </div>
    `;
  }

  elements.breadcrumb.innerHTML = `
    <div class="breadcrumb-path">${pathMarkup}</div>
    ${wizardMarkup}
  `;
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
  renderBreadcrumb();
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

function renderFastActions() {
  if (!elements.fastActions) {
    return;
  }
  const configured = normalizeFastActions(state.ui.fastActions);
  state.ui.fastActions = configured;
  const settingsAvailable = state.nodesById.has("settings");
  const buttonsMarkup = configured
    .map((id) => {
      const option = fastActionOptionById(id);
      if (!option) {
        return "";
      }
      return `<button class="action ${option.variant || "ghost"}" data-action-id="${option.id}">${escapeHtml(
        option.label
      )}</button>`;
    })
    .join("");
  elements.fastActions.hidden = false;
  elements.fastActions.innerHTML = `
    <div class="fast-actions-head">
      <div class="fast-actions-title">Fast Actions</div>
      ${
        settingsAvailable
          ? `<button class="action ghost mini" data-action-id="open-settings">Customize</button>`
          : ""
      }
    </div>
    <div class="fast-actions-row">
      ${buttonsMarkup}
    </div>
  `;
}

function renderCard(node, index, useIntroAnimation = false) {
  const status = node.meta && node.meta.status ? normalizeStatus(node.meta.status) : null;
  const badgeClass = node.badge ? node.badge.toLowerCase().replace(/[^a-z0-9]+/g, "-") : null;
  const expanded = node.id === state.ui.expandedCardId ? "expanded" : "";
  const selected = node.id === state.selectedId ? "selected" : "";
  const delay = `${index * 0.05}s`;
  const introClass = useIntroAnimation ? "intro" : "steady";
  const delayStyle = useIntroAnimation ? `style="animation-delay: ${delay}"` : "";
  return `
    <article class="app-card ${introClass} ${selected} ${expanded}" data-node-id="${node.id}" ${delayStyle}>
      <div class="app-card-frame">
        <div class="card-head">
          <button
            class="card-icon-button"
            data-card-open-node="${node.id}"
            title="Open ${escapeHtml(node.title || node.id)}"
            aria-label="Open ${escapeHtml(node.title || node.id)}"
          >
            <span class="card-icon">${iconFor(node.icon)}</span>
          </button>
          <button
            class="card-summary"
            data-card-expand-node="${node.id}"
            aria-expanded="${expanded ? "true" : "false"}"
            aria-label="More info for ${escapeHtml(node.title || node.id)}"
          >
            <span class="card-title">${escapeHtml(node.title || "")}</span>
            <span class="card-desc">${escapeHtml(node.description || "")}</span>
          </button>
        </div>
        <div class="card-meta">
          ${status ? `<span class="pill ${status}">${status}</span>` : ""}
          ${badgeClass ? `<span class="pill ${badgeClass}">${node.badge}</span>` : ""}
          ${node.meta && node.meta.ip ? `<span class="pill">${node.meta.ip}</span>` : ""}
        </div>
      </div>
      <div class="app-card-tab" aria-hidden="true"></div>
    </article>
  `;
}

function appCardsPerRow() {
  const width = elements.grid ? elements.grid.clientWidth : window.innerWidth;
  if (width < 680) {
    return 1;
  }
  if (width < 1024) {
    return 2;
  }
  if (width < 1400) {
    return 3;
  }
  return 4;
}

function stableHash(text) {
  let hash = 0;
  const value = String(text || "");
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

function renderNodeGraphBars(node) {
  const base = stableHash(node && (node.id || node.title || "app"));
  const cpu = 24 + (base % 62);
  const mem = 28 + (Math.floor(base / 7) % 58);
  const io = 20 + (Math.floor(base / 13) % 66);
  const lanes = [
    { label: "cpu", value: cpu },
    { label: "ram", value: mem },
    { label: "io", value: io },
  ];
  return lanes
    .map(
      (lane) => `
        <div class="row-graph-lane">
          <span class="row-graph-label">${escapeHtml(lane.label)}</span>
          <span class="row-graph-meter"><span class="row-graph-fill" style="width:${lane.value}%"></span></span>
          <span class="row-graph-value">${lane.value}%</span>
        </div>
      `
    )
    .join("");
}

function renderMoreInfoPanel(node) {
  if (!node) {
    return "";
  }
  const path = buildPath(state.selectedId || state.rootId);
  const pathMarkup = path
    .map(
      (entry) =>
        `<button class="row-more-nav-link" data-nav-node-id="${entry.id}" title="Go to ${escapeHtml(entry.title)}">${escapeHtml(
          entry.title
        )}</button>`
    )
    .join('<span class="row-more-nav-sep">/</span>');
  const status = node.meta && node.meta.status ? normalizeStatus(node.meta.status) : null;
  const actions = Array.isArray(node.actions) ? node.actions.slice(0, 8) : [];
  const quickActions = actions.length ? actions : [{ id: "refresh", label: "Sync Deck", variant: "ghost" }];
  const badges = [
    status ? `<span class="pill ${status}">${escapeHtml(status)}</span>` : "",
    node.badge ? `<span class="pill">${escapeHtml(node.badge)}</span>` : "",
    node.meta && node.meta.ip ? `<span class="pill">${escapeHtml(node.meta.ip)}</span>` : "",
  ]
    .filter(Boolean)
    .join("");
  return `
    <div class="row-more-content">
      <div class="row-more-nav">
        ${pathMarkup}
        <span class="row-more-nav-sep">/</span>
        <span class="row-more-nav-current">${escapeHtml(node.title || "App")}</span>
      </div>
      <div class="row-more-layout">
        <aside class="row-more-side">
          <div class="row-more-head">
            <div class="row-more-icon">${iconFor(node.icon)}</div>
            <div class="row-more-copy">
              <div class="row-more-title">${escapeHtml(node.title || "App")}</div>
              <div class="row-more-desc">${escapeHtml(node.description || "Open this app to inspect and execute actions.")}</div>
              <div class="card-meta">${badges}</div>
            </div>
          </div>
          <div class="row-more-side-actions">
            <button class="action" data-card-open-node="${node.id}" data-open-mode="expanded">Open</button>
            <button class="action ghost" data-card-expand-node="${node.id}">Close</button>
          </div>
        </aside>
        <section class="row-more-main">
          <div class="row-more-main-title">Live Signals</div>
          <div class="row-more-graphs">
            ${renderNodeGraphBars(node)}
          </div>
          <div class="row-more-main-title">Fast Actions</div>
          <div class="row-more-actions">
            ${
              quickActions
                .map(
                  (action) =>
                    `<button class="action ${action.variant || "ghost"}" data-action-id="${action.id}" data-node-id="${node.id}">${escapeHtml(
                      action.label || action.id
                    )}</button>`
                )
                .join("")
            }
          </div>
        </section>
      </div>
      <div class="row-more-foot">
        <div class="row-more-foot-note">Action surface expanded from this app button.</div>
        <div class="row-more-foot-rule"></div>
      </div>
    </div>
  `;
}

function connectorStyleForRow(rowNodes, expandedNode) {
  if (!expandedNode || !Array.isArray(rowNodes) || !rowNodes.length) {
    return "";
  }
  const index = rowNodes.findIndex((node) => node.id === expandedNode.id);
  if (index < 0) {
    return "";
  }
  const left = (index / rowNodes.length) * 100;
  const width = (1 / rowNodes.length) * 100;
  return `style="--connector-left:${left.toFixed(4)}%;--connector-width:${width.toFixed(4)}%"`;
}

function renderGrid() {
  const children = getChildren(state.selectedId || state.rootId);
  if (state.ui.expandedCardId && !children.some((child) => child.id === state.ui.expandedCardId)) {
    state.ui.expandedCardId = null;
  }
  const perRow = appCardsPerRow();
  const rows = [];
  for (let index = 0; index < children.length; index += perRow) {
    rows.push(children.slice(index, index + perRow));
  }
  const useIntroAnimation = !state.ui.cardsAnimated;
  elements.grid.style.setProperty("--app-row-cols", String(perRow));
  elements.grid.innerHTML = rows
    .map((rowNodes, rowIndex) => {
      const expandedNode = rowNodes.find((node) => node.id === state.ui.expandedCardId) || null;
      const connectorStyle = connectorStyleForRow(rowNodes, expandedNode);
      return `
        <section class="app-row" data-row-index="${rowIndex}">
          <div class="app-row-cards">
            ${rowNodes.map((node, offset) => renderCard(node, rowIndex * perRow + offset, useIntroAnimation)).join("")}
          </div>
          <div class="app-row-bridge ${expandedNode ? "open" : ""}" ${connectorStyle} aria-hidden="true"></div>
          <div class="app-row-more ${expandedNode ? "open" : ""}">
            ${expandedNode ? renderMoreInfoPanel(expandedNode) : ""}
          </div>
        </section>
      `;
    })
    .join("");
  state.ui.cardsAnimated = true;
}

function scheduleGridRelayout() {
  if (cardTransitionBusy) {
    return;
  }
  if (gridResizeTimer) {
    window.clearTimeout(gridResizeTimer);
  }
  gridResizeTimer = window.setTimeout(() => {
    gridResizeTimer = null;
    renderGrid();
  }, 120);
}

function safeNodeSelectorValue(nodeId) {
  return String(nodeId || "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"');
}

function cardElementByNodeId(nodeId) {
  if (!elements.grid || !nodeId) {
    return null;
  }
  return elements.grid.querySelector(`.app-card[data-node-id="${safeNodeSelectorValue(nodeId)}"]`);
}

function rowMoreElementFromCard(cardElement) {
  if (!cardElement) {
    return null;
  }
  const row = cardElement.closest(".app-row");
  if (!row) {
    return null;
  }
  return row.querySelector(".app-row-more");
}

function rowBridgeElementFromCard(cardElement) {
  if (!cardElement) {
    return null;
  }
  const row = cardElement.closest(".app-row");
  if (!row) {
    return null;
  }
  return row.querySelector(".app-row-bridge");
}

function clearCardTransitionTimer() {
  if (cardTransitionTimer) {
    window.clearTimeout(cardTransitionTimer);
    cardTransitionTimer = null;
  }
}

function runQueuedCardToggleIfNeeded() {
  if (!queuedExpandNodeId) {
    return;
  }
  const nextNodeId = queuedExpandNodeId;
  queuedExpandNodeId = null;
  if (nextNodeId === state.ui.expandedCardId) {
    return;
  }
  toggleAppCardDetails(nextNodeId);
}

function markCardOpeningSequence(nodeId) {
  const card = cardElementByNodeId(nodeId);
  if (!card) {
    return;
  }
  const rowMore = rowMoreElementFromCard(card);
  const rowBridge = rowBridgeElementFromCard(card);
  card.classList.add("is-expanding");
  if (rowMore) {
    rowMore.classList.add("is-opening");
  }
  if (rowBridge) {
    rowBridge.classList.add("is-opening");
  }
  window.setTimeout(() => {
    card.classList.remove("is-expanding");
    if (rowMore) {
      rowMore.classList.remove("is-opening");
    }
    if (rowBridge) {
      rowBridge.classList.remove("is-opening");
    }
  }, CARD_OPEN_SEQUENCE_MS);
}

function closeExpandedCardAndMaybeOpen(nextNodeId) {
  const currentNodeId = state.ui.expandedCardId;
  if (!currentNodeId) {
    if (nextNodeId) {
      state.ui.expandedCardId = nextNodeId;
      renderGrid();
      markCardOpeningSequence(nextNodeId);
    }
    cardTransitionBusy = false;
    runQueuedCardToggleIfNeeded();
    return;
  }

  const card = cardElementByNodeId(currentNodeId);
  const rowMore = rowMoreElementFromCard(card);
  const rowBridge = rowBridgeElementFromCard(card);
  if (card) {
    card.classList.add("is-collapsing");
  }
  if (rowMore) {
    rowMore.classList.add("is-closing");
  }
  if (rowBridge) {
    rowBridge.classList.add("is-closing");
  }

  clearCardTransitionTimer();
  cardTransitionTimer = window.setTimeout(() => {
    cardTransitionTimer = null;
    state.ui.expandedCardId = nextNodeId || null;
    renderGrid();
    if (nextNodeId) {
      markCardOpeningSequence(nextNodeId);
    }
    cardTransitionBusy = false;
    runQueuedCardToggleIfNeeded();
  }, CARD_SWITCH_SEQUENCE_MS);
}

function shouldShowImageCatalog() {
  const selected = state.selectedId || state.rootId;
  return selected === "containers";
}

function filteredImageEntries() {
  const entries = Array.isArray(state.images.popular) ? state.images.popular.slice() : [];
  const remoteFilter = state.images.remoteFilter || "all";
  const hideUnavailable = Boolean(state.images.hideUnavailable);
  return entries
    .filter((item) => {
      if (!item || typeof item !== "object") {
        return false;
      }
      if (remoteFilter !== "all" && (item.remote || "") !== remoteFilter) {
        return false;
      }
      if (hideUnavailable && item.available === false) {
        return false;
      }
      return true;
    })
    .sort((a, b) => {
      const aAvailable = a.available === false ? 1 : 0;
      const bAvailable = b.available === false ? 1 : 0;
      if (aAvailable !== bAvailable) {
        return aAvailable - bAvailable;
      }
      const aLabel = String(a.label || a.name || "").toLowerCase();
      const bLabel = String(b.label || b.name || "").toLowerCase();
      return aLabel.localeCompare(bLabel);
    });
}

function renderImageCatalog() {
  if (!elements.imageCatalog) {
    return;
  }
  const shouldShow = shouldShowImageCatalog() && !state.wizard.active;
  if (!shouldShow) {
    elements.imageCatalog.hidden = true;
    elements.imageCatalog.innerHTML = "";
    return;
  }
  elements.imageCatalog.hidden = false;
  const allEntries = Array.isArray(state.images.popular) ? state.images.popular : [];
  const discoveredRemotes = allEntries
    .map((item) => (item && item.remote ? String(item.remote) : ""))
    .filter(Boolean);
  const remotes = ["all", ...new Set([...(state.images.remotes || []), ...discoveredRemotes])];
  if (!remotes.includes(state.images.remoteFilter)) {
    state.images.remoteFilter = "all";
  }
  const filtered = filteredImageEntries();
  const remoteButtons = remotes
    .map((remote) => {
      const active = remote === state.images.remoteFilter ? "active" : "";
      const label = remote === "all" ? "All Remotes" : remote;
      return `<button class="catalog-filter ${active}" data-image-remote="${escapeHtml(remote)}">${escapeHtml(label)}</button>`;
    })
    .join("");

  const loadingMarkup = state.images.loading ? `<span class="pill">refreshing...</span>` : "";
  const latestLtsMarkup =
    state.images.latest && state.images.latest.ubuntu_lts
      ? `<span class="pill">${escapeHtml(state.images.latest.ubuntu_lts)}</span>`
      : "";
  const refreshedMarkup =
    state.images.refreshedAt
      ? `<span class="pill">${escapeHtml(new Date(state.images.refreshedAt).toLocaleTimeString())}</span>`
      : "";
  const errorMarkup = state.images.error ? `<div class="event-item error">${escapeHtml(state.images.error)}</div>` : "";
  const listMarkup =
    filtered.length === 0
      ? `<div class="event-item">${state.images.loading ? "Checking live image catalog..." : "No images match this filter."}</div>`
      : `
      <div class="catalog-grid">
        ${filtered
          .map((item) => {
            const available = item.available !== false;
            const availability = available
              ? `<span class="pill running">available</span>`
              : `<span class="pill danger">unavailable</span>`;
            const source = item.source ? `<span class="pill">${escapeHtml(item.source)}</span>` : "";
            const remote = item.remote ? `<span class="pill">${escapeHtml(item.remote)}</span>` : "";
            const release = item.release ? `<span class="pill">${escapeHtml(String(item.release))}</span>` : "";
            const os = item.os ? `<span class="pill">${escapeHtml(String(item.os))}</span>` : "";
            const reasonCode =
              !available && item.reason_code ? `<span class="pill danger">code ${escapeHtml(String(item.reason_code))}</span>` : "";
            const reason =
              !available && item.reason
                ? `<div class="catalog-item-code">${escapeHtml(String(item.reason))}</div>`
                : "";
            const debug =
              !available && item.debug
                ? `<details><summary>debug</summary><pre>${escapeHtml(
                    JSON.stringify(item.debug, null, 2)
                  )}</pre></details>`
                : "";
            return `
              <div class="catalog-item ${available ? "" : "unavailable"}">
                <div class="catalog-item-title">${escapeHtml(item.label || item.name || "image")}</div>
                <div class="catalog-item-code">${escapeHtml(item.resolved_name || item.name || "")}</div>
                <div class="catalog-item-meta">${availability}${reasonCode}${source}${remote}${release}${os}</div>
                ${reason}
                ${debug}
              </div>
            `;
          })
          .join("")}
      </div>
    `;

  elements.imageCatalog.innerHTML = `
    <div class="catalog-head">
      <div>
        <div class="catalog-title">Live Image Catalog</div>
        <div class="catalog-sub">Directly discovered from configured LXD remotes (startup preload + 10 minute refresh).</div>
      </div>
      <button class="action ghost mini" data-action-id="image-catalog-refresh">Refresh</button>
    </div>
    <div class="catalog-controls">
      <div class="catalog-remotes">${remoteButtons}</div>
      <label class="catalog-toggle" for="image-hide-unavailable">
        <input id="image-hide-unavailable" type="checkbox" ${state.images.hideUnavailable ? "checked" : ""} />
        Hide unavailable
      </label>
      ${refreshedMarkup}
      ${latestLtsMarkup}
      ${loadingMarkup}
    </div>
    ${errorMarkup}
    ${listMarkup}
  `;
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
  const scopedContainer =
    node && node.context && node.context.container ? String(node.context.container) : "";
  const latestReport = getLatestRecipeApplyReport(scopedContainer || null);
  const reportMarkup = renderRecipeApplyReport(latestReport, scopedContainer);
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
    ${
      scopedContainer
        ? `<div class="card-meta"><span class="pill">${escapeHtml(scopedContainer)}</span></div>`
        : ""
    }
    ${reportMarkup}
    ${body}
  `;
}

function renderSettingsPreview(node) {
  const selectedSet = new Set(normalizeFastActions(state.ui.fastActions));
  const optionsMarkup = FAST_ACTION_OPTIONS.map((option) => {
    const checked = selectedSet.has(option.id) ? "checked" : "";
    return `
      <div class="settings-fast-item">
        <label>
          <input type="checkbox" data-setting-fast-action="${option.id}" ${checked} />
          ${escapeHtml(option.label)}
        </label>
        <div class="settings-fast-desc">${escapeHtml(option.description || "")}</div>
      </div>
    `;
  }).join("");
  const currentFastActions = normalizeFastActions(state.ui.fastActions)
    .map((id) => fastActionOptionById(id))
    .filter(Boolean)
    .map((item) => `<span class="pill">${escapeHtml(item.label)}</span>`)
    .join("");
  const systemSummary = (() => {
    const latestUpdateReload = state.systemUpgrade.lastUpdateReload;
    if (!latestUpdateReload || !latestUpdateReload.result) {
      return `<div class="event-item">No update/reload run recorded yet in this session.</div>`;
    }
    const result = latestUpdateReload.result;
    const updated = Boolean(result.updated);
    const reloadScheduled = Boolean(result.reload && result.reload.scheduled);
    const stashUsed = Boolean(result.stash && result.stash.used);
    const stashConflict = Boolean(result.stash && result.stash.restore_conflict);
    return `
      <div class="event-item">
        <div><strong>Last update check</strong> — ${escapeHtml(
          new Date(latestUpdateReload.at).toLocaleString()
        )}</div>
        <div class="card-meta">
          <span class="pill ${updated ? "running" : "soon"}">${updated ? "updated" : "no changes"}</span>
          <span class="pill">${reloadScheduled ? "reload scheduled" : "reload skipped"}</span>
          ${stashUsed ? `<span class="pill">auto-stashed</span>` : ""}
          ${stashConflict ? `<span class="pill danger">stash conflict</span>` : ""}
        </div>
      </div>
    `;
  })();
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>${node.description || ""}</div>
    <div class="event-item">
      Use this page for global operations like <strong>Check Update + Reload</strong>, system upgrade, and dashboard quick-action preferences.
    </div>
    <div class="card-actions">
      <button class="action" data-action-id="system-update-reload" data-node-id="${node.id}">Check Update + Reload</button>
      <button class="action ghost" data-action-id="system-upgrade" data-node-id="${node.id}">System Upgrade</button>
      <button class="action ghost" data-action-id="refresh" data-node-id="${node.id}">Sync Deck</button>
    </div>
    ${systemSummary}
    <div class="event-item">
      <div><strong>Fast Actions Menu</strong> (top horizontal bar)</div>
      <div class="settings-fast-desc">Choose which actions stay one click away.</div>
      <div class="settings-fast-actions">
        ${optionsMarkup}
      </div>
      <div class="card-actions">
        <button class="action ghost" data-action-id="settings-fast-actions-default" data-node-id="${node.id}">Reset Defaults</button>
      </div>
      <div class="card-meta">${currentFastActions}</div>
    </div>
  `;
}

function renderPackagesPreview(node) {
  const lastPreflight = state.systemUpgrade.lastPreflight;
  const lastExecution = state.systemUpgrade.lastExecution;
  const lastUpdateReload = state.systemUpgrade.lastUpdateReload;
  const preflightSummary =
    lastPreflight && lastPreflight.preflight
      ? (() => {
          const plan = lastPreflight.preflight;
          const migrations = Array.isArray(plan.migrations) ? plan.migrations : [];
          const packageCommand =
            plan.packages && Array.isArray(plan.packages.command)
              ? plan.packages.command.join(" ")
              : "";
          return `
            <div class="event-item">
              <div><strong>Last preflight</strong> — ${escapeHtml(new Date(lastPreflight.at).toLocaleString())}</div>
              <div class="card-meta">
                <span class="pill">${lastPreflight.options.update_packages ? "packages:on" : "packages:off"}</span>
                <span class="pill">${lastPreflight.options.apply_migrations ? "migrations:on" : "migrations:off"}</span>
                <span class="pill">${migrations.length} migration changes</span>
              </div>
              ${
                packageCommand
                  ? `<pre>${escapeHtml(packageCommand)}</pre>`
                  : ""
              }
            </div>
          `;
        })()
      : "";
  const executionSummary =
    lastExecution && lastExecution.result
      ? (() => {
          const result = lastExecution.result;
          const migrations = result && result.migrations && Array.isArray(result.migrations.applied)
            ? result.migrations.applied
            : [];
          return `
            <div class="event-item">
              <div><strong>Last upgrade run</strong> — ${escapeHtml(new Date(lastExecution.at).toLocaleString())}</div>
              <div class="card-meta">
                <span class="pill running">${escapeHtml(result.message || "completed")}</span>
                <span class="pill">${migrations.length} stores migrated</span>
                <span class="pill">${lastExecution.options.update_packages ? "packages:on" : "packages:off"}</span>
              </div>
            </div>
          `;
        })()
      : "";
  const updateReloadSummary =
    lastUpdateReload && lastUpdateReload.result
      ? (() => {
          const result = lastUpdateReload.result;
          const migrations =
            result && result.migrations && Array.isArray(result.migrations.applied)
              ? result.migrations.applied
              : [];
          const reloadScheduled = Boolean(result && result.reload && result.reload.scheduled);
          const commit = result && result.after_commit ? String(result.after_commit).slice(0, 12) : "";
          return `
            <div class="event-item">
              <div><strong>Last update check</strong> — ${escapeHtml(new Date(lastUpdateReload.at).toLocaleString())}</div>
              <div class="card-meta">
                <span class="pill ${result.updated ? "running" : "soon"}">${result.updated ? "updated" : "no changes"}</span>
                <span class="pill">${migrations.length} stores migrated</span>
                <span class="pill">${reloadScheduled ? "reload:scheduled" : "reload:skipped"}</span>
                ${commit ? `<span class="pill">${escapeHtml(commit)}</span>` : ""}
              </div>
            </div>
          `;
        })()
      : "";
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>${node.description || ""}</div>
    <div class="event-item">
      Host-level package management uses apt/dnf/yum. Choose Install, Remove, or Update to run against the host or any container.
    </div>
    <div class="event-item">
      Global update controls moved to <strong>Settings</strong> for consistency: use Settings for <strong>System Upgrade</strong> and <strong>Check Update + Reload</strong>.
    </div>
    ${preflightSummary}
    ${executionSummary}
    ${updateReloadSummary}
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
  const chartBar = (value, label, max = 100) => {
    const width = Math.max(0, Math.min(100, Math.round((Number(value) || 0) / max * 100)));
    return `
      <div class="meter">
        <div class="meter-fill" style="width:${width}%;"></div>
        <span class="meter-label">${label}: ${value ?? "?"}%</span>
      </div>
    `;
  };
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
    ${chartBar(host.cpu_percent, "CPU")}
    ${chartBar(host.memory_percent, "RAM")}
    ${chartBar(host.disk_percent, "Disk")}
    ${
      Array.isArray(snapshot.history_samples) && snapshot.history_samples.length
        ? renderSparkline(snapshot.history_samples, "cpu_percent", "Host CPU history")
        : ""
    }
    ${containerRows.join("")}
  `;
}

function renderSparkline(samples, key, label) {
  const values = samples
    .map((item) => {
      const host = item.host || {};
      return typeof host[key] === "number" ? host[key] : null;
    })
    .filter((v) => v !== null);
  if (!values.length) {
    return "";
  }
  const max = Math.max(...values, 1);
  const width = 140;
  const height = 40;
  const step = values.length > 1 ? width / (values.length - 1) : width;
  const points = values
    .map((v, i) => {
      const x = i * step;
      const y = height - (v / max) * height;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  const last = values[values.length - 1];
  return `
    <div class="sparkline">
      <div class="sparkline-label">${label} (${last.toFixed(1)}%)</div>
      <svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
        <polyline fill="none" stroke="var(--leaf)" stroke-width="2" points="${points}" />
      </svg>
    </div>
  `;
}

function renderFirewallPreview(node) {
  if (state.firewallLoading) {
    elements.preview.innerHTML = `<div class="preview-title">${node.title}</div><div>Loading firewall...</div>`;
    return;
  }
  const fw = state.firewall || {};
  const rules = Array.isArray(fw.rules) ? fw.rules : [];
  const prevCount = Array.isArray(state.firewallPreviousRules) ? state.firewallPreviousRules.length : 0;
  const diffAdded = fw.added || [];
  const diffRemoved = fw.removed || [];
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
        <div class="card-actions">
          <button class="action danger ghost" data-action-id="firewall-close" data-port="${rule.port}" data-protocol="${rule.protocol}" data-source="${rule.source || ""}" data-node-id="${node.id}">Close</button>
        </div>
      </div>
    `
          )
          .join("");
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>Backend: ${fw.backend || "unknown"} • Active: ${fw.active ? "yes" : "no"}</div>
    <div class="card-meta">
      <span class="pill">${rules.length} rules</span>
      <span class="pill">${Math.max(rules.length - prevCount, 0)} new since last refresh</span>
    </div>
    ${
      diffAdded.length || diffRemoved.length
        ? `
      <div class="event-item">
        <div><strong>Diff vs baseline</strong></div>
        <div class="card-meta">
          <span class="pill running">${diffAdded.length} added</span>
          <span class="pill danger">${diffRemoved.length} removed</span>
        </div>
      </div>
    `
        : ""
    }
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
            const snapshotButtons =
              Array.isArray(vm.snapshots) && vm.snapshots.length
                ? vm.snapshots
                    .map(
                      (snap) =>
                        `<button class="action ghost" data-action-id="vm-restore" data-vm="${vm.name}" data-snapshot="${snap}" data-node-id="${node.id}">Restore ${snap}</button>`
                    )
                    .join("")
                : "";
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
              <button class="action ghost" data-action-id="vm-snapshot" data-vm="${vm.name}" data-node-id="${node.id}">Snapshot</button>
              ${snapshotButtons}
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

function renderSitesPreview(node) {
  if (state.sitesLoading) {
    elements.preview.innerHTML = `<div class="preview-title">${node.title}</div><div>Loading sites...</div>`;
    return;
  }
  if (!state.sites.length) {
    elements.preview.innerHTML = `<div class="preview-title">${node.title}</div><div>No sites yet. Create one to begin.</div>`;
    return;
  }
  const rows = state.sites
    .map((site) => {
      const status = site.status || "unknown";
      const pill = `<span class="pill ${status.includes("active") ? "running" : "stopped"}">${status}</span>`;
      const siteId = site.id || site.name;
      const detail = siteId ? state.siteDetails.get(siteId) || site : site;
      const runtime = detail.runtime || {};
      const routing = detail.routing || {};
      const tls = detail.tls || {};
      const database = detail.database || {};
      const domains = Array.isArray(detail.domains) ? detail.domains : [];
      const backups = siteId ? state.siteBackups.get(siteId) || [] : [];
      const backupsLoading = siteId ? state.siteBackupsLoading.has(siteId) : false;
      const detailsLoading = siteId ? state.siteDetailsLoading.has(siteId) : false;
      const routingLabel =
        routing.listen_port || routing.container_port
          ? `${routing.listen_address || "0.0.0.0"}:${routing.listen_port || 80} → ${routing.container_interface || "eth0"}:${routing.container_port || 80}`
          : "not set";
      const tlsLabel = tls.mode ? `${tls.mode}${tls.cert_name ? ` (${tls.cert_name})` : ""}` : "disabled";
      const dbLabel =
        database && (database.engine || database.name || database.username)
          ? `${database.engine || "db"} ${database.name || ""} ${database.username ? `as ${database.username}` : ""}`
          : "none";
      const backupBlock = siteId
        ? `
        <div class="event-item">
          <div><strong>Backups</strong></div>
          <div class="card-meta">
            <span class="pill">${backups.length} backups</span>
            ${backupsLoading ? `<span class="pill">loading...</span>` : ""}
          </div>
          ${
            backupsLoading
              ? ""
              : backups.length
              ? backups
                  .map(
                    (backup) => `
            <div class="card-meta">
              <span class="pill">${backup.backup_id}</span>
              ${backup.created_at ? `<span class="pill">${backup.created_at}</span>` : ""}
              ${backup.include_database ? `<span class="pill">DB</span>` : ""}
              <button class="action ghost" data-action-id="site-rollback" data-site="${siteId}" data-backup="${backup.backup_id}" data-node-id="${node.id}">Rollback</button>
            </div>
          `
                  )
                  .join("")
              : `<div class="card-meta"><span class="pill">No backups yet</span></div>`
          }
        </div>
      `
        : "";
      return `
        <div class="event-item">
          <div><strong>${site.id || site.name}</strong> — ${site.primary_domain} (${site.container_name})</div>
          <div class="card-meta">
            ${pill}
            ${detailsLoading ? `<span class="pill">loading...</span>` : ""}
            ${site.runtime && site.runtime.php_version ? `<span class="pill">PHP ${site.runtime.php_version}</span>` : ""}
            <span class="pill">${domains.length ? `${domains.length + 1} domains` : "1 domain"}</span>
          </div>
          <div class="preview-meta">
            <div>
              <strong>Routing</strong>
              <span>${routingLabel}</span>
            </div>
            <div>
              <strong>TLS</strong>
              <span>${tlsLabel}</span>
            </div>
            <div>
              <strong>Domains</strong>
              <span>${detail.primary_domain}${domains.length ? `, ${domains.join(", ")}` : ""}</span>
            </div>
            <div>
              <strong>Docroot</strong>
              <span>${detail.docroot || "/var/www/html"}</span>
            </div>
            <div>
              <strong>Runtime</strong>
              <span>${runtime.php_version ? `PHP ${runtime.php_version}` : "n/a"}${runtime.user ? ` • ${runtime.user}` : ""}</span>
            </div>
            <div>
              <strong>Database</strong>
              <span>${dbLabel}</span>
            </div>
          </div>
          ${backupBlock}
          <div class="card-actions">
            <button class="action ghost" data-action-id="site-deploy" data-site="${site.id}" data-node-id="${node.id}">Deploy</button>
            <button class="action ghost" data-action-id="site-backup" data-site="${site.id}" data-node-id="${node.id}">Backup</button>
            <button class="action ghost" data-action-id="site-rollback" data-site="${site.id}" data-node-id="${node.id}">Rollback</button>
            <button class="action ghost" data-action-id="site-services" data-site="${site.id}" data-node-id="${node.id}">Restart services</button>
            <button class="action ghost" data-action-id="site-logs" data-site="${site.id}" data-node-id="${node.id}">Logs</button>
            <button class="action ghost" data-action-id="site-health" data-site="${site.id}" data-node-id="${node.id}">Health</button>
          </div>
        </div>
      `;
    })
    .join("");
  elements.preview.innerHTML = `
    <div class="preview-title">${node.title}</div>
    <div>${node.description || ""}</div>
    ${rows}
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
  if (node.id === "recipes" || node.id.endsWith(":container-recipes")) {
    renderRecipesPreview(node);
    return;
  }
  if (node.id === "packages") {
    renderPackagesPreview(node);
    return;
  }
  if (node.id === "settings") {
    renderSettingsPreview(node);
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
  if (node.id === "sites") {
    renderSitesPreview(node);
    return;
  }

  const actions = Array.isArray(node.actions) ? node.actions : [];
  const contextContainer = node.context ? node.context.container : null;
  const containerMeta = contextContainer ? state.containerIndex.get(contextContainer) : null;
  const snapshots = contextContainer ? state.containerSnapshots.get(contextContainer) || [] : [];
  const snapshotsLoading = contextContainer ? state.containerSnapshotLoading.has(contextContainer) : false;
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
      contextContainer
        ? `
      <div class="event-item">
        <div><strong>Snapshots</strong></div>
        <div class="card-meta">
          <span class="pill">${snapshots.length} snapshots</span>
          ${snapshotsLoading ? `<span class="pill">loading...</span>` : ""}
        </div>
        ${
          snapshotsLoading && !snapshots.length
            ? `<div>Loading snapshots...</div>`
            : snapshots.length
            ? snapshots
                .map(
                  (snap) => `
          <div class="card-meta">
            <span class="pill">${snap}</span>
            <button class="action ghost" data-action-id="container-snapshot-restore" data-snapshot="${snap}" data-node-id="${node.id}">Restore</button>
            <button class="action danger ghost" data-action-id="container-snapshot-delete" data-snapshot="${snap}" data-node-id="${node.id}">Delete</button>
          </div>
        `
                )
                .join("")
            : `<div class="card-meta"><span class="pill">No snapshots yet</span></div>`
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

function renderDebugPanel() {
  if (!elements.debugPanel) {
    return;
  }
  const lastError = state.debug.lastError;
  if (!lastError) {
    elements.debugPanel.innerHTML = `
      <div class="event-item">
        No API errors captured in this session.
      </div>
    `;
    return;
  }
  const detailsJson =
    lastError.details && typeof lastError.details === "object"
      ? JSON.stringify(lastError.details, null, 2)
      : lastError.details
      ? String(lastError.details)
      : "";
  const stackJson = lastError.stack ? String(lastError.stack) : "";
  elements.debugPanel.innerHTML = `
    <div class="event-item error">
      <div><strong>${escapeHtml(lastError.message || "Request failed")}</strong></div>
      <div class="card-meta">
        ${lastError.status ? `<span class="pill danger">HTTP ${lastError.status}</span>` : `<span class="pill danger">network</span>`}
        ${lastError.method ? `<span class="pill">${escapeHtml(lastError.method)}</span>` : ""}
        ${lastError.path ? `<span class="pill">${escapeHtml(lastError.path)}</span>` : ""}
        ${lastError.at ? `<span class="pill">${escapeHtml(lastError.at)}</span>` : ""}
      </div>
      ${
        detailsJson
          ? `<details><summary>Payload</summary><pre>${escapeHtml(detailsJson)}</pre></details>`
          : ""
      }
      ${
        stackJson
          ? `<details><summary>Stack</summary><pre>${escapeHtml(stackJson)}</pre></details>`
          : ""
      }
    </div>
  `;
}

function wizardModeLabel(mode) {
  return WIZARD_MODE_LABELS[mode] || "Wizard";
}

function wizardStepTotal(mode) {
  return WIZARD_STEP_COUNTS[mode] || 1;
}

function buildOperationFacts() {
  const wizard = state.wizard;
  if (!wizard.active || !wizard.mode) {
    return [];
  }
  const facts = [];
  if (wizard.mode === "create-container") {
    facts.push(["Name", wizard.form.name || "(pending)"]);
    facts.push(["Image", wizard.form.distro || "ubuntu:lts"]);
  } else if (wizard.mode === "routing") {
    facts.push(["Container", wizard.routing.container_name || wizard.context.container || "(pending)"]);
    facts.push(["Domain", wizard.routing.domain || "(pending)"]);
  } else if (wizard.mode === "packages") {
    facts.push(["Mode", wizard.packages.mode || "install"]);
    facts.push(["Target", wizard.packages.target || "host"]);
  } else if (wizard.mode === "system-upgrade") {
    facts.push(["Packages", wizard.upgrade.update_packages ? "enabled" : "off"]);
    facts.push(["Migrations", wizard.upgrade.apply_migrations ? "enabled" : "off"]);
  } else if (wizard.mode === "recipe-apply") {
    facts.push(["Recipe", wizard.recipe.name || "(pending)"]);
    facts.push(["Target", wizard.recipe.target || "host"]);
  } else if (wizard.mode === "host-create") {
    facts.push(["Host", wizard.host.name || "(pending)"]);
    facts.push(["SSH", wizard.host.host || "(pending)"]);
  } else if (wizard.mode === "network") {
    facts.push(["Container", wizard.network.container_name || wizard.context.container || "(pending)"]);
    facts.push(["Port", wizard.network.container_port || "(pending)"]);
  } else if (wizard.mode === "firewall") {
    facts.push(["Action", wizard.firewall.mode || "open"]);
    facts.push(["Port", wizard.firewall.port || "(pending)"]);
  } else if (wizard.mode === "vm-snapshot") {
    facts.push(["VM", wizard.context.vm || "(pending)"]);
    facts.push(["Snapshot", wizard.vmSnapshot.name || "(pending)"]);
  } else if (wizard.mode === "container-snapshot") {
    facts.push(["Container", wizard.context.container || "(pending)"]);
    facts.push(["Snapshot", wizard.containerSnapshot.name || "(pending)"]);
  } else if (wizard.mode === "exec") {
    facts.push(["Container", wizard.context.container || "(pending)"]);
    facts.push(["Command", wizard.exec.command || "(pending)"]);
  } else if (wizard.mode === "site-create") {
    facts.push(["Site", wizard.siteCreate.name || "(pending)"]);
    facts.push(["Domain", wizard.siteCreate.primary_domain || "(pending)"]);
  } else if (wizard.mode === "site-deploy") {
    facts.push(["Site", wizard.siteDeploy.site_id || "(pending)"]);
    facts.push(["Source", wizard.siteDeploy.source || "(pending)"]);
  } else if (wizard.mode === "site-backup") {
    facts.push(["Site", wizard.siteBackup.site_id || "(pending)"]);
    facts.push(["Label", wizard.siteBackup.label || "none"]);
  } else if (wizard.mode === "site-rollback") {
    facts.push(["Site", wizard.siteRollback.site_id || "(pending)"]);
    facts.push(["Backup", wizard.siteRollback.backup_id || "(pending)"]);
  } else if (wizard.mode === "site-services") {
    facts.push(["Site", wizard.siteServices.site_id || "(pending)"]);
    facts.push(["Services", wizard.siteServices.services || "default"]);
  } else if (wizard.mode === "filemanager") {
    facts.push(["Container", wizard.context.container || "(pending)"]);
    facts.push(["User", wizard.filemanager.username || "(pending)"]);
  }
  return facts;
}

function renderOperationPanel() {
  if (!elements.operation) {
    return;
  }
  const wizard = state.wizard;
  if (!wizard.active || !wizard.mode) {
    elements.operation.innerHTML = `
      <div class="preview-title">Idle</div>
      <div>Pick a card action to start a guided operation.</div>
      <div class="card-meta">
        <span class="pill">Wizard inactive</span>
      </div>
    `;
    return;
  }
  const total = wizardStepTotal(wizard.mode);
  const facts = buildOperationFacts()
    .map(
      ([label, value]) => `
      <div>
        <strong>${escapeHtml(label)}</strong>
        <span>${escapeHtml(value)}</span>
      </div>
    `
    )
    .join("");
  const errorMarkup = wizard.error ? `<div class="event-item error">${escapeHtml(wizard.error)}</div>` : "";
  elements.operation.innerHTML = `
    <div class="preview-title">${escapeHtml(wizardModeLabel(wizard.mode))}</div>
    <div>Step ${wizard.step + 1} of ${total}</div>
    <div class="card-meta">
      <span class="pill">${wizard.busy ? "running" : "ready"}</span>
      <span class="pill">${escapeHtml(wizard.mode)}</span>
    </div>
    <div class="preview-meta">
      ${facts}
    </div>
    ${errorMarkup}
  `;
}

function renderWizard() {
  const wizard = state.wizard;
  if (!wizard.active || !wizard.mode) {
    elements.wizard.innerHTML = "";
    if (elements.wizardStage) {
      elements.wizardStage.hidden = true;
    }
    if (elements.grid) {
      elements.grid.hidden = false;
    }
    if (elements.layout) {
      elements.layout.classList.remove("wizard-active");
    }
    renderBreadcrumb();
    renderImageCatalog();
    renderOperationPanel();
    return;
  }
  if (elements.wizardStage) {
    elements.wizardStage.hidden = false;
  }
  if (elements.grid) {
    elements.grid.hidden = true;
  }
  if (elements.layout) {
    elements.layout.classList.add("wizard-active");
  }
  renderImageCatalog();

  let steps = [];
  let bodyMarkup = "";
  let nextLabel = "Next";
  const directionClass =
    wizard.prevStep === undefined || wizard.prevStep === null || wizard.prevStep === wizard.step
      ? ""
      : wizard.step > wizard.prevStep
      ? "slide-forward"
      : "slide-back";

  if (wizard.mode === "create-container") {
    steps = ["Identity", "Resources", "Confirm"];
    if (wizard.step === 0) {
      const optionsSource =
        state.images && state.images.popular && state.images.popular.length
          ? state.images.popular
          : [
              { name: "ubuntu:lts", resolved_name: "ubuntu:lts", label: "Ubuntu (latest LTS)", available: true },
              { name: "debian:12", resolved_name: "debian:12", label: "Debian 12", available: true },
              { name: "images:almalinux/9/cloud", resolved_name: "images:almalinux/9/cloud", label: "AlmaLinux 9 (cloud)", available: true },
            ];
      const distroOptions = optionsSource
        .map((item) => {
          const value = item.resolved_name || item.name;
          const disabled = item.available === false ? "disabled" : "";
          const suffix = item.available === false ? " (unavailable)" : "";
          const renderedLabel =
            item.resolved_name && item.resolved_name !== item.name
              ? `${item.label || item.name} — ${item.resolved_name}`
              : item.label || item.name;
          return `<option value="${value}" ${wizard.form.distro === value ? "selected" : ""} ${disabled}>${renderedLabel}${suffix}</option>`;
        })
        .join("");
      const presetsList = optionsSource
        .map((item) => {
          const source = String(item.source || "");
          const removable = source === "custom";
          const availability = item.available === false ? `<span class="pill danger">unavailable</span>` : "";
          const sourcePill = source ? `<span class="pill">${escapeHtml(source)}</span>` : "";
          const removeButton = removable
            ? `<button class="tag-remove" data-wizard-action="remove-image" data-image-name="${item.name}" title="Remove preset">×</button>`
            : "";
          return `
          <div class="tag">
            <span>${item.label || item.name}</span>
            ${sourcePill}
            ${availability}
            ${removeButton}
          </div>
        `;
        })
        .join("");
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-name">Container name</label>
          <input id="wiz-name" name="name" data-wizard-group="form" value="${wizard.form.name}" placeholder="web-01" />
        </div>
        <div class="wizard-field">
          <label for="wiz-distro">Image</label>
          <select id="wiz-distro" name="distro" data-wizard-group="form">
            ${distroOptions}
          </select>
          <div class="wizard-hint">
            <span>
              ${state.images.loading ? "Checking LXD images..." : state.images.error ? `<span class="pill danger">${state.images.error}</span>` : `Remotes: ${state.images.remotes && state.images.remotes.length ? state.images.remotes.join(", ") : "unknown"}`}
            </span>
            <button class="action ghost mini" data-wizard-action="refresh-images" type="button">Refresh</button>
          </div>
        </div>
        <div class="wizard-field">
          <label>Add image preset</label>
          <div class="wizard-inline">
            <input id="wiz-image-alias" name="alias" data-wizard-group="imagePreset" value="${wizard.imagePreset.alias}" placeholder="images:almalinux/9/cloud" />
            <input id="wiz-image-label" name="label" data-wizard-group="imagePreset" value="${wizard.imagePreset.label}" placeholder="Label (optional)" />
            <button class="action ghost" data-wizard-action="add-image" type="button">Add</button>
          </div>
          ${
            presetsList
              ? `<div class="wizard-tags">${presetsList}</div>`
              : `<div class="wizard-hint">No presets yet. Add one or refresh.</div>`
          }
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
            <strong>Image</strong>
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
  } else if (wizard.mode === "system-upgrade") {
    const upgrade = wizard.upgrade;
    const preflight = upgrade.preflight && typeof upgrade.preflight === "object" ? upgrade.preflight : null;
    const migrationStatus =
      upgrade.migration_status && typeof upgrade.migration_status === "object"
        ? upgrade.migration_status
        : null;
    const backups = Array.isArray(upgrade.backups) ? upgrade.backups : [];
    const migrationPlan = preflight && Array.isArray(preflight.migrations) ? preflight.migrations : [];
    const packageCommand =
      preflight &&
      preflight.packages &&
      preflight.packages.command &&
      Array.isArray(preflight.packages.command)
        ? preflight.packages.command.join(" ")
        : "";
    const pendingStores =
      migrationStatus && Array.isArray(migrationStatus.stores)
        ? migrationStatus.stores.filter((store) => store && store.pending).length
        : null;
    steps = ["Scope", "Preflight", "Backups", "Execute"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div>Plan a controlled host upgrade with dry-run preflight.</div>
        <div class="wizard-field">
          <label for="wiz-upgrade-packages">Update system packages</label>
          <input id="wiz-upgrade-packages" type="checkbox" name="update_packages" data-wizard-group="upgrade" ${
            upgrade.update_packages ? "checked" : ""
          } />
        </div>
        <div class="wizard-field">
          <label for="wiz-upgrade-full">Full upgrade (dist-upgrade)</label>
          <input id="wiz-upgrade-full" type="checkbox" name="full_upgrade" data-wizard-group="upgrade" ${
            upgrade.full_upgrade ? "checked" : ""
          } ${upgrade.update_packages ? "" : "disabled"} />
        </div>
        <div class="wizard-field">
          <label for="wiz-upgrade-migrations">Apply schema migrations</label>
          <input id="wiz-upgrade-migrations" type="checkbox" name="apply_migrations" data-wizard-group="upgrade" ${
            upgrade.apply_migrations ? "checked" : ""
          } />
        </div>
      `;
    } else if (wizard.step === 1) {
      const preflightMarkup = preflight
        ? `
          <div class="preview-meta">
            <div><strong>Packages</strong><span>${upgrade.update_packages ? "enabled" : "skipped"}</span></div>
            <div><strong>Migrations</strong><span>${upgrade.apply_migrations ? "enabled" : "skipped"}</span></div>
            <div><strong>Migration changes</strong><span>${migrationPlan.length}</span></div>
            <div><strong>Pending stores</strong><span>${pendingStores === null ? "n/a" : pendingStores}</span></div>
          </div>
          ${
            packageCommand
              ? `<div class="event-item"><strong>Package command</strong><pre>${escapeHtml(packageCommand)}</pre></div>`
              : ""
          }
          ${
            migrationPlan.length
              ? `
            <div class="event-item">
              <strong>Migration plan</strong>
              <div class="card-meta">${migrationPlan
                .slice(0, 8)
                .map(
                  (entry) =>
                    `<span class="pill">${escapeHtml(entry.store || "store")}:${escapeHtml(
                      entry.to_schema || "?"
                    )}</span>`
                )
                .join("")}</div>
            </div>
          `
              : `<div class="event-item">No migration changes reported by preflight.</div>`
          }
        `
        : `<div class="event-item error">Preflight data unavailable. Go back and retry.</div>`;
      bodyMarkup = `
        <div>Dry-run preflight summary before upgrade.</div>
        ${preflightMarkup}
      `;
    } else if (wizard.step === 2) {
      const backupPills = backups.length
        ? backups
            .slice(0, 8)
            .map((backup) => `<span class="pill">${escapeHtml(backup)}</span>`)
            .join("")
        : `<span class="pill stopped">No backups listed</span>`;
      bodyMarkup = `
        <div>Confirm backup posture before applying system changes.</div>
        <div class="event-item">
          <strong>Detected backups</strong>
          <div class="card-meta">
            <span class="pill">${backups.length} backup archives</span>
          </div>
          <div class="card-meta">${backupPills}</div>
        </div>
        <div class="wizard-field">
          <label for="wiz-upgrade-backup-confirm">I confirmed backup availability and restore readiness</label>
          <input id="wiz-upgrade-backup-confirm" type="checkbox" name="backup_confirmation" data-wizard-group="upgrade" ${
            upgrade.backup_confirmation ? "checked" : ""
          } />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Running..." : "Run Upgrade";
      bodyMarkup = `
        <div>Execute host upgrade with selected options.</div>
        <div class="preview-meta">
          <div><strong>Packages</strong><span>${upgrade.update_packages ? "yes" : "no"}</span></div>
          <div><strong>Full upgrade</strong><span>${upgrade.update_packages && upgrade.full_upgrade ? "yes" : "no"}</span></div>
          <div><strong>Migrations</strong><span>${upgrade.apply_migrations ? "yes" : "no"}</span></div>
          <div><strong>Backups confirmed</strong><span>${upgrade.backup_confirmation ? "yes" : "no"}</span></div>
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
  } else if (wizard.mode === "vm-snapshot") {
    const vmName = wizard.context.vm || "";
    steps = ["Snapshot", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div>Create a snapshot for ${vmName || "VM"}.</div>
        <div class="wizard-field">
          <label for="wiz-vm-snap-name">Snapshot name</label>
          <input id="wiz-vm-snap-name" name="name" data-wizard-group="vmSnapshot" value="${wizard.vmSnapshot.name}" placeholder="checkpoint-1" />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Creating..." : "Create";
      bodyMarkup = `
        <div>Confirm snapshot.</div>
        <div class="preview-meta">
          <div>
            <strong>VM</strong>
            <span>${vmName || "(missing)"}</span>
          </div>
          <div>
            <strong>Name</strong>
            <span>${wizard.vmSnapshot.name || "(missing)"}</span>
          </div>
        </div>
      `;
    }
  } else if (wizard.mode === "container-snapshot") {
    const containerName = wizard.context.container || "";
    steps = ["Snapshot", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div>Create a snapshot for ${containerName || "container"}.</div>
        <div class="wizard-field">
          <label for="wiz-ct-snap-name">Snapshot name</label>
          <input id="wiz-ct-snap-name" name="name" data-wizard-group="containerSnapshot" value="${wizard.containerSnapshot.name}" placeholder="snap-1" />
        </div>
        <div class="wizard-field">
          <label for="wiz-ct-snap-stateful">Stateful</label>
          <input id="wiz-ct-snap-stateful" type="checkbox" name="stateful" data-wizard-group="containerSnapshot" ${wizard.containerSnapshot.stateful ? "checked" : ""} />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Creating..." : "Create";
      bodyMarkup = `
        <div>Confirm snapshot.</div>
        <div class="preview-meta">
          <div>
            <strong>Container</strong>
            <span>${containerName || "(missing)"}</span>
          </div>
          <div>
            <strong>Name</strong>
            <span>${wizard.containerSnapshot.name || "(missing)"}</span>
          </div>
          <div>
            <strong>Stateful</strong>
            <span>${wizard.containerSnapshot.stateful ? "yes" : "no"}</span>
          </div>
        </div>
      `;
    }
  } else if (wizard.mode === "exec") {
    const containerName = wizard.context.container || "";
    steps = ["Command", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div>Run a command inside ${containerName || "container"}.</div>
        <div class="wizard-field">
          <label for="wiz-exec-cmd">Command (space separated)</label>
          <input id="wiz-exec-cmd" name="command" data-wizard-group="exec" value="${wizard.exec.command}" placeholder="ls -la /" />
        </div>
        <div class="wizard-field">
          <label for="wiz-exec-user">User (optional)</label>
          <input id="wiz-exec-user" name="user" data-wizard-group="exec" value="${wizard.exec.user}" placeholder="root" />
        </div>
        <div class="wizard-field">
          <label for="wiz-exec-cwd">Workdir (optional)</label>
          <input id="wiz-exec-cwd" name="workdir" data-wizard-group="exec" value="${wizard.exec.workdir}" placeholder="/var/www/html" />
        </div>
        <div class="wizard-field">
          <label for="wiz-exec-env">Environment (key=value per line)</label>
          <textarea id="wiz-exec-env" name="environment" data-wizard-group="exec" rows="3" placeholder="APP_ENV=prod&#10;DEBUG=0">${wizard.exec.environment}</textarea>
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Running..." : "Run";
      bodyMarkup = `
        <div>Confirm exec.</div>
        <div class="preview-meta">
          <div>
            <strong>Container</strong>
            <span>${containerName || "(missing)"}</span>
          </div>
          <div>
            <strong>Command</strong>
            <span>${wizard.exec.command || "(missing)"}</span>
          </div>
          <div>
            <strong>User</strong>
            <span>${wizard.exec.user || "default"}</span>
          </div>
          <div>
            <strong>Workdir</strong>
            <span>${wizard.exec.workdir || "default"}</span>
          </div>
        </div>
      `;
    }
  } else if (wizard.mode === "site-create") {
    const containersOptions = state.containers
      .map(
        (c) =>
          `<option value="${c.name}" ${c.name === state.wizard.siteCreate.container_name ? "selected" : ""}>${c.name}</option>`
      )
      .join("");
    steps = ["Domains", "Container", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-site-name">Site name</label>
          <input id="wiz-site-name" name="name" data-wizard-group="siteCreate" value="${wizard.siteCreate.name}" placeholder="app-site" />
        </div>
        <div class="wizard-field">
          <label for="wiz-site-primary">Primary domain</label>
          <input id="wiz-site-primary" name="primary_domain" data-wizard-group="siteCreate" value="${wizard.siteCreate.primary_domain}" placeholder="app.example.com" />
        </div>
        <div class="wizard-field">
          <label for="wiz-site-domains">Additional domains (comma separated)</label>
          <input id="wiz-site-domains" name="domains" data-wizard-group="siteCreate" value="${wizard.siteCreate.domains}" placeholder="www.app.example.com" />
        </div>
      `;
    } else if (wizard.step === 1) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-site-container">Container</label>
          <select id="wiz-site-container" name="container_name" data-wizard-group="siteCreate">${containersOptions}</select>
        </div>
        <div class="wizard-field">
          <label for="wiz-site-docroot">Docroot</label>
          <input id="wiz-site-docroot" name="docroot" data-wizard-group="siteCreate" value="${wizard.siteCreate.docroot}" placeholder="/var/www/html" />
        </div>
        <div class="wizard-field">
          <label for="wiz-site-php">PHP version (optional)</label>
          <input id="wiz-site-php" name="php_version" data-wizard-group="siteCreate" value="${wizard.siteCreate.php_version}" placeholder="8.2" />
        </div>
        <div class="wizard-field">
          <label for="wiz-site-db">Create database</label>
          <input id="wiz-site-db" type="checkbox" name="create_database" data-wizard-group="siteCreate" ${
            wizard.siteCreate.create_database ? "checked" : ""
          } />
        </div>
        <div class="wizard-field">
          <label for="wiz-site-user">Create app user</label>
          <input id="wiz-site-user" type="checkbox" name="create_user" data-wizard-group="siteCreate" ${
            wizard.siteCreate.create_user ? "checked" : ""
          } />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Creating..." : "Create";
      bodyMarkup = `
        <div>Confirm site.</div>
        <div class="preview-meta">
          <div><strong>Name</strong><span>${wizard.siteCreate.name || "(missing)"}</span></div>
          <div><strong>Domain</strong><span>${wizard.siteCreate.primary_domain || "(missing)"}</span></div>
          <div><strong>Container</strong><span>${wizard.siteCreate.container_name || "(missing)"}</span></div>
          <div><strong>Docroot</strong><span>${wizard.siteCreate.docroot}</span></div>
        </div>
      `;
    }
  } else if (wizard.mode === "site-deploy") {
    const siteId = wizard.siteDeploy.site_id;
    steps = ["Source", "Options", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div>Deploy assets to site ${siteId || ""}.</div>
        <div class="wizard-field">
          <label for="wiz-deploy-type">Source type</label>
          <select id="wiz-deploy-type" name="source_type" data-wizard-group="siteDeploy">
            <option value="git" ${wizard.siteDeploy.source_type === "git" ? "selected" : ""}>Git</option>
            <option value="archive" ${wizard.siteDeploy.source_type === "archive" ? "selected" : ""}>Archive</option>
            <option value="local" ${wizard.siteDeploy.source_type === "local" ? "selected" : ""}>Local path</option>
          </select>
        </div>
        <div class="wizard-field">
          <label for="wiz-deploy-source">Source</label>
          <input id="wiz-deploy-source" name="source" data-wizard-group="siteDeploy" value="${wizard.siteDeploy.source}" placeholder="https://github.com/org/repo.git or /path/file.tar.gz" />
        </div>
        <div class="wizard-field">
          <label for="wiz-deploy-ref">Ref (branch/tag)</label>
          <input id="wiz-deploy-ref" name="ref" data-wizard-group="siteDeploy" value="${wizard.siteDeploy.ref}" placeholder="main" />
        </div>
      `;
    } else if (wizard.step === 1) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-deploy-subdir">Subdir (optional)</label>
          <input id="wiz-deploy-subdir" name="subdir" data-wizard-group="siteDeploy" value="${wizard.siteDeploy.subdir}" placeholder="web" />
        </div>
        <div class="wizard-field">
          <label for="wiz-deploy-strip">Strip components (archives)</label>
          <input id="wiz-deploy-strip" name="strip_components" data-wizard-group="siteDeploy" value="${wizard.siteDeploy.strip_components}" placeholder="0" />
        </div>
        <div class="wizard-field">
          <label for="wiz-deploy-commands">Post-deploy commands (one per line)</label>
          <textarea id="wiz-deploy-commands" name="post_deploy_commands" data-wizard-group="siteDeploy" rows="3" placeholder="composer install">${wizard.siteDeploy.post_deploy_commands}</textarea>
        </div>
        <div class="wizard-field">
          <label for="wiz-deploy-restart">Restart services after deploy</label>
          <input id="wiz-deploy-restart" type="checkbox" name="restart_services" data-wizard-group="siteDeploy" ${
            wizard.siteDeploy.restart_services ? "checked" : ""
          } />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Deploying..." : "Deploy";
      bodyMarkup = `
        <div>Confirm deploy to ${siteId || "(missing)"}.</div>
        <div class="preview-meta">
          <div><strong>Source</strong><span>${wizard.siteDeploy.source}</span></div>
          <div><strong>Type</strong><span>${wizard.siteDeploy.source_type}</span></div>
          <div><strong>Ref</strong><span>${wizard.siteDeploy.ref || "default"}</span></div>
        </div>
      `;
    }
  } else if (wizard.mode === "site-backup") {
    const siteId = wizard.siteBackup.site_id;
    steps = ["Backup", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-site-backup-id">Site</label>
          <input id="wiz-site-backup-id" name="site_id" data-wizard-group="siteBackup" value="${siteId}" />
        </div>
        <div class="wizard-field">
          <label for="wiz-site-backup-label">Label</label>
          <input id="wiz-site-backup-label" name="label" data-wizard-group="siteBackup" value="${wizard.siteBackup.label}" placeholder="pre-release" />
        </div>
        <div class="wizard-field">
          <label for="wiz-site-backup-db">Include database</label>
          <input id="wiz-site-backup-db" type="checkbox" name="include_database" data-wizard-group="siteBackup" ${
            wizard.siteBackup.include_database ? "checked" : ""
          } />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Backing up..." : "Backup";
      bodyMarkup = `
        <div>Backup site ${siteId || "(missing)"}.</div>
        <div class="preview-meta">
          <div><strong>Label</strong><span>${wizard.siteBackup.label || "none"}</span></div>
          <div><strong>Include DB</strong><span>${wizard.siteBackup.include_database ? "yes" : "no"}</span></div>
        </div>
      `;
    }
  } else if (wizard.mode === "site-rollback") {
    const siteId = wizard.siteRollback.site_id;
    steps = ["Rollback", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-site-rollback-id">Site</label>
          <input id="wiz-site-rollback-id" name="site_id" data-wizard-group="siteRollback" value="${siteId}" />
        </div>
        <div class="wizard-field">
          <label for="wiz-site-backup-id">Backup ID</label>
          <input id="wiz-site-backup-id" name="backup_id" data-wizard-group="siteRollback" value="${wizard.siteRollback.backup_id}" placeholder="backup-uuid" />
        </div>
        <div class="wizard-field">
          <label for="wiz-site-rollback-restart">Restart services</label>
          <input id="wiz-site-rollback-restart" type="checkbox" name="restart_services" data-wizard-group="siteRollback" ${
            wizard.siteRollback.restart_services ? "checked" : ""
          } />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Rolling back..." : "Rollback";
      bodyMarkup = `
        <div>Rollback site ${siteId || "(missing)"}.</div>
        <div class="preview-meta">
          <div><strong>Backup</strong><span>${wizard.siteRollback.backup_id || "(missing)"}</span></div>
          <div><strong>Restart</strong><span>${wizard.siteRollback.restart_services ? "yes" : "no"}</span></div>
        </div>
      `;
    }
  } else if (wizard.mode === "site-services") {
    const siteId = wizard.siteServices.site_id;
    steps = ["Services", "Confirm"];
    if (wizard.step === 0) {
      bodyMarkup = `
        <div class="wizard-field">
          <label for="wiz-site-services-id">Site</label>
          <input id="wiz-site-services-id" name="site_id" data-wizard-group="siteServices" value="${siteId}" />
        </div>
        <div class="wizard-field">
          <label for="wiz-site-services-list">Services (comma separated, optional)</label>
          <input id="wiz-site-services-list" name="services" data-wizard-group="siteServices" value="${wizard.siteServices.services}" placeholder="php-fpm,nginx" />
        </div>
      `;
    } else {
      nextLabel = wizard.busy ? "Restarting..." : "Restart";
      bodyMarkup = `
        <div>Restart services for ${siteId || "(missing)"}.</div>
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
      const done = index <= wizard.maxStep ? "done" : "";
      const locked = index > wizard.maxStep ? "locked" : "";
      const disabled = wizard.busy || index > wizard.maxStep ? "disabled" : "";
      return `
        <button class="wizard-step ${active} ${done} ${locked}" data-wizard-action="goto-step" data-step-index="${index}" ${disabled}>
          <span class="wizard-step-index">${index + 1}</span>
          <span class="wizard-step-label">${escapeHtml(title)}</span>
        </button>
      `;
    })
    .join("");

  const errorMarkup = wizard.error ? `<div class="event-item error">${wizard.error}</div>` : "";
  const backDisabled = wizard.step === 0 || wizard.busy ? "disabled" : "";
  const nextDisabled = wizard.busy ? "disabled" : "";
  const pagesMarkup = steps
    .map((title, index) => {
      const placeholder = `
        <div class="wizard-page-placeholder">
          <div>${escapeHtml(title)}</div>
          <div>Step ${index + 1} of ${steps.length}</div>
        </div>
      `;
      const content = index === wizard.step ? `${bodyMarkup}${errorMarkup}` : placeholder;
      return `<div class="wizard-page">${content}</div>`;
    })
    .join("");
  const progressPercent = steps.length ? Math.round(((wizard.step + 1) / steps.length) * 100) : 0;
  const trackClass = directionClass ? `wizard-track ${directionClass}` : "wizard-track";
  elements.wizard.innerHTML = `
    <div class="wizard-shell">
      <div class="wizard-header">
        <div class="wizard-title">${escapeHtml(wizardModeLabel(wizard.mode))}</div>
        <div class="wizard-progress-wrap">
          <div class="wizard-progress" style="width:${progressPercent}%;"></div>
        </div>
      </div>
      <div class="wizard-steps">${stepMarkup}</div>
      <div class="wizard-viewport">
        <div class="${trackClass}" style="transform: translateX(-${wizard.step * 100}%);">
          ${pagesMarkup}
        </div>
      </div>
      <div class="wizard-actions">
        <button class="action ghost" data-wizard-action="close">Close</button>
        <button class="action ghost" data-wizard-action="back" ${backDisabled}>Back</button>
        <button class="action" data-wizard-action="next" ${nextDisabled}>${nextLabel}</button>
      </div>
    </div>
  `;
  renderBreadcrumb(steps);
  wizard.prevStep = wizard.step;
  renderOperationPanel();
}

function renderAll() {
  renderTree();
  renderStatusLine();
  renderFastActions();
  renderImageCatalog();
  renderGrid();
  renderPreview();
  renderWizard();
  renderOperationPanel();
  renderEvents();
  renderDebugPanel();
}

function selectNode(id) {
  clearCardTransitionTimer();
  cardTransitionBusy = false;
  queuedExpandNodeId = null;
  state.selectedId = id;
  state.ui.expandedCardId = null;
  renderAll();
  hydrateNode(id).catch(() => {});
}

function toggleAppCardDetails(nodeId) {
  if (!nodeId) {
    return;
  }
  if (cardTransitionBusy) {
    queuedExpandNodeId = nodeId;
    return;
  }
  const currentNodeId = state.ui.expandedCardId;
  if (!currentNodeId) {
    state.ui.expandedCardId = nodeId;
    renderGrid();
    markCardOpeningSequence(nodeId);
    return;
  }
  cardTransitionBusy = true;
  if (currentNodeId === nodeId) {
    closeExpandedCardAndMaybeOpen(null);
    return;
  }
  closeExpandedCardAndMaybeOpen(nodeId);
}

let pendingCardOpenTimer = null;

function openAppFromCard(nodeId) {
  if (!nodeId) {
    return;
  }
  clearCardTransitionTimer();
  cardTransitionBusy = false;
  queuedExpandNodeId = null;
  if (pendingCardOpenTimer) {
    window.clearTimeout(pendingCardOpenTimer);
    pendingCardOpenTimer = null;
  }
  const cards = elements.grid ? Array.from(elements.grid.querySelectorAll(".app-card")) : [];
  const card = cards.find((item) => item.getAttribute("data-node-id") === nodeId) || null;
  if (card) {
    card.classList.add("opening");
    pendingCardOpenTimer = window.setTimeout(() => {
      pendingCardOpenTimer = null;
      selectNode(nodeId);
    }, 180);
    return;
  }
  selectNode(nodeId);
}

async function hydrateNode(id) {
  const nodeId = id || state.selectedId;
  if (!nodeId) {
    return;
  }
  try {
    if (nodeId === "containers") {
      await loadPopularImages();
    } else if (nodeId === "routing") {
      await loadRoutes();
    } else if (nodeId === "recipes" || nodeId.endsWith(":container-recipes")) {
      await loadRecipes();
    } else if (nodeId === "hosts") {
      await loadHosts();
    } else if (nodeId === "monitoring") {
      await loadMonitoring();
    } else if (nodeId === "firewall") {
      await loadFirewall();
    } else if (nodeId === "vms") {
      await loadVms();
    } else if (nodeId === "sites") {
      await loadSites();
    } else if (nodeId && nodeId.startsWith("container:")) {
      const name = nodeId.split(":")[1];
      await loadContainerSnapshots(name);
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

function parseEnvBlock(raw) {
  const params = parseParametersInput(raw);
  const result = {};
  for (const [key, value] of Object.entries(params)) {
    if (key) {
      result[key] = value;
    }
  }
  return result;
}

function parseCsv(raw) {
  if (!raw) {
    return [];
  }
  return raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function parseMultiline(raw) {
  if (!raw) {
    return [];
  }
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function escapeHtml(value) {
  if (value === null || value === undefined) {
    return "";
  }
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function statusPillClass(status) {
  if (status === "pass") {
    return "running";
  }
  if (status === "skipped") {
    return "soon";
  }
  return "stopped";
}

function normalizeRecipeApplyReport(response, recipeName, target, dryRun = false) {
  const payload = response && typeof response === "object" ? response : {};
  const probe = payload.probe && typeof payload.probe === "object" ? payload.probe : {};
  const healthChecks =
    probe.health_checks && typeof probe.health_checks === "object" ? probe.health_checks : null;
  const healthSummary =
    healthChecks && healthChecks.summary && typeof healthChecks.summary === "object"
      ? healthChecks.summary
      : {};
  const checks = healthChecks && Array.isArray(healthChecks.checks) ? healthChecks.checks : [];
  const serviceProbes = Object.entries(probe).filter(
    ([key, value]) => key !== "health_checks" && key !== "error" && typeof value === "boolean"
  );
  return {
    recipe: payload.recipe || recipeName || "unknown",
    target: target || "host",
    message: payload.message || "",
    dryRun: Boolean(dryRun),
    plan: Array.isArray(payload.plan) ? payload.plan : [],
    applied: Array.isArray(payload.applied) ? payload.applied : [],
    error: probe && typeof probe.error === "string" ? probe.error : "",
    serviceProbes,
    health: {
      recipes:
        healthChecks && Array.isArray(healthChecks.recipes)
          ? healthChecks.recipes.map((item) => String(item))
          : [],
      checks,
      summary: {
        passed: Number(healthSummary.passed) || 0,
        failed: Number(healthSummary.failed) || 0,
        skipped: Number(healthSummary.skipped) || 0,
      },
    },
    at: new Date().toISOString(),
  };
}

function rememberRecipeApplyReport(report) {
  if (!report || !report.target) {
    return;
  }
  const key = report.target;
  state.recipeReports.set(key, report);
  state.recipeReportOrder = [key, ...state.recipeReportOrder.filter((item) => item !== key)];
}

function getLatestRecipeApplyReport(target = null) {
  if (target) {
    return state.recipeReports.get(target) || null;
  }
  const latestKey = state.recipeReportOrder[0];
  return latestKey ? state.recipeReports.get(latestKey) || null : null;
}

function recipeHealthSummaryLabel(report) {
  if (!report || !report.health) {
    return "";
  }
  const summary = report.health.summary || {};
  const passed = Number(summary.passed) || 0;
  const failed = Number(summary.failed) || 0;
  const skipped = Number(summary.skipped) || 0;
  if (passed === 0 && failed === 0 && skipped === 0) {
    return "";
  }
  return `${passed} pass, ${failed} fail, ${skipped} skipped`;
}

function renderRecipeApplyReport(report, scopedTarget = "") {
  if (!report) {
    return "";
  }
  const summary = report.health && report.health.summary ? report.health.summary : {};
  const passed = Number(summary.passed) || 0;
  const failed = Number(summary.failed) || 0;
  const skipped = Number(summary.skipped) || 0;
  const checks = report.health && Array.isArray(report.health.checks) ? report.health.checks : [];
  const serviceProbes = Array.isArray(report.serviceProbes) ? report.serviceProbes : [];
  const scopeLabel = scopedTarget ? `container ${scopedTarget}` : report.target === "host" ? "host" : report.target;
  const checksMarkup = checks.length
    ? checks
        .slice(0, 8)
        .map((check) => {
          const status = String(check.status || "fail").toLowerCase();
          const type = String(check.type || "check");
          const name = check.name || check.id || "unnamed check";
          const details = check.details ? `<pre>${escapeHtml(check.details)}</pre>` : "";
          return `
            <div class="event-item">
              <div class="card-meta">
                <span class="pill ${statusPillClass(status)}">${escapeHtml(status)}</span>
                <span class="pill">${escapeHtml(type)}</span>
                <span>${escapeHtml(name)}</span>
              </div>
              ${details}
            </div>
          `;
        })
        .join("")
    : "";
  const serviceMarkup = serviceProbes.length
    ? serviceProbes
        .map(
          ([service, available]) =>
            `<span class="pill ${available ? "running" : "stopped"}">${escapeHtml(service)}:${available ? "ok" : "missing"}</span>`
        )
        .join("")
    : "";

  return `
    <div class="event-item">
      <div><strong>Last recipe run</strong> — ${escapeHtml(report.recipe)} on ${escapeHtml(scopeLabel)}</div>
      <div class="card-meta">
        <span class="pill">${report.dryRun ? "dry-run" : "applied"}</span>
        <span class="pill">${escapeHtml(new Date(report.at).toLocaleString())}</span>
        ${
          passed || failed || skipped
            ? `<span class="pill running">pass ${passed}</span><span class="pill stopped">fail ${failed}</span><span class="pill soon">skipped ${skipped}</span>`
            : ""
        }
      </div>
      ${
        report.plan && report.plan.length
          ? `<div class="card-meta"><span class="pill">${report.plan.length} planned steps</span><span class="pill">${report.applied.length} applied steps</span></div>`
          : ""
      }
      ${report.error ? `<div class="event-item error">${escapeHtml(report.error)}</div>` : ""}
      ${serviceMarkup ? `<div class="card-meta">${serviceMarkup}</div>` : ""}
      ${checksMarkup}
    </div>
  `;
}

function apiErrorMessage(payload, status) {
  if (payload && typeof payload === "object") {
    const primary =
      payload.error ||
      payload.detail ||
      payload.message ||
      (typeof payload.details === "string" ? payload.details : "");
    if (primary) {
      return String(primary);
    }
  }
  if (typeof payload === "string" && payload.trim()) {
    return payload.trim();
  }
  return status ? `Request failed (${status})` : "Request failed";
}

function captureDebugError(error, context = {}) {
  const details = error && error.details ? error.details : null;
  const payload = {
    at: new Date().toISOString(),
    message: (error && error.message) || "Request failed",
    status: error && Number.isFinite(error.status) ? error.status : null,
    method: context.method || (error && error.method) || null,
    path: context.path || (error && error.path) || null,
    details,
    stack: error && error.stack ? error.stack : null,
  };
  state.debug.lastError = payload;
  if (typeof console !== "undefined" && console.error) {
    console.error("[lizard-debug] API error", payload);
  }
  renderDebugPanel();
}

async function apiRequest(path, options = {}) {
  const requestOptions = { ...options };
  const suppressAuthOverlay = Boolean(requestOptions.suppressAuthOverlay);
  delete requestOptions.suppressAuthOverlay;
  const method = requestOptions.method || "GET";

  let response;
  try {
    response = await fetch(path, {
      headers: {
        "Content-Type": "application/json",
      },
      ...requestOptions,
    });
  } catch (fetchErr) {
    const error = new Error(`Network request failed: ${(fetchErr && fetchErr.message) || fetchErr}`);
    error.status = 0;
    error.details = {
      error: error.message,
    };
    error.path = path;
    error.method = method;
    captureDebugError(error, { path, method });
    throw error;
  }
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
    const message = apiErrorMessage(data, response.status);
    const error = new Error(message);
    error.status = response.status;
    error.details = data;
    error.path = path;
    error.method = method;
    captureDebugError(error, { path, method });
    if (response.status === 401 || response.status === 403) {
      const authMessage = apiErrorMessage(data, response.status);
      if (!suppressAuthOverlay) {
        if (authMessage.toLowerCase().includes("admin")) {
          showAdminOverlay(authMessage || "Admin session required.");
        } else {
          showAuthOverlay("Session required. Enter a delegated token.");
        }
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
  if (!state.auth.active) {
    stopImageCatalogRefreshLoop();
  }
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
  stopImageCatalogRefreshLoop();
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

function stopImageCatalogRefreshLoop() {
  if (imageCatalogRefreshTimer) {
    window.clearInterval(imageCatalogRefreshTimer);
    imageCatalogRefreshTimer = null;
  }
}

function startImageCatalogRefreshLoop() {
  stopImageCatalogRefreshLoop();
  if (!state.auth.active) {
    return;
  }
  loadPopularImages({ background: true, suppressAuthOverlay: true }).catch(() => {});
  imageCatalogRefreshTimer = window.setInterval(() => {
    if (!state.auth.active) {
      stopImageCatalogRefreshLoop();
      return;
    }
    loadPopularImages({ background: true, suppressAuthOverlay: true }).catch(() => {});
  }, IMAGE_CATALOG_REFRESH_INTERVAL_MS);
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
  stopImageCatalogRefreshLoop();
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

function buildSystemUpgradePayload(upgradeState, dryRun = false) {
  return {
    update_packages: Boolean(upgradeState.update_packages),
    full_upgrade: Boolean(upgradeState.update_packages && upgradeState.full_upgrade),
    apply_migrations: Boolean(upgradeState.apply_migrations),
    dry_run: Boolean(dryRun),
  };
}

async function fetchSystemUpgradePreflight(upgradeState) {
  const payload = buildSystemUpgradePayload(upgradeState, true);
  const [preflight, migrationStatusPayload, backupPayload] = await Promise.all([
    apiRequest("/api/system/upgrade", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
    apiRequest("/api/migrations/status").catch(() => null),
    apiRequest("/api/backup/list").catch(() => ({ backups: [] })),
  ]);
  const migrationStatus =
    migrationStatusPayload && typeof migrationStatusPayload === "object" ? migrationStatusPayload : null;
  const backups =
    backupPayload && Array.isArray(backupPayload.backups) ? backupPayload.backups : [];
  return { preflight, migrationStatus, backups };
}

async function checkForUpdateAndReload(options = {}) {
  const payload = {
    apply_migrations: options.applyMigrations !== false,
    restart_mode: options.restartMode || "auto",
    auto_stash: options.autoStash !== false,
  };
  return apiRequest("/api/system/update-reload", {
    method: "POST",
    body: JSON.stringify(payload),
  });
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

async function loadPopularImages(options = {}) {
  const background = Boolean(options.background);
  if (!background) {
    state.images.loading = true;
    state.images.error = null;
    renderImageCatalog();
    renderWizard();
  }
  try {
    const payload = await apiRequest("/api/containers/images/popular", {
      suppressAuthOverlay: options.suppressAuthOverlay === true,
    });
    state.images.popular = Array.isArray(payload.images) ? payload.images : [];
    state.images.remotes = Array.isArray(payload.remotes) ? payload.remotes : [];
    state.images.latest = payload.latest || null;
    state.images.refreshedAt = payload && payload.refreshed_at ? payload.refreshed_at : new Date().toISOString();
    state.images.error = null;
    if (state.wizard.active && state.wizard.mode === "create-container") {
      const preferred = state.images.popular[0]
        ? state.images.popular[0].resolved_name || state.images.popular[0].name
        : state.images.latest && state.images.latest.ubuntu_lts
        ? state.images.latest.ubuntu_lts
        : "ubuntu:lts";
      if (!state.wizard.form.distro || state.wizard.form.distro === "ubuntu:lts") {
        state.wizard.form.distro = preferred;
      }
    }
    if (options.log) {
      logEvent("success", "Image catalog refreshed");
    }
  } catch (err) {
    state.images.error = err.message || "Failed to load image catalog";
    if (options.log) {
      logEvent("error", state.images.error);
    }
  } finally {
    if (!background) {
      state.images.loading = false;
    }
    renderImageCatalog();
    renderWizard();
  }
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
    const payload = await apiRequest("/api/monitoring/resources?include_history=1&history_samples=24");
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
  state.firewallPreviousRules = Array.isArray(state.firewall.rules) ? state.firewall.rules.slice() : [];
  renderPreview();
  try {
    const statusPayload = await apiRequest("/api/firewall/status");
    const rulesPayload = await apiRequest("/api/firewall/rules");
    const diffPayload = await apiRequest("/api/firewall/rules/diff", {
      method: "POST",
      body: JSON.stringify({ baseline: state.firewallPreviousRules }),
    });
    state.firewall = {
      backend: statusPayload.backend || null,
      active: statusPayload.active,
      rules: (rulesPayload && rulesPayload.rules) || [],
      added: diffPayload.added || [],
      removed: diffPayload.removed || [],
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

async function loadSites(options = {}) {
  state.sitesLoading = true;
  renderPreview();
  try {
    const payload = await apiRequest("/api/sites");
    state.sites = payload && Array.isArray(payload.sites) ? payload.sites : [];
    const keepIds = new Set(state.sites.map((site) => site.id || site.name).filter(Boolean));
    for (const key of Array.from(state.siteDetails.keys())) {
      if (!keepIds.has(key)) {
        state.siteDetails.delete(key);
        state.siteBackups.delete(key);
      }
    }
    if (options.details !== false && state.sites.length) {
      const detailPromises = state.sites.map((site) =>
        loadSiteDetails(site.id || site.name, { includeBackups: true, silent: !options.log })
      );
      await Promise.allSettled(detailPromises);
    }
    if (options.log) {
      logEvent("success", "Sites refreshed");
    }
    return state.sites;
  } catch (err) {
    logEvent("error", err.message || "Failed to load sites");
    throw err;
  } finally {
    state.sitesLoading = false;
    renderPreview();
  }
}

async function loadSiteDetails(siteId, options = {}) {
  if (!siteId) {
    return null;
  }
  const silent = Boolean(options.silent);
  state.siteDetailsLoading.add(siteId);
  renderPreview();
  try {
    const payload = await apiRequest(`/api/sites/${encodeURIComponent(siteId)}`);
    const detail = payload && payload.site ? payload.site : null;
    if (detail) {
      state.siteDetails.set(siteId, detail);
      if (options.includeBackups) {
        await loadSiteBackups(siteId, { silent: true });
      }
    }
    if (options.log) {
      logEvent("success", `Site ${siteId} details refreshed`);
    }
    return detail;
  } catch (err) {
    if (!silent) {
      logEvent("error", err.message || `Failed to load site ${siteId}`);
    }
    return null;
  } finally {
    state.siteDetailsLoading.delete(siteId);
    renderPreview();
  }
}

async function loadSiteBackups(siteId, options = {}) {
  if (!siteId) {
    return [];
  }
  const silent = Boolean(options.silent);
  state.siteBackupsLoading.add(siteId);
  renderPreview();
  try {
    const payload = await apiRequest(`/api/sites/${encodeURIComponent(siteId)}/backups`);
    const backups = payload && Array.isArray(payload.backups) ? payload.backups : [];
    state.siteBackups.set(siteId, backups);
    if (options.log) {
      logEvent("success", `Backups refreshed for ${siteId}`);
    }
    renderPreview();
    return backups;
  } catch (err) {
    if (!silent) {
      logEvent("error", err.message || `Failed to load backups for ${siteId}`);
    }
    return [];
  } finally {
    state.siteBackupsLoading.delete(siteId);
    renderPreview();
  }
}

async function loadContainerSnapshots(containerName) {
  if (!containerName) {
    return [];
  }
  state.containerSnapshotLoading.add(containerName);
  renderPreview();
  try {
    const payload = await apiRequest(`/api/containers/${encodeURIComponent(containerName)}/snapshots`);
    const snaps = payload && Array.isArray(payload.snapshots) ? payload.snapshots : [];
    state.containerSnapshots.set(containerName, snaps);
    renderPreview();
    return snaps;
  } catch (err) {
    logEvent("error", err.message || `Failed to load snapshots for ${containerName}`);
    return [];
  } finally {
    state.containerSnapshotLoading.delete(containerName);
    renderPreview();
  }
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

  if (actionId === "image-catalog-refresh") {
    await loadPopularImages({ log: true });
    return;
  }

  if (actionId === "open-settings") {
    if (state.nodesById.has("settings")) {
      selectNode("settings");
    } else {
      logEvent("error", "Settings app is not available");
    }
    return;
  }

  if (actionId === "settings-fast-actions-default") {
    updateFastActions(FAST_ACTION_DEFAULT_IDS);
    renderFastActions();
    renderPreview();
    logEvent("success", "Fast actions reset to defaults");
    return;
  }

  if (actionId === "container-start" || actionId === "container-stop" || actionId === "container-restart") {
    const containerName = node && node.context ? node.context.container : null;
    if (!containerName) {
      logEvent("error", "No container selected");
      return;
    }
    const path =
      actionId === "container-start"
        ? `/api/containers/${containerName}/start`
        : actionId === "container-stop"
        ? `/api/containers/${containerName}/stop`
        : `/api/containers/${containerName}/restart`;
    const response = await apiRequest(path, { method: "POST" });
    logEvent("success", response.message || `${actionId.replace("container-", "")} sent to ${containerName}`);
    await loadGraph({ skipProbe: true });
    await hydrateNode(node ? node.id : state.selectedId);
    return;
  }

  if (actionId === "container-snapshot") {
    const containerName = node && node.context ? node.context.container : null;
    if (!containerName) {
      logEvent("error", "No container selected");
      return;
    }
    openWizard("container-snapshot", containerName);
    return;
  }

  if (actionId === "container-snapshot-restore") {
    const containerName = node && node.context ? node.context.container : params.container;
    const snapshot = params.snapshot;
    if (!containerName || !snapshot) {
      logEvent("error", "Snapshot and container are required");
      return;
    }
    const response = await apiRequest(
      `/api/containers/${encodeURIComponent(containerName)}/snapshots/${encodeURIComponent(snapshot)}/restore`,
      { method: "POST", body: JSON.stringify({}) }
    );
    logEvent("success", response.message || `Snapshot ${snapshot} restored for ${containerName}`);
    await loadContainerSnapshots(containerName);
    await loadGraph({ skipProbe: true });
    return;
  }

  if (actionId === "container-snapshot-delete") {
    const containerName = node && node.context ? node.context.container : params.container;
    const snapshot = params.snapshot;
    if (!containerName || !snapshot) {
      logEvent("error", "Snapshot and container are required");
      return;
    }
    const confirmed = window.confirm(`Delete snapshot ${snapshot} for ${containerName}?`);
    if (!confirmed) {
      return;
    }
    const response = await apiRequest(
      `/api/containers/${encodeURIComponent(containerName)}/snapshots/${encodeURIComponent(snapshot)}`,
      { method: "DELETE" }
    );
    logEvent("success", response.message || `Snapshot ${snapshot} deleted for ${containerName}`);
    await loadContainerSnapshots(containerName);
    return;
  }

  if (actionId === "container-logs") {
    const containerName = node && node.context ? node.context.container : null;
    if (!containerName) {
      logEvent("error", "No container selected");
      return;
    }
    const response = await apiRequest(`/api/containers/${encodeURIComponent(containerName)}/logs`);
    const snippet = (response.logs || "").split("\n").slice(-20).join("\n");
    logEvent("success", `Logs for ${containerName} (tail):\n${snippet}`);
    return;
  }

  if (actionId === "container-exec") {
    const containerName = node && node.context ? node.context.container : null;
    if (!containerName) {
      logEvent("error", "No container selected");
      return;
    }
    openWizard("exec", containerName);
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
    const preload = {
      mode: "close",
      port: params.port || "",
      protocol: params.protocol || "tcp",
      source: params.source || "",
    };
    state.wizard.firewall = { ...state.wizard.firewall, ...preload };
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

  if (actionId === "sites-refresh") {
    await loadSites({ log: true });
    return;
  }

  if (actionId === "site-create") {
    openWizard("site-create");
    return;
  }

  if (actionId === "site-deploy") {
    const siteId = params.site;
    openWizard("site-deploy", null, { siteId });
    return;
  }

  if (actionId === "site-backup") {
    const siteId = params.site;
    openWizard("site-backup", null, { siteId });
    return;
  }

  if (actionId === "site-rollback") {
    const siteId = params.site;
    openWizard("site-rollback", null, { siteId });
    if (params.backup) {
      state.wizard.siteRollback.backup_id = params.backup;
      renderWizard();
    }
    return;
  }

  if (actionId === "site-services") {
    const siteId = params.site;
    openWizard("site-services", null, { siteId });
    return;
  }

  if (actionId === "site-logs") {
    const siteId = params.site;
    if (!siteId) {
      logEvent("error", "Site ID missing");
      return;
    }
    const response = await apiRequest(`/api/sites/${encodeURIComponent(siteId)}/logs`);
    const logs = response && response.logs ? String(response.logs).split("\n").slice(-20).join("\n") : "No logs";
    logEvent("success", `Logs for ${siteId}:\n${logs}`);
    return;
  }

  if (actionId === "site-health") {
    const siteId = params.site;
    if (!siteId) {
      logEvent("error", "Site ID missing");
      return;
    }
    const response = await apiRequest(`/api/sites/${encodeURIComponent(siteId)}/health`);
    logEvent("success", response.message || `Health: ${JSON.stringify(response)}`);
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

  if (actionId === "vm-snapshot") {
    const name = params.vm || (node && node.context ? node.context.vm : null);
    openWizard("vm-snapshot", null, { vmName: name });
    return;
  }

  if (actionId === "vm-restore") {
    const name = params.vm;
    const snapshot = params.snapshot;
    if (!name || !snapshot) {
      logEvent("error", "VM and snapshot are required");
      return;
    }
    const response = await apiRequest(`/api/vms/${encodeURIComponent(name)}/snapshots/${encodeURIComponent(snapshot)}/restore`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    logEvent("success", response.message || `Snapshot ${snapshot} restored for ${name}`);
    await loadVms();
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

  if (actionId === "system-upgrade") {
    openWizard("system-upgrade");
    return;
  }

  if (actionId === "system-update-reload") {
    const confirmed = window.confirm(
      "Check for repository updates and reload Fortress API/WebUI if new commits are pulled? Local changes are auto-stashed and restored."
    );
    if (!confirmed) {
      return;
    }
    try {
      const response = await checkForUpdateAndReload({ applyMigrations: true, restartMode: "auto", autoStash: true });
      state.systemUpgrade.lastUpdateReload = {
        at: new Date().toISOString(),
        result: response,
      };
      const stashUsed = Boolean(response && response.stash && response.stash.used);
      const stashRestoreConflict = Boolean(response && response.stash && response.stash.restore_conflict);
      const appliedMigrations =
        response &&
        response.migrations &&
        Array.isArray(response.migrations.applied)
          ? response.migrations.applied.length
          : 0;
      if (stashRestoreConflict) {
        logEvent("error", (response && response.message) || "Update pulled but local changes could not be restored");
      } else if (response && response.updated) {
        const reloadScheduled = Boolean(response.reload && response.reload.scheduled);
        const stashSuffix = stashUsed ? ", local changes restored from auto-stash" : "";
        logEvent(
          "success",
          `Update pulled (${appliedMigrations} migrated stores, ${reloadScheduled ? "reload scheduled" : "reload skipped"}${stashSuffix})`
        );
      } else {
        const stashSuffix = stashUsed ? " (local changes auto-stashed/restored)" : "";
        logEvent("success", `${(response && response.message) || "Already up to date"}${stashSuffix}`);
      }
      renderPreview();
      const reloadDelayMs =
        response && response.reload && response.reload.scheduled ? 2600 : 900;
      logEvent("success", `Reloading WebUI in ${Math.max(1, Math.round(reloadDelayMs / 1000))}s...`);
      window.setTimeout(() => {
        window.location.reload();
      }, reloadDelayMs);
    } catch (err) {
      logEvent("error", err.message || "Check update and reload failed");
    }
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

async function handleWizardAction(action, payload = {}) {
  if (!state.wizard.active) {
    return;
  }
  if (action === "add-image") {
    const alias = state.wizard.imagePreset.alias.trim();
    const label = state.wizard.imagePreset.label.trim();
    if (!alias) {
      state.wizard.error = "Image alias is required";
      renderWizard();
      return;
    }
    try {
      await apiRequest("/api/containers/images/popular", {
        method: "POST",
        body: JSON.stringify({ name: alias, label: label || undefined }),
      });
      state.wizard.imagePreset = { alias: "", label: "" };
      await loadPopularImages();
      logEvent("success", `Image preset saved (${alias})`);
    } catch (err) {
      state.wizard.error = err.message || "Failed to save image preset";
    }
    renderWizard();
    return;
  }
  if (action === "refresh-images") {
    await loadPopularImages({ log: true });
    return;
  }
  if (action === "remove-image") {
    const alias = payload.imageName || payload.name || "";
    if (!alias) {
      state.wizard.error = "Missing image alias";
      renderWizard();
      return;
    }
    try {
      await apiRequest("/api/containers/images/popular/remove", {
        method: "POST",
        body: JSON.stringify({ name: alias }),
      });
      await loadPopularImages();
      const availableValues = state.images.popular.map((item) => item.resolved_name || item.name);
      if (!availableValues.includes(state.wizard.form.distro)) {
        state.wizard.form.distro = availableValues[0] || "ubuntu:lts";
      }
      logEvent("success", `Image preset removed (${alias})`);
    } catch (err) {
      state.wizard.error = err.message || "Failed to remove image preset";
    }
    renderWizard();
    return;
  }
  if (action === "close") {
    closeWizardState();
    renderWizard();
    return;
  }
  if (action === "back") {
    setWizardStep(state.wizard.step - 1);
    renderWizard();
    return;
  }
  if (action === "goto-step") {
    if (state.wizard.busy) {
      return;
    }
    const requestedStep = Number.parseInt(String(payload.stepIndex || payload.step), 10);
    if (!Number.isFinite(requestedStep)) {
      return;
    }
    if (requestedStep > state.wizard.maxStep || requestedStep < 0) {
      return;
    }
    if (requestedStep === state.wizard.step) {
      return;
    }
    setWizardStep(requestedStep);
    renderWizard();
    return;
  }
  if (action === "next") {
    if (state.wizard.mode === "system-upgrade") {
      const upgrade = state.wizard.upgrade;
      if (state.wizard.step === 0) {
        state.wizard.busy = true;
        state.wizard.error = null;
        renderWizard();
        try {
          const preflightData = await fetchSystemUpgradePreflight(upgrade);
          const timestamp = new Date().toISOString();
          upgrade.preflight = preflightData.preflight;
          upgrade.migration_status = preflightData.migrationStatus;
          upgrade.backups = preflightData.backups;
          upgrade.preflight_at = timestamp;
          upgrade.backup_confirmation = false;
          state.systemUpgrade.lastPreflight = {
            at: timestamp,
            options: buildSystemUpgradePayload(upgrade, true),
            preflight: preflightData.preflight,
            migration_status: preflightData.migrationStatus,
            backups: preflightData.backups,
          };
          const migrationPlan =
            preflightData.preflight && Array.isArray(preflightData.preflight.migrations)
              ? preflightData.preflight.migrations
              : [];
          logEvent(
            "success",
            `Upgrade preflight ready (${migrationPlan.length} migration changes, ${preflightData.backups.length} backups listed)`
          );
          setWizardStep(1);
          renderPreview();
        } catch (err) {
          state.wizard.error = err.message || "Upgrade preflight failed";
        } finally {
          state.wizard.busy = false;
          renderWizard();
        }
        return;
      }
      if (state.wizard.step === 1) {
        setWizardStep(2);
        renderWizard();
        return;
      }
      if (state.wizard.step === 2) {
        if (!upgrade.backup_confirmation) {
          state.wizard.error = "Backup confirmation is required before upgrade.";
          renderWizard();
          return;
        }
        setWizardStep(3);
        renderWizard();
        return;
      }
      state.wizard.busy = true;
      state.wizard.error = null;
      renderWizard();
      try {
        const payload = buildSystemUpgradePayload(upgrade, false);
        const response = await apiRequest("/api/system/upgrade", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        state.systemUpgrade.lastExecution = {
          at: new Date().toISOString(),
          options: payload,
          result: response,
        };
        const appliedMigrations =
          response &&
          response.migrations &&
          Array.isArray(response.migrations.applied)
            ? response.migrations.applied.length
            : 0;
        logEvent(
          "success",
          `System upgrade complete (${appliedMigrations} migrated stores)`
        );
        state.wizard.active = false;
        state.wizard.mode = null;
        renderPreview();
      } catch (err) {
        state.wizard.error = err.message || "System upgrade failed";
      } finally {
        state.wizard.busy = false;
        renderWizard();
      }
      return;
    }
    const steps = wizardStepTotal(state.wizard.mode);
    if (state.wizard.step < steps - 1) {
      setWizardStep(state.wizard.step + 1);
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
        const report = normalizeRecipeApplyReport(
          response,
          recipeName,
          target || "host",
          Boolean(recipe.dry_run)
        );
        rememberRecipeApplyReport(report);
        const healthSummary = recipeHealthSummaryLabel(report);
        const baseMessage =
          response.message ||
          (recipe.dry_run ? `Plan generated for ${recipeName}` : `Recipe ${recipeName} applied`);
        logEvent(
          "success",
          healthSummary ? `${baseMessage} • Health: ${healthSummary}` : baseMessage
        );
        renderPreview();
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
      } else if (state.wizard.mode === "vm-snapshot") {
        const vmName = state.wizard.context.vm;
        const snapName = state.wizard.vmSnapshot.name.trim();
        if (!vmName) {
          throw new Error("VM is required");
        }
        if (!snapName) {
          throw new Error("Snapshot name is required");
        }
        const response = await apiRequest(`/api/vms/${encodeURIComponent(vmName)}/snapshots`, {
          method: "POST",
          body: JSON.stringify({ snapshot_name: snapName }),
        });
        logEvent("success", response.message || `Snapshot ${snapName} created for ${vmName}`);
        state.wizard.active = false;
        state.wizard.mode = null;
        await loadVms();
      } else if (state.wizard.mode === "container-snapshot") {
        const containerName = state.wizard.context.container;
        const snapName = state.wizard.containerSnapshot.name.trim();
        if (!containerName) {
          throw new Error("Container is required");
        }
        if (!snapName) {
          throw new Error("Snapshot name is required");
        }
        const response = await apiRequest(`/api/containers/${encodeURIComponent(containerName)}/snapshot`, {
          method: "POST",
          body: JSON.stringify({ snapshot_name: snapName, stateful: Boolean(state.wizard.containerSnapshot.stateful) }),
        });
        logEvent("success", response.message || `Snapshot ${snapName} created for ${containerName}`);
        state.wizard.active = false;
        state.wizard.mode = null;
        await loadContainerSnapshots(containerName);
        await loadGraph({ skipProbe: true });
      } else if (state.wizard.mode === "exec") {
        const containerName = state.wizard.context.container;
        if (!containerName) {
          throw new Error("Container is required");
        }
        const commandText = state.wizard.exec.command.trim();
        if (!commandText) {
          throw new Error("Command is required");
        }
        const command = commandText.split(/\s+/);
        const environment = parseEnvBlock(state.wizard.exec.environment);
        const response = await apiRequest(`/api/containers/${encodeURIComponent(containerName)}/exec`, {
          method: "POST",
          body: JSON.stringify({
            command,
            user: state.wizard.exec.user || undefined,
            workdir: state.wizard.exec.workdir || undefined,
            environment: environment && Object.keys(environment).length ? environment : undefined,
          }),
        });
        logEvent("success", response.output ? `Exec output: ${response.output.slice(0, 200)}...` : "Command executed");
        state.wizard.active = false;
        state.wizard.mode = null;
      } else if (state.wizard.mode === "site-create") {
        const payload = {
          name: state.wizard.siteCreate.name.trim(),
          primary_domain: state.wizard.siteCreate.primary_domain.trim(),
          domains: parseCsv(state.wizard.siteCreate.domains),
          container_name: state.wizard.siteCreate.container_name,
          docroot: state.wizard.siteCreate.docroot.trim() || "/var/www/html",
          runtime: state.wizard.siteCreate.php_version
            ? { php_version: state.wizard.siteCreate.php_version.trim() }
            : undefined,
          create_database: Boolean(state.wizard.siteCreate.create_database),
          create_user: Boolean(state.wizard.siteCreate.create_user),
        };
        if (!payload.name || !payload.primary_domain || !payload.container_name) {
          throw new Error("Name, primary domain, and container are required");
        }
        const response = await apiRequest("/api/sites", {
          method: "POST",
          body: JSON.stringify(payload),
        });
        logEvent("success", response.message || `Site ${payload.name} created`);
        state.wizard.active = false;
        state.wizard.mode = null;
        await loadSites();
      } else if (state.wizard.mode === "site-deploy") {
        const siteId = state.wizard.siteDeploy.site_id.trim();
        if (!siteId) {
          throw new Error("Site ID is required");
        }
        const commands = parseMultiline(state.wizard.siteDeploy.post_deploy_commands);
        const payload = {
          source_type: state.wizard.siteDeploy.source_type,
          source: state.wizard.siteDeploy.source.trim(),
          ref: state.wizard.siteDeploy.ref.trim() || undefined,
          subdir: state.wizard.siteDeploy.subdir.trim() || undefined,
          strip_components: Number.parseInt(state.wizard.siteDeploy.strip_components, 10) || 0,
          post_deploy_commands: commands,
          restart_services: Boolean(state.wizard.siteDeploy.restart_services),
        };
        if (!payload.source) {
          throw new Error("Source is required");
        }
        const response = await apiRequest(`/api/sites/${encodeURIComponent(siteId)}/deploy`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        logEvent("success", response.message || `Deploy triggered for ${siteId}`);
        await loadSiteDetails(siteId, { includeBackups: true, silent: true });
        state.wizard.active = false;
        state.wizard.mode = null;
      } else if (state.wizard.mode === "site-backup") {
        const siteId = state.wizard.siteBackup.site_id.trim();
        if (!siteId) {
          throw new Error("Site ID is required");
        }
        const payload = {
          include_database: Boolean(state.wizard.siteBackup.include_database),
          label: state.wizard.siteBackup.label.trim() || undefined,
        };
        const response = await apiRequest(`/api/sites/${encodeURIComponent(siteId)}/backup`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        logEvent("success", response.message || `Backup created for ${siteId}`);
        await loadSiteBackups(siteId, { silent: true });
        state.wizard.active = false;
        state.wizard.mode = null;
      } else if (state.wizard.mode === "site-rollback") {
        const siteId = state.wizard.siteRollback.site_id.trim();
        const backupId = state.wizard.siteRollback.backup_id.trim();
        if (!siteId || !backupId) {
          throw new Error("Site ID and backup ID are required");
        }
        const payload = {
          backup_id: backupId,
          restart_services: Boolean(state.wizard.siteRollback.restart_services),
        };
        const response = await apiRequest(`/api/sites/${encodeURIComponent(siteId)}/rollback`, {
          method: "POST",
          body: JSON.stringify(payload),
        });
        logEvent("success", response.message || `Rollback started for ${siteId}`);
        await loadSiteDetails(siteId, { includeBackups: true, silent: true });
        state.wizard.active = false;
        state.wizard.mode = null;
      } else if (state.wizard.mode === "site-services") {
        const siteId = state.wizard.siteServices.site_id.trim();
        if (!siteId) {
          throw new Error("Site ID is required");
        }
        const services = parseCsv(state.wizard.siteServices.services);
        const response = await apiRequest(`/api/sites/${encodeURIComponent(siteId)}/services/restart`, {
          method: "POST",
          body: JSON.stringify({ services: services.length ? services : undefined }),
        });
        logEvent("success", response.message || `Services restarted for ${siteId}`);
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
  if (["containers", "routing", "recipes", "hosts", "monitoring", "firewall", "vms"].includes(state.selectedId)) {
    await hydrateNode(state.selectedId);
  }
  startImageCatalogRefreshLoop();
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

    const remoteFilter = event.target.closest("[data-image-remote]");
    if (remoteFilter) {
      const selectedRemote = remoteFilter.getAttribute("data-image-remote") || "all";
      state.images.remoteFilter = selectedRemote || "all";
      renderImageCatalog();
      return;
    }

    const navNode = event.target.closest("[data-nav-node-id]");
    if (navNode) {
      const nodeId = navNode.getAttribute("data-nav-node-id");
      if (nodeId) {
        if (state.wizard.active) {
          closeWizardState();
        }
        selectNode(nodeId);
      }
      return;
    }

    const cardOpen = event.target.closest("[data-card-open-node]");
    if (cardOpen) {
      event.preventDefault();
      event.stopPropagation();
      openAppFromCard(cardOpen.getAttribute("data-card-open-node"));
      return;
    }

    const cardExpand = event.target.closest("[data-card-expand-node]");
    if (cardExpand) {
      event.preventDefault();
      event.stopPropagation();
      toggleAppCardDetails(cardExpand.getAttribute("data-card-expand-node"));
      return;
    }

    const card = event.target.closest(".app-card");
    if (card) {
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
    const data = { ...action.dataset };
    delete data.wizardAction;
    handleWizardAction(action.getAttribute("data-wizard-action"), data);
  });

  if (elements.breadcrumb) {
    elements.breadcrumb.addEventListener("click", (event) => {
      const action = event.target.closest("[data-wizard-action]");
      if (!action) {
        return;
      }
      const data = { ...action.dataset };
      delete data.wizardAction;
      handleWizardAction(action.getAttribute("data-wizard-action"), data);
    });
  }

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
    } else if (group === "upgrade") {
      state.wizard.upgrade[target.name] = value;
      if (target.name === "update_packages" && !value) {
        state.wizard.upgrade.full_upgrade = false;
      }
    } else if (group === "recipe") {
      state.wizard.recipe[target.name] = value;
    } else if (group === "host") {
      state.wizard.host[target.name] = value;
    } else if (group === "network") {
      state.wizard.network[target.name] = value;
    } else if (group === "firewall") {
      state.wizard.firewall[target.name] = value;
    } else if (group === "vmSnapshot") {
      state.wizard.vmSnapshot[target.name] = value;
    } else if (group === "containerSnapshot") {
      state.wizard.containerSnapshot[target.name] = target.type === "checkbox" ? target.checked : value;
    } else if (group === "exec") {
      state.wizard.exec[target.name] = value;
    } else if (group === "siteCreate") {
      state.wizard.siteCreate[target.name] = value;
    } else if (group === "siteDeploy") {
      state.wizard.siteDeploy[target.name] = value;
    } else if (group === "siteBackup") {
      state.wizard.siteBackup[target.name] = value;
    } else if (group === "siteRollback") {
      state.wizard.siteRollback[target.name] = value;
    } else if (group === "siteServices") {
      state.wizard.siteServices[target.name] = value;
    } else if (group === "imagePreset") {
      state.wizard.imagePreset[target.name] = value;
    } else {
      state.wizard.form[target.name] = value;
    }
  });

  if (elements.preview) {
    elements.preview.addEventListener("input", (event) => {
      const target = event.target;
      if (!target) {
        return;
      }
      const fastActionId = target.getAttribute && target.getAttribute("data-setting-fast-action");
      if (!fastActionId) {
        return;
      }
      const enabled = Boolean(target.checked);
      const current = normalizeFastActions(state.ui.fastActions);
      const next = enabled
        ? [...current, fastActionId]
        : current.filter((id) => id !== fastActionId);
      updateFastActions(next);
      renderFastActions();
      renderPreview();
    });
  }

  if (elements.imageCatalog) {
    elements.imageCatalog.addEventListener("input", (event) => {
      const target = event.target;
      if (!target || target.id !== "image-hide-unavailable") {
        return;
      }
      state.images.hideUnavailable = Boolean(target.checked);
      renderImageCatalog();
    });
  }
}

window.addEventListener("DOMContentLoaded", () => {
  loadFastActionsPreference();
  renderDebugPanel();
  bindEvents();
  window.addEventListener("resize", scheduleGridRelayout);
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
