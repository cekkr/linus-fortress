import crypto from "crypto";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import fs from "fs/promises";
import { Agent, fetch } from "undici";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const HOST = process.env.FORTRESS_UI_HOST || "127.0.0.1";
const PORT = Number.parseInt(process.env.FORTRESS_UI_PORT || "8090", 10);
const API_URL = process.env.FORTRESS_API_URL || "https://127.0.0.1:8443";
const API_KEY = process.env.FORTRESS_UI_API_KEY || "";
const USER_TOKEN = process.env.FORTRESS_UI_USER_TOKEN || "";
const INSECURE_TLS = /^(1|true|yes)$/i.test(process.env.FORTRESS_UI_INSECURE_TLS || "");
const SESSION_TTL_SECONDS = Number.parseInt(process.env.FORTRESS_UI_SESSION_TTL || "43200", 10);
const SESSION_COOKIE = process.env.FORTRESS_UI_SESSION_COOKIE || "fortress_session";
const COOKIE_SECURE = /^(1|true|yes)$/i.test(process.env.FORTRESS_UI_COOKIE_SECURE || "");
const ADMIN_DB = process.env.FORTRESS_UI_ADMIN_DB || "/var/lib/fortress/ui_admins.json";
const ADMIN_AUDIT_LOG = process.env.FORTRESS_UI_ADMIN_AUDIT_LOG || "/var/lib/fortress/ui_admin_audit.log";
const ADMIN_SESSION_TTL_SECONDS = Number.parseInt(process.env.FORTRESS_UI_ADMIN_SESSION_TTL || "43200", 10);
const ADMIN_SESSION_COOKIE = process.env.FORTRESS_UI_ADMIN_SESSION_COOKIE || "fortress_admin_session";
const ADMIN_ENABLED = !/^(0|false|no)$/i.test(process.env.FORTRESS_UI_ADMIN_ENABLED || "1");
const ADMIN_LOCKOUT_THRESHOLD = Number.parseInt(process.env.FORTRESS_UI_LOCKOUT_THRESHOLD || "5", 10);
const ADMIN_LOCKOUT_MINUTES = Number.parseInt(process.env.FORTRESS_UI_LOCKOUT_MINUTES || "15", 10);
const PASSWORD_MIN_LENGTH = Number.parseInt(process.env.FORTRESS_UI_PASSWORD_MIN_LENGTH || "12", 10);

const sessions = new Map();
const adminSessions = new Map();

const dispatcher = INSECURE_TLS
  ? new Agent({
      connect: {
        rejectUnauthorized: false,
      },
    })
  : undefined;

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));
app.use("/api", async (req, res, next) => {
  if (!ADMIN_ENABLED) {
    next();
    return;
  }
  if (req.path.startsWith("/admin") || req.path === "/health") {
    next();
    return;
  }
  try {
    const authorized = await ensureAdminAuthorized(req, res);
    if (!authorized) {
      return;
    }
    next();
  } catch (err) {
    res.status(500).json({ error: "Admin guard failed" });
  }
});

function buildHeaders() {
  const headers = {
    Accept: "application/json",
  };
  return headers;
}

function authHeaders(tokenOverride) {
  const headers = buildHeaders();
  if (tokenOverride) {
    headers["X-User-Token"] = tokenOverride;
  } else if (API_KEY) {
    headers["X-API-Key"] = API_KEY;
  } else if (USER_TOKEN) {
    headers["X-User-Token"] = USER_TOKEN;
  }
  return headers;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) {
    return cookies;
  }
  const pairs = cookieHeader.split(";");
  for (const pair of pairs) {
    const [rawKey, ...rest] = pair.split("=");
    const key = rawKey ? rawKey.trim() : "";
    if (!key) {
      continue;
    }
    cookies[key] = decodeURIComponent(rest.join("=").trim());
  }
  return cookies;
}

function createSession(token) {
  const id = crypto.randomBytes(24).toString("hex");
  const ttl = Number.isFinite(SESSION_TTL_SECONDS) && SESSION_TTL_SECONDS > 0 ? SESSION_TTL_SECONDS : 0;
  const expiresAt = ttl ? Date.now() + ttl * 1000 : null;
  sessions.set(id, { token, expiresAt });
  return id;
}

function getSessionToken(req) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies[SESSION_COOKIE];
  if (!sessionId) {
    return "";
  }
  const session = sessions.get(sessionId);
  if (!session) {
    return "";
  }
  if (session.expiresAt && session.expiresAt <= Date.now()) {
    sessions.delete(sessionId);
    return "";
  }
  return session.token;
}

function clearSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies[SESSION_COOKIE];
  if (sessionId) {
    sessions.delete(sessionId);
  }
}

function setSessionCookie(res, sessionId) {
  const ttl = Number.isFinite(SESSION_TTL_SECONDS) && SESSION_TTL_SECONDS > 0 ? SESSION_TTL_SECONDS : 0;
  let cookie = `${SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; SameSite=Lax`;
  if (ttl) {
    cookie += `; Max-Age=${ttl}`;
  }
  if (COOKIE_SECURE) {
    cookie += "; Secure";
  }
  res.setHeader("Set-Cookie", cookie);
}

function clearSessionCookie(res) {
  let cookie = `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
  if (COOKIE_SECURE) {
    cookie += "; Secure";
  }
  res.setHeader("Set-Cookie", cookie);
}

async function ensureAdminDir() {
  const dir = path.dirname(ADMIN_DB);
  await fs.mkdir(dir, { recursive: true });
}

async function loadAdminStore() {
  try {
    const raw = await fs.readFile(ADMIN_DB, "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      return parsed;
    }
  } catch (err) {
    if (err.code !== "ENOENT") {
      console.warn("Failed to read admin DB:", err.message);
    }
  }
  return { users: {} };
}

async function saveAdminStore(store) {
  await ensureAdminDir();
  await fs.writeFile(ADMIN_DB, JSON.stringify(store, null, 2));
}

async function logAdminEvent(event) {
  const entry = { ...event, timestamp: new Date().toISOString() };
  const dir = path.dirname(ADMIN_AUDIT_LOG);
  await fs.mkdir(dir, { recursive: true });
  await fs.appendFile(ADMIN_AUDIT_LOG, `${JSON.stringify(entry)}\n`);
}

function passwordPolicyErrors(password) {
  const errors = [];
  if (!password || password.length < PASSWORD_MIN_LENGTH) {
    errors.push(`min_length:${PASSWORD_MIN_LENGTH}`);
  }
  if (!/[a-z]/.test(password || "")) {
    errors.push("lowercase_required");
  }
  if (!/[A-Z]/.test(password || "")) {
    errors.push("uppercase_required");
  }
  if (!/[0-9]/.test(password || "")) {
    errors.push("digit_required");
  }
  return errors;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const iterations = 200000;
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");
  return {
    salt: salt.toString("hex"),
    hash: hash.toString("hex"),
    iterations,
    digest: "sha256",
  };
}

function verifyPassword(password, record) {
  if (!record || !record.hash || !record.salt) {
    return false;
  }
  const salt = Buffer.from(record.salt, "hex");
  const hash = crypto.pbkdf2Sync(password, salt, record.iterations || 200000, 32, record.digest || "sha256");
  const stored = Buffer.from(record.hash, "hex");
  if (stored.length !== hash.length) {
    return false;
  }
  return crypto.timingSafeEqual(stored, hash);
}

function createAdminSession(username) {
  const id = crypto.randomBytes(24).toString("hex");
  const ttl = Number.isFinite(ADMIN_SESSION_TTL_SECONDS) && ADMIN_SESSION_TTL_SECONDS > 0 ? ADMIN_SESSION_TTL_SECONDS : 0;
  const expiresAt = ttl ? Date.now() + ttl * 1000 : null;
  adminSessions.set(id, { username, expiresAt });
  return id;
}

function getAdminSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies[ADMIN_SESSION_COOKIE];
  if (!sessionId) {
    return null;
  }
  const session = adminSessions.get(sessionId);
  if (!session) {
    return null;
  }
  if (session.expiresAt && session.expiresAt <= Date.now()) {
    adminSessions.delete(sessionId);
    return null;
  }
  return session;
}

function clearAdminSession(req) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies[ADMIN_SESSION_COOKIE];
  if (sessionId) {
    adminSessions.delete(sessionId);
  }
}

function setAdminSessionCookie(res, sessionId) {
  const ttl = Number.isFinite(ADMIN_SESSION_TTL_SECONDS) && ADMIN_SESSION_TTL_SECONDS > 0 ? ADMIN_SESSION_TTL_SECONDS : 0;
  let cookie = `${ADMIN_SESSION_COOKIE}=${sessionId}; Path=/; HttpOnly; SameSite=Lax`;
  if (ttl) {
    cookie += `; Max-Age=${ttl}`;
  }
  if (COOKIE_SECURE) {
    cookie += "; Secure";
  }
  res.setHeader("Set-Cookie", cookie);
}

function clearAdminSessionCookie(res) {
  let cookie = `${ADMIN_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
  if (COOKIE_SECURE) {
    cookie += "; Secure";
  }
  res.setHeader("Set-Cookie", cookie);
}

async function ensureAdminAuthorized(req, res) {
  if (!ADMIN_ENABLED) {
    return true;
  }
  const store = await loadAdminStore();
  const users = store.users || {};
  if (Object.keys(users).length === 0) {
    res.status(403).json({ error: "UI admin bootstrap required." });
    return false;
  }
  const session = getAdminSession(req);
  if (!session) {
    res.status(401).json({ error: "Admin session required." });
    return false;
  }
  return true;
}

function resolveAuthMode(req) {
  if (getSessionToken(req)) {
    return "session";
  }
  if (API_KEY) {
    return "api_key";
  }
  if (USER_TOKEN) {
    return "user_token";
  }
  return "none";
}

async function fortressRequest(method, apiPath, body, tokenOverride) {
  const url = new URL(apiPath, API_URL);
  const headers = authHeaders(tokenOverride);
  if (body) {
    headers["Content-Type"] = "application/json";
  }
  const options = {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  };
  if (dispatcher) {
    options.dispatcher = dispatcher;
  }
  const response = await fetch(url, options);
  const text = await response.text();
  let payload = null;
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch (err) {
      payload = text;
    }
  }
  if (!response.ok) {
    const detail = payload && payload.detail ? payload.detail : response.statusText;
    const error = new Error(detail || "Request failed");
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  return payload;
}

function normalizeIps(state) {
  const ips = new Set();
  const network = state && state.network && typeof state.network === "object" ? state.network : null;
  if (!network) {
    return [];
  }
  for (const iface of Object.values(network)) {
    const addresses = iface && Array.isArray(iface.addresses) ? iface.addresses : [];
    for (const address of addresses) {
      if (address.family === "inet" && address.address) {
        ips.add(address.address);
      }
    }
  }
  return Array.from(ips);
}

const STACK_KEYS = ["user.lizard.stack", "user.fortress.stack", "user.stack"];
const SERVICES_KEYS = ["user.lizard.services", "user.fortress.services", "user.services"];

function readConfigValue(config, expandedConfig, keys) {
  for (const key of keys) {
    if (config && typeof config[key] === "string" && config[key].trim()) {
      return config[key].trim();
    }
    if (expandedConfig && typeof expandedConfig[key] === "string" && expandedConfig[key].trim()) {
      return expandedConfig[key].trim();
    }
  }
  return null;
}

function parseServiceList(value) {
  if (!value) {
    return [];
  }
  return value
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function resolveContainerStack(name, config, expandedConfig) {
  const value = readConfigValue(config, expandedConfig, STACK_KEYS);
  if (value) {
    return value.toLowerCase();
  }
  if (name && name.toLowerCase().includes("lamp")) {
    return "lamp";
  }
  return null;
}

function resolveContainerServices(config, expandedConfig) {
  const value = readConfigValue(config, expandedConfig, SERVICES_KEYS);
  return parseServiceList(value);
}

function normalizeContainer(raw) {
  const status = raw.status || (raw.state ? raw.state.status : "unknown") || "unknown";
  const ips = normalizeIps(raw.state || {});
  const config = raw.config && typeof raw.config === "object" ? raw.config : {};
  const expandedConfig = raw.expanded_config && typeof raw.expanded_config === "object" ? raw.expanded_config : {};
  const stack = resolveContainerStack(raw.name, config, expandedConfig);
  const services = resolveContainerServices(config, expandedConfig);
  return {
    name: raw.name,
    status,
    type: raw.type || "container",
    ips,
    ip: ips[0] || null,
    architecture: raw.architecture || null,
    stack,
    services,
  };
}

async function getContainers(tokenOverride) {
  const payload = await fortressRequest("GET", "/status", null, tokenOverride);
  let containers = [];
  if (payload && Array.isArray(payload.containers)) {
    containers = payload.containers;
  } else if (payload && typeof payload.containers === "string") {
    try {
      const parsed = JSON.parse(payload.containers);
      containers = Array.isArray(parsed) ? parsed : [];
    } catch (err) {
      containers = [];
    }
  }
  return containers.map(normalizeContainer).sort((a, b) => a.name.localeCompare(b.name));
}

function fortressRequestFor(req, method, apiPath, body) {
  const token = getSessionToken(req);
  return fortressRequest(method, apiPath, body, token);
}

async function findAppFiles(dir, collected = []) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name.startsWith(".")) {
      continue;
    }
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      await findAppFiles(fullPath, collected);
      continue;
    }
    if (entry.isFile() && entry.name === "app.json") {
      collected.push(fullPath);
    }
  }
  return collected;
}

async function loadModules() {
  const appsRoot = path.join(__dirname, "apps");
  const files = await findAppFiles(appsRoot);
  const modules = [];
  for (const file of files) {
    const raw = await fs.readFile(file, "utf8");
    try {
      const parsed = JSON.parse(raw);
      if (parsed && parsed.id && parsed.title) {
        modules.push(parsed);
      }
    } catch (err) {
      console.warn(`Skipping invalid module ${file}: ${err.message}`);
    }
  }
  return modules;
}

function buildAppGraph(modules, containers) {
  const rootModule = modules.find((module) => module.root);
  const rootId = rootModule ? rootModule.id : "home";
  const nodes = [];
  if (rootModule) {
    nodes.push({
      ...rootModule,
      parent: null,
      type: "root",
    });
  } else {
    nodes.push({
      id: rootId,
      title: "Control Deck",
      description: "Lizard control deck for fortress operations.",
      icon: "compass",
      parent: null,
      type: "root",
      order: 0,
    });
  }

  const containerTemplate = modules.find((module) => module.template === "container");
  const containerModules = modules
    .filter((module) => module.scope === "container" && module.template !== "container")
    .sort((a, b) => (a.order || 0) - (b.order || 0));

  for (const module of modules) {
    if (module.root || module.template || module.scope === "container") {
      continue;
    }
    nodes.push({
      ...module,
      type: module.type || "app",
      parent: module.parent || rootId,
    });
  }

  if (containerTemplate) {
    for (const container of containers) {
      const containerId = `container:${container.name}`;
      nodes.push({
        id: containerId,
        title: container.name,
        description: containerTemplate.description || "Container handle",
        icon: containerTemplate.icon || "crate",
        parent: containerTemplate.parent || "containers",
        type: "container",
        actions: containerTemplate.actions || [],
        order: containerTemplate.order || 10,
        context: {
          container: container.name,
        },
        meta: container,
      });

      for (const module of containerModules) {
        const moduleStack = module.stack ? String(module.stack).toLowerCase() : null;
        if (moduleStack && moduleStack !== container.stack) {
          continue;
        }
        const containerServices = Array.isArray(container.services) ? container.services : [];
        const serviceInstalled = module.service ? containerServices.includes(module.service) : null;
        const resolvedBadge = module.service && !serviceInstalled ? module.install_badge || "Install" : module.badge;
        const resolvedParent = module.parent ? `${containerId}:${module.parent}` : containerId;
        nodes.push({
          ...module,
          id: `${containerId}:${module.id}`,
          parent: resolvedParent,
          type: module.type || "container-app",
          badge: resolvedBadge,
          context: {
            container: container.name,
          },
          meta: {
            ...container,
            service: module.service || null,
            service_installed: serviceInstalled,
          },
        });
      }
    }
  }

  return { rootId, nodes };
}

function asyncHandler(handler) {
  return async (req, res) => {
    try {
      await handler(req, res);
    } catch (err) {
      const status = err.status || 500;
      res.status(status).json({
        error: err.message || "Request failed",
        details: err.payload || null,
      });
    }
  };
}

function sanitizeAdminUser(user) {
  return {
    username: user.username,
    enabled: user.enabled !== false,
    locked_until: user.locked_until || null,
    last_login: user.last_login || null,
    created_at: user.created_at || null,
    updated_at: user.updated_at || null,
  };
}

app.get(
  "/api/admin/session",
  asyncHandler(async (req, res) => {
    const store = await loadAdminStore();
    const users = store.users || {};
    if (Object.keys(users).length === 0) {
      res.json({ active: false, bootstrap_required: true });
      return;
    }
    const session = getAdminSession(req);
    res.json({ active: Boolean(session), username: session ? session.username : null });
  })
);

app.post(
  "/api/admin/bootstrap",
  asyncHandler(async (req, res) => {
    const store = await loadAdminStore();
    const users = store.users || {};
    if (Object.keys(users).length > 0) {
      res.status(409).json({ error: "Admin already initialized." });
      return;
    }
    const username = req.body && typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = req.body && typeof req.body.password === "string" ? req.body.password : "";
    if (!username) {
      res.status(400).json({ error: "Username is required." });
      return;
    }
    const errors = passwordPolicyErrors(password);
    if (errors.length) {
      res.status(400).json({ error: `Password policy failed: ${errors.join(",")}` });
      return;
    }
    const record = {
      username,
      password: hashPassword(password),
      enabled: true,
      failed_attempts: 0,
      locked_until: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    users[username] = record;
    await saveAdminStore({ users });
    await logAdminEvent({ action: "bootstrap", username, ip: req.ip, status: "success" });
    res.json({ message: "Admin bootstrap complete", user: sanitizeAdminUser(record) });
  })
);

app.post(
  "/api/admin/login",
  asyncHandler(async (req, res) => {
    const username = req.body && typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = req.body && typeof req.body.password === "string" ? req.body.password : "";
    const store = await loadAdminStore();
    const users = store.users || {};
    const record = users[username];
    if (!record || record.enabled === false) {
      await logAdminEvent({ action: "login", username, ip: req.ip, status: "error" });
      res.status(403).json({ error: "Invalid credentials." });
      return;
    }
    if (record.locked_until && new Date(record.locked_until).getTime() > Date.now()) {
      res.status(429).json({ error: "Account locked. Try later." });
      return;
    }
    const ok = verifyPassword(password, record.password);
    if (!ok) {
      record.failed_attempts = (record.failed_attempts || 0) + 1;
      if (record.failed_attempts >= ADMIN_LOCKOUT_THRESHOLD) {
        const lockedUntil = new Date(Date.now() + ADMIN_LOCKOUT_MINUTES * 60000);
        record.locked_until = lockedUntil.toISOString();
        record.failed_attempts = 0;
      }
      record.updated_at = new Date().toISOString();
      await saveAdminStore({ users });
      await logAdminEvent({ action: "login", username, ip: req.ip, status: "error" });
      res.status(403).json({ error: "Invalid credentials." });
      return;
    }
    record.failed_attempts = 0;
    record.locked_until = null;
    record.last_login = new Date().toISOString();
    record.updated_at = record.last_login;
    await saveAdminStore({ users });
    const sessionId = createAdminSession(username);
    setAdminSessionCookie(res, sessionId);
    await logAdminEvent({ action: "login", username, ip: req.ip, status: "success" });
    res.json({ message: "Admin session established.", username });
  })
);

app.post(
  "/api/admin/logout",
  asyncHandler(async (req, res) => {
    clearAdminSession(req);
    clearAdminSessionCookie(res);
    res.json({ message: "Admin session cleared." });
  })
);

app.get(
  "/api/admin/users",
  asyncHandler(async (req, res) => {
    const authorized = await ensureAdminAuthorized(req, res);
    if (!authorized) {
      return;
    }
    const store = await loadAdminStore();
    const users = Object.values(store.users || {}).map(sanitizeAdminUser);
    res.json({ users });
  })
);

app.post(
  "/api/admin/users",
  asyncHandler(async (req, res) => {
    const authorized = await ensureAdminAuthorized(req, res);
    if (!authorized) {
      return;
    }
    const username = req.body && typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = req.body && typeof req.body.password === "string" ? req.body.password : "";
    if (!username) {
      res.status(400).json({ error: "Username is required." });
      return;
    }
    const errors = passwordPolicyErrors(password);
    if (errors.length) {
      res.status(400).json({ error: `Password policy failed: ${errors.join(",")}` });
      return;
    }
    const store = await loadAdminStore();
    const users = store.users || {};
    if (users[username]) {
      res.status(409).json({ error: "Admin already exists." });
      return;
    }
    const record = {
      username,
      password: hashPassword(password),
      enabled: true,
      failed_attempts: 0,
      locked_until: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    users[username] = record;
    await saveAdminStore({ users });
    await logAdminEvent({ action: "create_user", username, ip: req.ip, status: "success" });
    res.json({ message: "Admin user created", user: sanitizeAdminUser(record) });
  })
);

app.put(
  "/api/admin/users/:username",
  asyncHandler(async (req, res) => {
    const authorized = await ensureAdminAuthorized(req, res);
    if (!authorized) {
      return;
    }
    const store = await loadAdminStore();
    const users = store.users || {};
    const record = users[req.params.username];
    if (!record) {
      res.status(404).json({ error: "Admin not found." });
      return;
    }
    const password = req.body && typeof req.body.password === "string" ? req.body.password : null;
    if (password) {
      const errors = passwordPolicyErrors(password);
      if (errors.length) {
        res.status(400).json({ error: `Password policy failed: ${errors.join(",")}` });
        return;
      }
      record.password = hashPassword(password);
    }
    if (typeof req.body.enabled === "boolean") {
      record.enabled = req.body.enabled;
    }
    if (req.body.unlock) {
      record.locked_until = null;
      record.failed_attempts = 0;
    }
    record.updated_at = new Date().toISOString();
    await saveAdminStore({ users });
    await logAdminEvent({ action: "update_user", username: record.username, ip: req.ip, status: "success" });
    res.json({ message: "Admin updated", user: sanitizeAdminUser(record) });
  })
);

app.delete(
  "/api/admin/users/:username",
  asyncHandler(async (req, res) => {
    const authorized = await ensureAdminAuthorized(req, res);
    if (!authorized) {
      return;
    }
    const store = await loadAdminStore();
    const users = store.users || {};
    if (!users[req.params.username]) {
      res.status(404).json({ error: "Admin not found." });
      return;
    }
    delete users[req.params.username];
    await saveAdminStore({ users });
    await logAdminEvent({ action: "delete_user", username: req.params.username, ip: req.ip, status: "success" });
    res.json({ message: "Admin removed." });
  })
);

app.get(
  "/api/health",
  asyncHandler(async (req, res) => {
    res.json({
      status: "ok",
      ui: {
        host: HOST,
        port: PORT,
      },
      fortress: {
        api_url: API_URL,
        insecure_tls: INSECURE_TLS,
        auth_mode: resolveAuthMode(req),
      },
    });
  })
);

app.get(
  "/api/session",
  asyncHandler(async (req, res) => {
    const mode = resolveAuthMode(req);
    res.json({
      active: mode !== "none",
      mode,
      session: Boolean(getSessionToken(req)),
    });
  })
);

app.post(
  "/api/session",
  asyncHandler(async (req, res) => {
    const token = req.body && typeof req.body.token === "string" ? req.body.token.trim() : "";
    const userToken =
      req.body && typeof req.body.user_token === "string" ? req.body.user_token.trim() : "";
    const resolvedToken = userToken || token;
    if (!resolvedToken) {
      res.status(400).json({ error: "Missing delegated token." });
      return;
    }
    await fortressRequest("GET", "/status", null, resolvedToken);
    const sessionId = createSession(resolvedToken);
    setSessionCookie(res, sessionId);
    res.json({ message: "Session established." });
  })
);

app.delete(
  "/api/session",
  asyncHandler(async (req, res) => {
    clearSession(req);
    clearSessionCookie(res);
    res.json({ message: "Session cleared." });
  })
);

app.get(
  "/api/apps",
  asyncHandler(async (req, res) => {
    const modules = await loadModules();
    let containers = [];
    let fortressStatus = "ok";
    let fortressError = null;
    try {
      containers = await getContainers(getSessionToken(req));
    } catch (err) {
      fortressStatus = "error";
      fortressError = err.message;
    }
    const { rootId, nodes } = buildAppGraph(modules, containers);
    res.json({
      rootId,
      nodes,
      containers,
      fortress: {
        status: fortressStatus,
        error: fortressError,
      },
      timestamp: new Date().toISOString(),
    });
  })
);

app.get(
  "/api/containers",
  asyncHandler(async (req, res) => {
    const containers = await getContainers(getSessionToken(req));
    res.json({ containers });
  })
);

app.post(
  "/api/containers",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/container/create", req.body || {});
    res.json(payload);
  })
);

app.delete(
  "/api/containers/:name",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "DELETE", `/container/${req.params.name}`);
    res.json(payload);
  })
);

app.post(
  "/api/containers/:name/access",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/access/external/open", {
      container_name: req.params.name,
      service: req.body && req.body.service ? req.body.service : "ssh",
      host_port: req.body && req.body.host_port ? req.body.host_port : undefined,
      connect_port: req.body && req.body.connect_port ? req.body.connect_port : undefined,
      bind_address: req.body && req.body.bind_address ? req.body.bind_address : "0.0.0.0",
      connect_address: req.body && req.body.connect_address ? req.body.connect_address : undefined,
      connect_interface: req.body && req.body.connect_interface ? req.body.connect_interface : undefined,
    });
    res.json(payload);
  })
);

app.post(
  "/api/containers/:name/backup",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", `/backup/${req.params.name}`);
    res.json(payload);
  })
);

app.post(
  "/api/containers/:name/probe",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/containers/probe", {
      container_name: req.params.name,
      services: req.body && req.body.services ? req.body.services : undefined,
      update_labels: Boolean(req.body && req.body.update_labels),
    });
    res.json(payload);
  })
);

app.post(
  "/api/packages/install",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/packages/install", req.body || {});
    res.json(payload);
  })
);

app.get(
  "/api/recipes",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", "/recipes");
    res.json(payload);
  })
);

app.get(
  "/api/recipes/:name",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/recipes/${req.params.name}`);
    res.json(payload);
  })
);

app.post(
  "/api/recipes",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/recipes", req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/recipes/apply",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/recipes/apply", req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/routing",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/routing/add", req.body || {});
    res.json(payload);
  })
);

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, HOST, () => {
  console.log(`Lizard UI listening on http://${HOST}:${PORT}`);
});
