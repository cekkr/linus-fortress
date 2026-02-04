import crypto from "crypto";
import express from "express";
import path from "path";
import os from "os";
import { fileURLToPath } from "url";
import fs from "fs";
import fsPromises from "fs/promises";

let fetchFn;
let dispatcher;

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadEnvFileSync(filePath, force = false) {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    for (const line of raw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) {
        continue;
      }
      const idx = trimmed.indexOf("=");
      if (idx <= 0) {
        continue;
      }
      const key = trimmed.slice(0, idx).trim();
      let value = trimmed.slice(idx + 1).trim();
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      }
      value = value.replace(/\\n/g, "\n");
      if (force || process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch (err) {
    if (err && err.code !== "ENOENT") {
      console.warn(`Failed to load env file ${filePath}:`, err.message);
    }
  }
}

const envPath = process.env.FORTRESS_UI_ENV_FILE || path.join(__dirname, ".env.local");
loadEnvFileSync(envPath, false);
if (process.env.FORTRESS_UI_ENV_FILE === undefined) {
  const altEnv = path.join(process.cwd(), ".env.local");
  if (altEnv !== envPath) {
    loadEnvFileSync(altEnv, false);
  }
}

const HOST = process.env.FORTRESS_UI_HOST || "127.0.0.1";
const PORT = Number.parseInt(process.env.FORTRESS_UI_PORT || "8090", 10);
if (HOST === "127.0.0.1") {
  console.warn(
    "FORTRESS_UI_HOST resolved to 127.0.0.1. If you expected a different host, ensure .env.local is loaded or unset FORTRESS_UI_HOST."
  );
}
const API_URL = process.env.FORTRESS_API_URL || "https://127.0.0.1:8443";
const API_KEY = process.env.FORTRESS_UI_API_KEY || "";
const USER_TOKEN = process.env.FORTRESS_UI_USER_TOKEN || "";
const INSECURE_TLS = /^(1|true|yes)$/i.test(process.env.FORTRESS_UI_INSECURE_TLS || "");
const SESSION_TTL_SECONDS = Number.parseInt(process.env.FORTRESS_UI_SESSION_TTL || "43200", 10);
const SESSION_COOKIE = process.env.FORTRESS_UI_SESSION_COOKIE || "fortress_session";
const COOKIE_SECURE = /^(1|true|yes)$/i.test(process.env.FORTRESS_UI_COOKIE_SECURE || "");
const isRoot = typeof process.getuid === "function" && process.getuid() === 0;
const defaultAdminDir = isRoot ? "/var/lib/fortress" : path.join(os.homedir(), ".fortress-ui");
const ADMIN_DB = process.env.FORTRESS_UI_ADMIN_DB || path.join(defaultAdminDir, "ui_admins.json");
const ADMIN_AUDIT_LOG =
  process.env.FORTRESS_UI_ADMIN_AUDIT_LOG || path.join(defaultAdminDir, "ui_admin_audit.log");
const ADMIN_SESSION_TTL_SECONDS = Number.parseInt(process.env.FORTRESS_UI_ADMIN_SESSION_TTL || "43200", 10);
const ADMIN_SESSION_COOKIE = process.env.FORTRESS_UI_ADMIN_SESSION_COOKIE || "fortress_admin_session";
const ADMIN_ENABLED = !/^(0|false|no)$/i.test(process.env.FORTRESS_UI_ADMIN_ENABLED || "1");
const ADMIN_LOCKOUT_THRESHOLD = Number.parseInt(process.env.FORTRESS_UI_LOCKOUT_THRESHOLD || "5", 10);
const ADMIN_LOCKOUT_MINUTES = Number.parseInt(process.env.FORTRESS_UI_LOCKOUT_MINUTES || "15", 10);
const PASSWORD_MIN_LENGTH = Number.parseInt(process.env.FORTRESS_UI_PASSWORD_MIN_LENGTH || "12", 10);
const TOTP_ISSUER = process.env.FORTRESS_UI_TOTP_ISSUER || "Fortress UI";
const TOTP_WINDOW = Number.parseInt(process.env.FORTRESS_UI_TOTP_WINDOW || "1", 10);
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const DEBUG_ENABLED = !/^(0|false|no)$/i.test(process.env.FORTRESS_DEBUG || "1");

const sessions = new Map();
const adminSessions = new Map();

async function ensureReadableStream() {
  if (globalThis.ReadableStream) {
    return;
  }
  try {
    const webStreams = await import("stream/web");
    if (webStreams.ReadableStream) {
      globalThis.ReadableStream = webStreams.ReadableStream;
      return;
    }
  } catch (err) {
    // Fall through to polyfill.
  }
  try {
    const polyfill = await import("web-streams-polyfill/ponyfill/es2018");
    if (polyfill.ReadableStream) {
      globalThis.ReadableStream = polyfill.ReadableStream;
      return;
    }
  } catch (err) {
    // Fall through to error.
  }
  console.error("ReadableStream is not available. Upgrade Node.js (>=18 recommended) or install stream/web support.");
  process.exit(1);
}

async function initHttpClient() {
  await ensureReadableStream();
  const undici = await import("undici");
  fetchFn = undici.fetch;
  if (INSECURE_TLS) {
    const agent = new undici.Agent({
      connect: {
        rejectUnauthorized: false,
      },
    });
    dispatcher = agent;
  }
}

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

function parseTypedToken(raw) {
  if (!raw || typeof raw !== "string") {
    return { type: null, token: "" };
  }
  const value = raw.trim();
  if (!value || !value.includes(":")) {
    return { type: null, token: value };
  }
  const [prefix, ...rest] = value.split(":");
  const token = rest.join(":").trim();
  const normalized = prefix.trim().toLowerCase();
  if (!token) {
    return { type: null, token: value };
  }
  if (["api-key", "api_key", "master", "master-key", "master_key", "api"].includes(normalized)) {
    return { type: "api-key", token };
  }
  if (["user-token", "user_token", "user", "delegated", "token"].includes(normalized)) {
    return { type: "user-token", token };
  }
  return { type: null, token: value };
}

function authHeaders(tokenOverride) {
  const headers = buildHeaders();
  if (tokenOverride) {
    const parsed = parseTypedToken(tokenOverride);
    if (parsed.type === "api-key") {
      headers["X-API-Key"] = parsed.token;
    } else {
      headers["X-User-Token"] = parsed.token || tokenOverride;
    }
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

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function base32Decode(text) {
  if (!text) {
    return Buffer.alloc(0);
  }
  const cleaned = text.toUpperCase().replace(/=+$/g, "").replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index === -1) {
      continue;
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function totpForCounter(secret, counter) {
  const key = base32Decode(secret);
  const buffer = Buffer.alloc(8);
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  buffer.writeUInt32BE(high, 0);
  buffer.writeUInt32BE(low, 4);
  const hmac = crypto.createHmac("sha1", key).update(buffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 10 ** TOTP_DIGITS;
  return code.toString().padStart(TOTP_DIGITS, "0");
}

function verifyTotp(code, secret, lastStep) {
  if (!secret) {
    return { ok: false, error: "TOTP not initialized." };
  }
  const trimmed = (code || "").replace(/\s+/g, "");
  if (!trimmed) {
    return { ok: false, error: "TOTP required." };
  }
  const window = Number.isFinite(TOTP_WINDOW) ? TOTP_WINDOW : 1;
  const now = Date.now();
  const counter = Math.floor(now / 1000 / TOTP_STEP_SECONDS);
  for (let offset = -window; offset <= window; offset += 1) {
    const step = counter + offset;
    if (step < 0) {
      continue;
    }
    const candidate = totpForCounter(secret, step);
    if (candidate === trimmed) {
      if (Number.isFinite(lastStep) && step <= lastStep) {
        return { ok: false, error: "TOTP code already used." };
      }
      return { ok: true, step };
    }
  }
  return { ok: false, error: "Invalid TOTP code." };
}

function buildOtpAuthUrl(username, secret) {
  const label = encodeURIComponent(`${TOTP_ISSUER}:${username}`);
  const issuer = encodeURIComponent(TOTP_ISSUER);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`;
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
  await fsPromises.mkdir(dir, { recursive: true });
}

async function loadAdminStore() {
  try {
    const raw = await fsPromises.readFile(ADMIN_DB, "utf8");
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === "object") {
      return parsed;
    }
  } catch (err) {
    if (err.code === "ENOENT") {
      try {
        await saveAdminStore({ users: {} });
        return { users: {} };
      } catch (writeErr) {
        return { users: {}, _error: `Unable to initialize admin store at ${ADMIN_DB}: ${writeErr.message}` };
      }
    }
    console.warn("Failed to read admin DB:", err.message);
    return { users: {}, _error: `Unable to read admin store at ${ADMIN_DB}: ${err.message}` };
  }
  return { users: {} };
}

async function saveAdminStore(store) {
  await ensureAdminDir();
  await fsPromises.writeFile(ADMIN_DB, JSON.stringify(store, null, 2));
}

async function logAdminEvent(event) {
  const entry = { ...event, timestamp: new Date().toISOString() };
  const dir = path.dirname(ADMIN_AUDIT_LOG);
  await fsPromises.mkdir(dir, { recursive: true });
  await fsPromises.appendFile(ADMIN_AUDIT_LOG, `${JSON.stringify(entry)}\n`);
}

function buildAdminAuditContext(req) {
  return {
    ip: req.ip,
    user_agent: req.headers["user-agent"] || null,
  };
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
  if (store._error) {
    res.status(500).json({ error: store._error, admin_db: ADMIN_DB });
    return false;
  }
  const users = store.users || {};
  if (Object.keys(users).length === 0) {
    const tokenSession = Boolean(getSessionToken(req));
    if (req.path === "/session" || tokenSession) {
      return true;
    }
    res.status(403).json({
      error: `UI admin bootstrap required. Create the first admin for this UI server (store: ${ADMIN_DB}).`,
      admin_db: ADMIN_DB,
    });
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
  if (!fetchFn) {
    throw new Error("HTTP client not initialized");
  }
  let response;
  try {
    response = await fetchFn(url, options);
  } catch (err) {
    const hint =
      (err && err.message && err.message.toLowerCase().includes("certificate")) ||
      (err && err.code && String(err.code).toUpperCase().includes("CERT"))
        ? " Check FORTRESS_UI_INSECURE_TLS=1 if the API uses self-signed TLS."
        : "";
    const error = new Error(`Fortress API unreachable: ${err.message || err}.${hint}`);
    error.status = 502;
    error.cause = err;
    throw error;
  }
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
  const entries = await fsPromises.readdir(dir, { withFileTypes: true });
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
    const raw = await fsPromises.readFile(file, "utf8");
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
      const payload = {
        error: err.message || "Request failed",
        details: err.payload || null,
      };
      if (DEBUG_ENABLED) {
        const cause = err.cause;
        let causeInfo = null;
        if (cause) {
          if (typeof cause === "object") {
            causeInfo = {
              name: cause.name,
              message: cause.message,
              stack: cause.stack,
              code: cause.code,
            };
          } else {
            causeInfo = cause;
          }
        }
        payload.debug = {
          name: err.name,
          message: err.message,
          stack: err.stack,
          code: err.code,
          cause: causeInfo,
        };
      }
      res.status(status).json(payload);
    }
  };
}

function sanitizeAdminUser(user) {
  return {
    username: user.username,
    enabled: user.enabled !== false,
    locked_until: user.locked_until || null,
    last_login: user.last_login || null,
    totp_enabled: user.totp_enabled === true,
    totp_pending: Boolean(user.totp_pending),
    created_at: user.created_at || null,
    updated_at: user.updated_at || null,
  };
}

app.get(
  "/api/admin/session",
  asyncHandler(async (req, res) => {
    const store = await loadAdminStore();
    if (store._error) {
      res.json({ active: false, bootstrap_required: false, error: store._error, admin_db: ADMIN_DB });
      return;
    }
    const users = store.users || {};
    if (Object.keys(users).length === 0) {
      const tokenSession = Boolean(getSessionToken(req));
      res.json({
        active: tokenSession,
        bootstrap_required: true,
        token_session: tokenSession,
        admin_db: ADMIN_DB,
      });
      return;
    }
    const session = getAdminSession(req);
    res.json({
      active: Boolean(session),
      username: session ? session.username : null,
      bootstrap_required: false,
      token_session: false,
      admin_db: ADMIN_DB,
    });
  })
);

app.post(
  "/api/admin/bootstrap",
  asyncHandler(async (req, res) => {
    const store = await loadAdminStore();
    if (store._error) {
      res.status(500).json({ error: store._error, admin_db: ADMIN_DB });
      return;
    }
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
      totp_enabled: false,
      totp_secret: null,
      totp_pending: null,
      totp_last_step: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    users[username] = record;
    try {
      await saveAdminStore({ users });
    } catch (err) {
      res.status(500).json({ error: `Failed to save admin store at ${ADMIN_DB}: ${err.message}` });
      return;
    }
    await logAdminEvent({ action: "bootstrap", username, status: "success", ...buildAdminAuditContext(req) });
    res.json({ message: "Admin bootstrap complete", user: sanitizeAdminUser(record) });
  })
);

app.post(
  "/api/admin/login",
  asyncHandler(async (req, res) => {
    const username = req.body && typeof req.body.username === "string" ? req.body.username.trim() : "";
    const password = req.body && typeof req.body.password === "string" ? req.body.password : "";
    const totp = req.body && typeof req.body.totp === "string" ? req.body.totp.trim() : "";
    const store = await loadAdminStore();
    const users = store.users || {};
    const record = users[username];
    if (!record || record.enabled === false) {
      await logAdminEvent({ action: "login", username, status: "error", ...buildAdminAuditContext(req) });
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
      await logAdminEvent({ action: "login", username, status: "error", ...buildAdminAuditContext(req) });
      res.status(403).json({ error: "Invalid credentials." });
      return;
    }
    if (record.totp_enabled) {
      const result = verifyTotp(totp, record.totp_secret, record.totp_last_step);
      if (!result.ok) {
        record.failed_attempts = (record.failed_attempts || 0) + 1;
        if (record.failed_attempts >= ADMIN_LOCKOUT_THRESHOLD) {
          const lockedUntil = new Date(Date.now() + ADMIN_LOCKOUT_MINUTES * 60000);
          record.locked_until = lockedUntil.toISOString();
          record.failed_attempts = 0;
        }
        record.updated_at = new Date().toISOString();
        await saveAdminStore({ users });
        await logAdminEvent({
          action: "login",
          username,
          status: "error",
          error: result.error,
          ...buildAdminAuditContext(req),
        });
        res.status(403).json({ error: result.error });
        return;
      }
      record.totp_last_step = result.step;
    }
    record.failed_attempts = 0;
    record.locked_until = null;
    record.last_login = new Date().toISOString();
    record.updated_at = record.last_login;
    await saveAdminStore({ users });
    const sessionId = createAdminSession(username);
    setAdminSessionCookie(res, sessionId);
    await logAdminEvent({
      action: "login",
      username,
      status: "success",
      mfa: record.totp_enabled === true,
      ...buildAdminAuditContext(req),
    });
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

app.post(
  "/api/admin/totp/enroll",
  asyncHandler(async (req, res) => {
    const authorized = await ensureAdminAuthorized(req, res);
    if (!authorized) {
      return;
    }
    const session = getAdminSession(req);
    if (!session) {
      res.status(401).json({ error: "Admin session required." });
      return;
    }
    const requested = req.body && typeof req.body.username === "string" ? req.body.username.trim() : "";
    const username = requested || session.username;
    if (username !== session.username) {
      res.status(403).json({ error: "TOTP enrollment is limited to your own account." });
      return;
    }
    const store = await loadAdminStore();
    const users = store.users || {};
    const record = users[username];
    if (!record) {
      res.status(404).json({ error: "Admin not found." });
      return;
    }
    if (record.totp_enabled) {
      res.status(409).json({ error: "TOTP already enabled." });
      return;
    }
    const secret = generateTotpSecret();
    record.totp_pending = secret;
    record.updated_at = new Date().toISOString();
    await saveAdminStore({ users });
    await logAdminEvent({ action: "totp_enroll", username, status: "success", ...buildAdminAuditContext(req) });
    res.json({
      message: "TOTP enrollment started.",
      secret,
      otpauth_url: buildOtpAuthUrl(username, secret),
    });
  })
);

app.post(
  "/api/admin/totp/verify",
  asyncHandler(async (req, res) => {
    const authorized = await ensureAdminAuthorized(req, res);
    if (!authorized) {
      return;
    }
    const session = getAdminSession(req);
    if (!session) {
      res.status(401).json({ error: "Admin session required." });
      return;
    }
    const username = session.username;
    const code = req.body && typeof req.body.code === "string" ? req.body.code.trim() : "";
    const store = await loadAdminStore();
    const users = store.users || {};
    const record = users[username];
    if (!record) {
      res.status(404).json({ error: "Admin not found." });
      return;
    }
    if (!record.totp_pending) {
      res.status(409).json({ error: "No pending TOTP enrollment." });
      return;
    }
    const result = verifyTotp(code, record.totp_pending, record.totp_last_step);
    if (!result.ok) {
      await logAdminEvent({
        action: "totp_verify",
        username,
        status: "error",
        error: result.error,
        ...buildAdminAuditContext(req),
      });
      res.status(403).json({ error: result.error });
      return;
    }
    record.totp_secret = record.totp_pending;
    record.totp_pending = null;
    record.totp_enabled = true;
    record.totp_last_step = result.step;
    record.updated_at = new Date().toISOString();
    await saveAdminStore({ users });
    await logAdminEvent({ action: "totp_verify", username, status: "success", ...buildAdminAuditContext(req) });
    res.json({ message: "TOTP enabled.", user: sanitizeAdminUser(record) });
  })
);

app.post(
  "/api/admin/totp/disable",
  asyncHandler(async (req, res) => {
    const authorized = await ensureAdminAuthorized(req, res);
    if (!authorized) {
      return;
    }
    const session = getAdminSession(req);
    if (!session) {
      res.status(401).json({ error: "Admin session required." });
      return;
    }
    const username = session.username;
    const code = req.body && typeof req.body.code === "string" ? req.body.code.trim() : "";
    const store = await loadAdminStore();
    const users = store.users || {};
    const record = users[username];
    if (!record) {
      res.status(404).json({ error: "Admin not found." });
      return;
    }
    if (!record.totp_enabled || !record.totp_secret) {
      res.status(409).json({ error: "TOTP not enabled." });
      return;
    }
    const result = verifyTotp(code, record.totp_secret, record.totp_last_step);
    if (!result.ok) {
      await logAdminEvent({
        action: "totp_disable",
        username,
        status: "error",
        error: result.error,
        ...buildAdminAuditContext(req),
      });
      res.status(403).json({ error: result.error });
      return;
    }
    record.totp_enabled = false;
    record.totp_secret = null;
    record.totp_pending = null;
    record.totp_last_step = null;
    record.updated_at = new Date().toISOString();
    await saveAdminStore({ users });
    await logAdminEvent({ action: "totp_disable", username, status: "success", ...buildAdminAuditContext(req) });
    res.json({ message: "TOTP disabled.", user: sanitizeAdminUser(record) });
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
      totp_enabled: false,
      totp_secret: null,
      totp_pending: null,
      totp_last_step: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    users[username] = record;
    await saveAdminStore({ users });
    await logAdminEvent({ action: "create_user", username, status: "success", ...buildAdminAuditContext(req) });
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
    await logAdminEvent({
      action: "update_user",
      username: record.username,
      status: "success",
      ...buildAdminAuditContext(req),
    });
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
    await logAdminEvent({
      action: "delete_user",
      username: req.params.username,
      status: "success",
      ...buildAdminAuditContext(req),
    });
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
  "/api/containers/:name/start",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/containers/start", {
      container_name: req.params.name,
      force: Boolean(req.body && req.body.force),
    });
    res.json(payload);
  })
);

app.post(
  "/api/containers/:name/stop",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/containers/stop", {
      container_name: req.params.name,
      force: Boolean(req.body && req.body.force),
    });
    res.json(payload);
  })
);

app.post(
  "/api/containers/:name/restart",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/containers/restart", {
      container_name: req.params.name,
      force: Boolean(req.body && req.body.force),
    });
    res.json(payload);
  })
);

app.get(
  "/api/containers/:name/snapshots",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/containers/${req.params.name}/snapshots`);
    res.json(payload);
  })
);

app.post(
  "/api/containers/:name/snapshot",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/containers/snapshot", {
      container_name: req.params.name,
      snapshot_name: req.body && req.body.snapshot_name,
      stateful: Boolean(req.body && req.body.stateful),
    });
    res.json(payload);
  })
);

app.post(
  "/api/containers/:name/snapshots/:snapshot/restore",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/containers/snapshots/restore", {
      container_name: req.params.name,
      snapshot_name: req.params.snapshot,
      stateful: Boolean(req.body && req.body.stateful),
    });
    res.json(payload);
  })
);

app.delete(
  "/api/containers/:name/snapshots/:snapshot",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(
      req,
      "DELETE",
      `/containers/${req.params.name}/snapshots/${req.params.snapshot}`
    );
    res.json(payload);
  })
);

app.post(
  "/api/containers/:name/exec",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/containers/exec", {
      container_name: req.params.name,
      command: req.body && Array.isArray(req.body.command) ? req.body.command : [],
      user: req.body && req.body.user,
      workdir: req.body && req.body.workdir,
      environment: req.body && req.body.environment,
    });
    res.json(payload);
  })
);

app.get(
  "/api/containers/:name/logs",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/containers/${req.params.name}/logs`);
    res.json(payload);
  })
);

app.get(
  "/api/sites",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", "/sites");
    res.json(payload);
  })
);

app.get(
  "/api/sites/:site_id",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/sites/${req.params.site_id}`);
    res.json(payload);
  })
);

app.post(
  "/api/sites",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/sites", req.body || {});
    res.json(payload);
  })
);

app.put(
  "/api/sites/:site_id",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "PUT", `/sites/${req.params.site_id}`, req.body || {});
    res.json(payload);
  })
);

app.delete(
  "/api/sites/:site_id",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "DELETE", `/sites/${req.params.site_id}`);
    res.json(payload);
  })
);

app.post(
  "/api/sites/:site_id/deploy",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", `/sites/${req.params.site_id}/deploy`, req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/sites/:site_id/backup",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", `/sites/${req.params.site_id}/backup`, req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/sites/:site_id/rollback",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", `/sites/${req.params.site_id}/rollback`, req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/sites/:site_id/services/restart",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(
      req,
      "POST",
      `/sites/${req.params.site_id}/services/restart`,
      req.body || {}
    );
    res.json(payload);
  })
);

app.get(
  "/api/sites/:site_id/logs",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/sites/${req.params.site_id}/logs`);
    res.json(payload);
  })
);

app.get(
  "/api/sites/:site_id/health",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/sites/${req.params.site_id}/health`);
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

app.post(
  "/api/packages/remove",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/packages/remove", req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/packages/update",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/packages/update", req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/containers/expose",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/containers/expose", req.body || {});
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
  "/api/recipes/seed",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/recipes/seed", req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/recipes/plan",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/recipes/plan", req.body || {});
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

app.get(
  "/api/routing",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", "/routing");
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

app.post(
  "/api/routing/refresh",
  asyncHandler(async (req, res) => {
    const domain = (req.query && req.query.domain) || (req.body && req.body.domain);
    const apiPath = domain ? `/routing/refresh?domain=${encodeURIComponent(domain)}` : "/routing/refresh";
    const payload = await fortressRequestFor(req, "POST", apiPath);
    res.json(payload);
  })
);

app.delete(
  "/api/routing/:domain",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "DELETE", `/routing/${req.params.domain}`);
    res.json(payload);
  })
);

app.get(
  "/api/monitoring/resources",
  asyncHandler(async (req, res) => {
    const qs = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
    const apiPath = `/monitoring/resources${qs}`;
    const payload = await fortressRequestFor(req, "GET", apiPath);
    res.json(payload);
  })
);

app.get(
  "/api/firewall/status",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", "/firewall/status");
    res.json(payload);
  })
);

app.get(
  "/api/firewall/rules",
  asyncHandler(async (req, res) => {
    const qs = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";
    const payload = await fortressRequestFor(req, "GET", `/firewall/rules${qs}`);
    res.json(payload);
  })
);

app.post(
  "/api/firewall/open",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/firewall/open", req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/firewall/close",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/firewall/close", req.body || {});
    res.json(payload);
  })
);

app.get(
  "/api/vms",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", "/vms");
    res.json(payload);
  })
);

app.get(
  "/api/vms/:name",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/vms/${req.params.name}`);
    res.json(payload);
  })
);

app.post(
  "/api/vms/:name/start",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", `/vms/${req.params.name}/start`);
    res.json(payload);
  })
);

app.post(
  "/api/vms/:name/stop",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", `/vms/${req.params.name}/stop`);
    res.json(payload);
  })
);

app.get(
  "/api/vms/:name/status",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/vms/${req.params.name}/status`);
    res.json(payload);
  })
);

app.get(
  "/api/vms/:name/snapshots",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/vms/${req.params.name}/snapshots`);
    res.json(payload);
  })
);

app.post(
  "/api/vms/:name/snapshots",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", `/vms/${req.params.name}/snapshots`, req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/vms/:name/snapshots/:snapshot/restore",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(
      req,
      "POST",
      `/vms/${req.params.name}/snapshots/${req.params.snapshot}/restore`,
      req.body || {}
    );
    res.json(payload);
  })
);

app.delete(
  "/api/vms/:name/snapshots/:snapshot",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(
      req,
      "DELETE",
      `/vms/${req.params.name}/snapshots/${req.params.snapshot}`
    );
    res.json(payload);
  })
);

app.get(
  "/api/hosts",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", "/hosts");
    res.json(payload);
  })
);

app.get(
  "/api/hosts/:name",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/hosts/${req.params.name}`);
    res.json(payload);
  })
);

app.post(
  "/api/hosts",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", "/hosts", req.body || {});
    res.json(payload);
  })
);

app.put(
  "/api/hosts/:name",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "PUT", `/hosts/${req.params.name}`, req.body || {});
    res.json(payload);
  })
);

app.delete(
  "/api/hosts/:name",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "DELETE", `/hosts/${req.params.name}`);
    res.json(payload);
  })
);

app.post(
  "/api/hosts/:name/probe",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", `/hosts/${req.params.name}/probe`, req.body || {});
    res.json(payload);
  })
);

app.post(
  "/api/hosts/:name/provision",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "POST", `/hosts/${req.params.name}/provision`, req.body || {});
    res.json(payload);
  })
);

app.get(
  "/api/hosts/:name/states",
  asyncHandler(async (req, res) => {
    const payload = await fortressRequestFor(req, "GET", `/hosts/${req.params.name}/states`);
    res.json(payload);
  })
);

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

async function start() {
  await initHttpClient();
  app.listen(PORT, HOST, () => {
    console.log(`Lizard UI listening on http://${HOST}:${PORT}`);
  });
}

start().catch((err) => {
  console.error("Failed to start Lizard UI:", err);
  process.exit(1);
});
