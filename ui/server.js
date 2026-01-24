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

const sessions = new Map();

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
