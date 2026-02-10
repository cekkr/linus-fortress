import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VISUAL_BASELINE_FILE = path.join(__dirname, "fixtures", "app_home_visual_hashes.json");
const UPDATE_VISUAL_BASELINES = process.env.UPDATE_VISUAL_BASELINES === "1";

const TOP_LEVEL_APPS = [
  { id: "containers", title: "Containers Home" },
  { id: "settings", title: "Settings Home" },
  { id: "monitoring", title: "Monitoring Home" },
  { id: "routing", title: "Routing Home" },
  { id: "recipes", title: "Recipes Home" },
  { id: "firewall", title: "Firewall Home" },
  { id: "packages", title: "Host Packages Home" },
  { id: "hosts", title: "Hosts Home" },
  { id: "vms", title: "VM Labs Home" },
  { id: "sites", title: "Sites Home" },
];

function getFreePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1");
    server.on("listening", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
    server.on("error", reject);
  });
}

function waitForReady(proc) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("UI server did not start")), 10000);
    proc.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      if (text.includes("Lizard UI listening")) {
        clearTimeout(timeout);
        resolve();
      }
    });
    proc.on("error", reject);
  });
}

function jsonResponse(res, payload, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

function makeStatusPayload() {
  return {
    status: "ok",
    containers: [],
  };
}

function makeStubApi(port) {
  const routes = [
    {
      domain: "app.example.com",
      enabled: true,
      container_name: "lamp-alpha",
      container_port: 80,
      listen_address: "0.0.0.0",
      listen_port: 80,
      tls: { mode: "letsencrypt", listen_port: 443 },
    },
    {
      domain: "*.preview.example.com",
      enabled: false,
      container_name: "worker-beta",
      container_port: 8080,
      listen_address: "0.0.0.0",
      listen_port: 8081,
      tls: { mode: "manual", listen_port: 4443 },
    },
  ];

  const recipes = [
    {
      name: "lamp-stack",
      description: "Install LAMP stack",
      dependencies_count: 4,
      packages_count: 8,
      commands_count: 5,
      parameter_keys: ["php_version", "db_name"],
    },
    {
      name: "baseline-nginx",
      description: "Install nginx baseline",
      dependencies_count: 0,
      packages_count: 2,
      commands_count: 2,
      parameter_keys: [],
    },
  ];

  const monitoring = {
    host: {
      cpu_percent: 37,
      memory_percent: 58,
      disk_percent: 46,
    },
    containers: {
      "lamp-alpha": {
        cpu_percent: 23,
        memory_percent: 45,
        disk_percent: 41,
        process_count: 61,
      },
      "worker-beta": {
        cpu_percent: 5,
        memory_percent: 20,
        disk_percent: 33,
        process_count: 12,
      },
    },
    alerts: {
      host: [],
      containers: {
        "lamp-alpha": [],
        "worker-beta": ["cpu spike"],
      },
    },
    history_samples: [
      { host: { cpu_percent: 32 } },
      { host: { cpu_percent: 35 } },
      { host: { cpu_percent: 37 } },
    ],
  };

  const firewallRules = [
    { action: "allow", port: "22", protocol: "tcp", source: "10.0.0.0/8", interface: "eth0" },
    { action: "deny", port: "23", protocol: "tcp", source: "any", interface: "eth0" },
  ];

  const hosts = [
    { name: "edge-01", ssh_host: "192.0.2.11", ssh_port: 22, installed: true, os_type: "ubuntu" },
    { name: "edge-02", ssh_host: "192.0.2.12", ssh_port: 22, installed: false, os_type: "almalinux" },
  ];

  const vms = [
    { name: "lab-01", status: "running", profile: "ubuntu", memory_mb: 1024, disk_gb: 15, snapshots: ["boot"] },
    { name: "lab-02", status: "stopped", profile: "fedora", memory_mb: 2048, disk_gb: 20, snapshots: [] },
  ];

  const sites = [
    { id: "main-site", primary_domain: "app.example.com", container_name: "lamp-alpha", status: "active" },
    { id: "preview-site", primary_domain: "preview.example.com", container_name: "worker-beta", status: "inactive" },
  ];

  const siteDetails = {
    "main-site": {
      id: "main-site",
      primary_domain: "app.example.com",
      domains: ["www.app.example.com"],
      container_name: "lamp-alpha",
      status: "active",
      runtime: { php_version: "8.2" },
      routing: { listen_address: "0.0.0.0", listen_port: 80, container_interface: "eth0", container_port: 80 },
      tls: { mode: "letsencrypt", cert_name: "app.example.com" },
      database: { engine: "mariadb", name: "app", username: "app_user" },
    },
    "preview-site": {
      id: "preview-site",
      primary_domain: "preview.example.com",
      domains: [],
      container_name: "worker-beta",
      status: "inactive",
      runtime: { php_version: "8.1" },
      routing: { listen_address: "0.0.0.0", listen_port: 8081, container_interface: "eth0", container_port: 8080 },
      tls: { mode: "manual", cert_name: "preview.example.com" },
      database: {},
    },
  };

  const siteBackups = {
    "main-site": [
      { backup_id: "bkp-main-1", created_at: "2026-02-10T01:00:00Z", include_database: true },
      { backup_id: "bkp-main-2", created_at: "2026-02-10T02:00:00Z", include_database: false },
    ],
    "preview-site": [{ backup_id: "bkp-prev-1", created_at: "2026-02-10T03:00:00Z", include_database: true }],
  };

  const server = createServer((req, res) => {
    const url = new URL(req.url || "/", `http://127.0.0.1:${port}`);
    const pathname = url.pathname;
    const cleanPath = pathname.length > 1 && pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;

    if (cleanPath === "/status") {
      jsonResponse(res, makeStatusPayload());
      return;
    }
    if (cleanPath === "/containers/images/popular") {
      jsonResponse(res, {
        images: [
          {
            name: "ubuntu:lts",
            label: "Ubuntu LTS",
            resolved_name: "ubuntu:lts",
            available: true,
            remote: "images",
            source: "lxc",
          },
          {
            name: "debian:12",
            label: "Debian 12",
            resolved_name: "debian:12",
            available: true,
            remote: "images",
            source: "lxc",
          },
        ],
        remotes: ["images"],
        latest: { ubuntu_lts: "ubuntu:lts" },
        refreshed_at: "2026-02-10T04:00:00Z",
      });
      return;
    }
    if (cleanPath === "/routing") {
      jsonResponse(res, { routes });
      return;
    }
    if (cleanPath === "/recipes") {
      jsonResponse(res, { recipes });
      return;
    }
    if (cleanPath === "/monitoring/resources") {
      jsonResponse(res, monitoring);
      return;
    }
    if (cleanPath === "/firewall/status") {
      jsonResponse(res, { backend: "ufw", active: true });
      return;
    }
    if (cleanPath === "/firewall/rules") {
      jsonResponse(res, { rules: firewallRules });
      return;
    }
    if (cleanPath === "/firewall/rules/diff") {
      jsonResponse(res, { added: firewallRules.slice(0, 1), removed: [] });
      return;
    }
    if (cleanPath === "/hosts") {
      jsonResponse(res, { hosts });
      return;
    }
    if (cleanPath === "/vms") {
      jsonResponse(res, { vms });
      return;
    }
    if (cleanPath === "/sites") {
      jsonResponse(res, { sites });
      return;
    }
    if (cleanPath.startsWith("/sites/") && cleanPath.endsWith("/backups")) {
      const siteId = decodeURIComponent(cleanPath.split("/")[2] || "");
      jsonResponse(res, { backups: siteBackups[siteId] || [] });
      return;
    }
    if (cleanPath.startsWith("/sites/")) {
      const siteId = decodeURIComponent(cleanPath.split("/")[2] || "");
      jsonResponse(res, { site: siteDetails[siteId] || null }, siteDetails[siteId] ? 200 : 404);
      return;
    }

    jsonResponse(res, { error: "not found" }, 404);
  });

  return new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", () => resolve(server));
    server.on("error", reject);
  });
}

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

function loadBaselines() {
  if (!fs.existsSync(VISUAL_BASELINE_FILE)) {
    return {};
  }
  try {
    const raw = fs.readFileSync(VISUAL_BASELINE_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

async function openAppHome(page, appId, expectedTitle) {
  const selector = `.app-card[data-node-id="${appId}"] .card-icon-button`;
  await page.waitForFunction(
    (target) => {
      const el = document.querySelector(target);
      return Boolean(el && el.getBoundingClientRect().width > 4 && el.getBoundingClientRect().height > 4);
    },
    {},
    selector
  );
  await page.$eval(selector, (el) => {
    el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
  });
  await page.waitForSelector("#app-grid .app-home-shell", { visible: true });
  await page.waitForFunction(
    (title) => {
      const el = document.querySelector("#app-grid .app-home-title");
      return el && (el.textContent || "").trim() === title;
    },
    {},
    expectedTitle
  );
}

async function screenshotAppHomeShell(page) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    await page.waitForFunction(() => {
      const el = document.querySelector("#app-grid .app-home-shell");
      if (!el) {
        return false;
      }
      const rect = el.getBoundingClientRect();
      return rect.width > 4 && rect.height > 4;
    });
    const shell = await page.$("#app-grid .app-home-shell");
    assert.ok(shell, "app home shell missing");
    try {
      return await shell.screenshot({ type: "png" });
    } catch (err) {
      const message = err && err.message ? String(err.message) : "";
      const retryable =
        message.includes("detached") || message.includes("not visible") || message.includes("not an HTMLElement");
      if (!retryable) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 90));
    }
  }
  throw new Error("Unable to capture app home shell screenshot after retries");
}

test("visual regression for all top-level app homes and per-item actions", async (t) => {
  let puppeteer;
  try {
    puppeteer = await import("puppeteer");
  } catch (err) {
    t.skip(`puppeteer not available: ${err.message}`);
    return;
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fortress-ui-"));
  const adminDb = path.join(tmpDir, "ui_admins.json");
  const adminLog = path.join(tmpDir, "ui_admin_audit.log");
  const apiPort = await getFreePort();
  const uiPort = await getFreePort();
  const apiServer = await makeStubApi(apiPort);

  const env = {
    ...process.env,
    FORTRESS_UI_HOST: "127.0.0.1",
    FORTRESS_UI_PORT: String(uiPort),
    FORTRESS_UI_ADMIN_DB: adminDb,
    FORTRESS_UI_ADMIN_AUDIT_LOG: adminLog,
    FORTRESS_API_URL: `http://127.0.0.1:${apiPort}`,
  };

  const proc = spawn("node", ["server.js"], {
    cwd: path.resolve(path.join(__dirname, "..")),
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  let browser;
  try {
    await waitForReady(proc);
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1600, height: 1000 });
    await page.goto(`http://127.0.0.1:${uiPort}`, { waitUntil: "networkidle0" });
    await page.addStyleTag({
      content: "*,*::before,*::after{animation:none !important;transition:none !important;}",
    });

    await page.waitForSelector("#auth-overlay", { visible: true });
    await page.type("#auth-token", "user-token:visual-regression");
    await page.click("#auth-form button[type=\"submit\"]");
    await page.waitForSelector("#auth-overlay", { hidden: true });
    await page.waitForSelector(".app-card[data-node-id=\"containers\"] .card-icon-button", { visible: true });

    const observedHashes = {};
    for (const app of TOP_LEVEL_APPS) {
      await openAppHome(page, app.id, app.title);

      if (app.id === "routing") {
        await page.waitForFunction(
          () => document.querySelectorAll("#app-grid .app-home-item [data-action-id=\"route-refresh\"][data-domain]").length > 0
        );
        await page.waitForFunction(
          () => document.querySelectorAll("#app-grid .app-home-item [data-action-id=\"route-delete\"][data-domain]").length > 0
        );
      }
      if (app.id === "sites") {
        await page.waitForFunction(
          () => document.querySelectorAll("#app-grid .app-home-item [data-action-id=\"site-deploy\"][data-site]").length > 0
        );
        await page.waitForFunction(
          () => document.querySelectorAll("#app-grid .app-home-item [data-action-id=\"site-backup\"][data-site]").length > 0
        );
      }
      if (app.id === "vms") {
        await page.waitForFunction(
          () => document.querySelectorAll("#app-grid .app-home-item [data-action-id=\"vm-start\"][data-vm]").length > 0
        );
        await page.waitForFunction(
          () => document.querySelectorAll("#app-grid .app-home-item [data-action-id=\"vm-stop\"][data-vm]").length > 0
        );
        await page.waitForFunction(
          () => document.querySelectorAll("#app-grid .app-home-item [data-action-id=\"vm-snapshot\"][data-vm]").length > 0
        );
      }

      const png = await screenshotAppHomeShell(page);
      observedHashes[app.id] = sha256(png);

      await page.$eval("#breadcrumb [data-nav-node-id=\"home\"]", (el) => {
        el.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      });
      await page.waitForSelector(".app-card[data-node-id=\"containers\"] .card-icon-button", { visible: true });
    }

    if (UPDATE_VISUAL_BASELINES) {
      fs.mkdirSync(path.dirname(VISUAL_BASELINE_FILE), { recursive: true });
      fs.writeFileSync(VISUAL_BASELINE_FILE, `${JSON.stringify(observedHashes, null, 2)}\n`);
      return;
    }

    const baselines = loadBaselines();
    for (const app of TOP_LEVEL_APPS) {
      const expectedHash = baselines[app.id];
      assert.ok(expectedHash, `Missing visual baseline for ${app.id}. Run with UPDATE_VISUAL_BASELINES=1.`);
      assert.equal(
        observedHashes[app.id],
        expectedHash,
        `Visual regression detected for ${app.id} home. Run with UPDATE_VISUAL_BASELINES=1 if change is expected.`
      );
    }
  } finally {
    if (browser) {
      await browser.close();
    }
    proc.kill("SIGTERM");
    apiServer.close();
  }
});
