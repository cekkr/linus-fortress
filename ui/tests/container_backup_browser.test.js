import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import fs from "node:fs/promises";
import { createServer } from "node:http";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const uiDir = fileURLToPath(new URL("../", import.meta.url));
const token = "browser-backup-fixture";
const original = "web01_20261120_091001.tar.gz.enc";
const retired = "retired_20261118_070005.tar.gz.enc";
const queued = "web01_20261120_101500-1234567890abcdef1234567890abcdef.tar.gz.enc";
const binary = Buffer.from([0x00, 0x04, 0x80, 0xff, 0x0a, 0x62]);

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server.address().port;
}

function json(res, status, payload) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

function fixtureApi() {
  const state = { seen: [], verifyingAllowed: false, expiry: false, queued: false, restores: [], restored: [] };
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const route = url.pathname;
    state.seen.push({ route, method: req.method, query: url.search, token: req.headers["x-user-token"] });
    if (req.headers["x-user-token"] !== token) {
      return json(res, 401, { detail: "Authentication required" });
    }
    if (state.expiry) return json(res, 401, { detail: "API token expired" });
    if (route === "/status") {
      return json(res, 200, { containers: ["web01", ...state.restored].map((name) => ({ name, status: "Stopped" })) });
    }
    if (route === "/containers/images/popular") return json(res, 200, { images: [] });
    if (route === "/containers/web01/snapshots") return json(res, 200, { snapshots: [] });
    if (route === "/containers/probe") return json(res, 200, { health_checks: [], detected_services: [] });
    if (route === "/sites") {
      return json(res, 200, { sites: [{ id: "demo", primary_domain: "demo.example.com", status: "active" }] });
    }
    if (route === "/sites/demo") {
      return json(res, 200, { site: { id: "demo", primary_domain: "demo.example.com", container_name: "web01" } });
    }
    if (route === "/sites/demo/backups") return json(res, 200, { backups: [] });
    if (route === "/sites/demo/tls/status") return json(res, 200, { tls_status: { status: "disabled" } });
    if (route === "/sites/demo/services/restart" && req.method === "POST") {
      req.resume();
      return json(res, 200, { message: "Some services failed to restart", restarted: ["httpd"], failed: ["php-fpm"] });
    }
    if (route === "/backup/list") {
      const items = [
        { filename: original, container: "web01", size_bytes: binary.length },
        { filename: retired, container: "retired" },
      ];
      if (state.queued) items.push({ filename: queued, container: "web01", size_bytes: 4500 });
      const container = url.searchParams.get("container");
      return json(res, 200, { items: container ? items.filter((item) => item.container === container) : items });
    }
    if (route === "/backup/web01" && req.method === "POST") {
      state.queued = true;
      res.setHeader("X-Fortress-Request-ID", "fixture-export-receipt");
      return json(res, 200, { message: "Backup started in background" });
    }
    if (route === `/backup/download/${original}`) {
      res.writeHead(200, { "Content-Type": "application/octet-stream", "Content-Length": binary.length });
      res.write(binary.subarray(0, 3));
      return res.end(binary.subarray(3));
    }
    if (route.startsWith("/backup/restore/") && req.method === "POST") {
      const destination = url.searchParams.get("container_name");
      const dryRun = url.searchParams.get("dry_run") === "true";
      state.restores.push({ route, dryRun, destination });
      res.setHeader("X-Fortress-Request-ID", dryRun ? "fixture-verify-receipt" : "fixture-restore-receipt");
      if (dryRun) {
        return state.verifyingAllowed
          ? json(res, 200, { message: "Backup integrity verified" })
          : json(res, 403, { detail: "Permission denied for this API user" });
      }
      if (destination === "web01") return json(res, 409, { detail: { message: "Destination already exists" } });
      state.restored.push(destination);
      return json(res, 200, { message: `Container ${destination} restored successfully` });
    }
    return json(res, 404, { detail: "Not found" });
  });
  return { server, state };
}

async function startUi(t, apiPort, directory) {
  const probe = createServer();
  const port = await listen(probe);
  await new Promise((resolve) => probe.close(resolve));
  const proc = spawn(process.execPath, ["server.js"], {
    cwd: uiDir,
    env: {
      ...process.env,
      FORTRESS_UI_HOST: "127.0.0.1",
      FORTRESS_UI_PORT: String(port),
      FORTRESS_UI_ENV_FILE: path.join(directory, "absent.env"),
      FORTRESS_UI_ADMIN_ENABLED: "1",
      FORTRESS_UI_ADMIN_DB: path.join(directory, "admins.json"),
      FORTRESS_UI_ADMIN_AUDIT_LOG: path.join(directory, "admin-audit.log"),
      FORTRESS_UI_API_KEY: "",
      FORTRESS_UI_USER_TOKEN: "",
      FORTRESS_API_URL: `http://127.0.0.1:${apiPort}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => proc.kill("SIGTERM"));
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Lizard UI did not start")), 10000);
    proc.once("error", (err) => { clearTimeout(timer); reject(err); });
    proc.once("exit", (code) => { clearTimeout(timer); reject(new Error(`Lizard UI exited with ${code}`)); });
    proc.stdout.on("data", (chunk) => {
      if (chunk.toString().includes("Lizard UI listening")) {
        clearTimeout(timer);
        resolve();
      }
    });
  });
  return `http://127.0.0.1:${port}`;
}

async function openCard(page, id) {
  const button = `.app-card[data-node-id="${id}"] .card-icon-button`;
  await click(page, button);
}

function click(page, selector) {
  return page.locator(selector).setTimeout(5000).click();
}

async function waitForText(page, selector, text) {
  await page.waitForFunction(
    (selector, text) => document.querySelector(selector)?.textContent.includes(text), { timeout: 5000 }, selector, text
  );
}

async function actionFor(page, actionId, filename) {
  const button = `[data-action-id="${actionId}"][data-filename="${filename}"]`;
  await click(page, button);
}

async function waitForDownload(directory, filename) {
  const destination = path.join(directory, filename);
  for (let attempt = 0; attempt < 100; attempt++) {
    try { return await fs.readFile(destination); } catch (err) {
      if (err.code !== "ENOENT") throw err;
    }
    await delay(50);
  }
  throw new Error(`Chromium did not download ${filename}`);
}

test("live container backups UI verifies, downloads, queues, and restores through the session proxy", { timeout: 45000 }, async (t) => {
  let puppeteer;
  try { puppeteer = await import("puppeteer"); } catch {
    t.skip("Puppeteer not installed");
    return;
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "fortress-ui-backups-"));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  const { server, state } = fixtureApi();
  const apiPort = await listen(server);
  t.after(() => server.close());
  const ui = await startUi(t, apiPort, directory);
  const browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
  t.after(() => browser.close());
  const page = await browser.newPage();
  const cdp = await page.createCDPSession();
  await cdp.send("Page.setDownloadBehavior", { behavior: "allow", downloadPath: directory });
  await page.setViewport({ width: 1440, height: 950 });
  await page.setRequestInterception(true);
  page.on("request", (req) => (req.url().startsWith(ui) ? req.continue() : req.abort()).catch(() => {}));
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(ui, { waitUntil: "domcontentloaded" });
  await page.waitForSelector("#auth-token", { visible: true });
  await page.type("#auth-token", `user-token:${token}`);
  await page.click('#auth-form button[type="submit"]');
  await page.waitForSelector("#auth-overlay", { hidden: true });

  await openCard(page, "containers");
  await openCard(page, "container:web01");
  await openCard(page, "container:web01:container-backups");
  await waitForText(page, ".app-home-backups", original);
  assert.equal(await page.$eval(".app-home-backups", (el, name) => el.textContent.includes(name), retired), false);
  assert.ok(state.seen.some((request) => request.route === "/backup/list" && request.query === "?container=web01" && request.token === token));

  await actionFor(page, "container-backup-verify", original);
  await waitForText(page, "[data-backup-notice]", "Permission denied");
  assert.equal(await page.$eval("#auth-overlay", (overlay) => overlay.hidden), true);
  state.verifyingAllowed = true;
  await actionFor(page, "container-backup-verify", original);
  await waitForText(page, "[data-backup-notice]", "fixture-verify-receipt");
  await waitForText(page, ".app-home-backups .pill.running", "Verified");
  assert.deepEqual(state.restores.slice(-2), [
    { route: `/backup/restore/${original}`, dryRun: true, destination: null },
    { route: `/backup/restore/${original}`, dryRun: true, destination: null },
  ]);

  await click(page, `a[href="/api/backup/download/${original}"]`);
  assert.deepEqual(await waitForDownload(directory, original), binary);
  await click(page, '.app-home-backups [data-action-id="backup-container"]');
  await waitForText(page, "[data-backup-notice]", "fixture-export-receipt");
  assert.equal(await page.$eval(".app-home-backups", (el, name) => el.textContent.includes(name), queued), false);
  await click(page, '[data-action-id="container-backups-refresh"]');
  await waitForText(page, ".app-home-backups", queued);

  await click(page, '[data-nav-node-id="backups"]');
  await waitForText(page, ".app-home-backups", retired);
  await page.setViewport({ width: 390, height: 844 });
  await page.waitForFunction(() => document.documentElement.scrollWidth <= 392);
  await actionFor(page, "container-backup-restore", retired);
  const destination = "#wiz-restore-destination";
  await page.waitForSelector(destination, { visible: true });
  assert.equal(await page.$eval(destination, (input) => input.value), "retired");
  const next = '#wizard [data-wizard-action="next"]';
  const back = '#wizard [data-wizard-action="back"]';
  await page.locator(destination).fill("bad_name");
  await click(page, next);
  await waitForText(page, "#wizard .event-item.error", "starting with a letter");
  await page.locator(destination).fill("web01");
  await click(page, next);
  await waitForText(page, "#wizard", "Import the archive as web01?");
  assert.equal(state.restores.filter((request) => !request.dryRun).length, 0);
  await click(page, next);
  await waitForText(page, "#wizard .event-item.error", "Destination already exists");
  await click(page, back);
  await page.locator(destination).fill("retired-drill");
  await click(page, next);
  await waitForText(page, "#wizard", "Import the archive as retired-drill?");
  await click(page, next);
  await page.waitForSelector("#wizard-stage", { hidden: true });
  await waitForText(page, "[data-backup-notice]", "fixture-restore-receipt");
  assert.deepEqual(state.restored, ["retired-drill"]);
  assert.deepEqual(state.restores.filter((request) => !request.dryRun).map((request) => request.destination), ["web01", "retired-drill"]);

  await page.setViewport({ width: 1440, height: 950 });
  await click(page, '#breadcrumb [data-nav-node-id="home"]');
  await openCard(page, "sites");
  const siteServices = '[data-action-id="site-services"][data-site="demo"]';
  await click(page, siteServices);
  await page.waitForSelector("#wiz-site-services-restart", { visible: true });
  await click(page, next);
  await waitForText(page, "#wizard", "Apply service/runtime changes for demo.");
  await click(page, next);
  await waitForText(page, "#wizard .event-item.error", "Could not restart: php-fpm");
  await click(page, '#wizard [data-wizard-action="close"]');
  await click(page, '#breadcrumb [data-nav-node-id="home"]');
  await openCard(page, "backups");
  await waitForText(page, ".app-home-backups", retired);

  state.expiry = true;
  await click(page, '[data-action-id="container-backups-refresh"]');
  await page.waitForSelector("#auth-overlay", { visible: true });
  await waitForText(page, "#auth-overlay", "API token expired");
  assert.deepEqual(errors, []);
});
