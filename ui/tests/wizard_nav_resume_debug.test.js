import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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
      if (chunk.toString().includes("Lizard UI listening")) {
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

function startStubApi(port, { tokenExpiry = false, imagePresets = false } = {}) {
  const upgrades = [];
  const vmQueries = [];
  const vmSnapshotRequests = [];
  const snapshots = [];
  let failPreflight = false;
  let failFirewallStatus = false;
  let latestLts = "ubuntu:24.04";
  const presets = new Map([["ubuntu:lts", "Rolling Ubuntu"]]);
  const server = createServer(async (req, res) => {
    const url = new URL(req.url || "/", `http://127.0.0.1:${port}`);
    const { pathname } = url;
    if (pathname === "/status") {
      const credential = tokenExpiry
        ? { type: "delegated", expires_at: "2099-01-01T00:00:00Z", can_list_tokens: true }
        : undefined;
      jsonResponse(res, { status: "ok", containers: [], credential });
      return;
    }
    if (pathname === "/api-users" && tokenExpiry && url.searchParams.get("expiry_summary") === "true") {
      jsonResponse(res, { users: [
        { username: "current", expired: false, expires_at: "2099-01-01T00:00:00Z", token_hint: "act1...act2" },
        { username: "retired", expired: true, expires_at: "2020-01-01T00:00:00Z", token_hint: "old1...old2", token: "private-fixture-token" },
      ] });
      return;
    }
    if (imagePresets && req.method === "POST" && ["/containers/images/popular", "/containers/images/popular/remove"].includes(pathname)) {
      let body = "";
      for await (const chunk of req) body += chunk;
      const { name, label } = JSON.parse(body);
      if (pathname.endsWith("/remove")) presets.delete(name);
      else presets.set(name, label);
      jsonResponse(res, { message: pathname.endsWith("/remove") ? "Image preset removed" : "Image preset saved" });
      return;
    }
    if (pathname === "/containers/images/popular") {
      jsonResponse(res, {
        images: [{ name: "ubuntu:lts", label: "Ubuntu LTS", resolved_name: "ubuntu:lts", available: true, remote: "ubuntu" }],
        remotes: ["ubuntu"],
        latest: { ubuntu_lts: imagePresets ? latestLts : "ubuntu:lts" },
        presets: imagePresets ? [...presets].map(([name, label]) => ({
          name, label, resolved_name: name === "ubuntu:lts" ? latestLts : name,
          remote: name.split(":")[0], available: name.startsWith("ubuntu:"),
        })) : undefined,
        can_manage_presets: imagePresets,
        refreshed_at: "2026-02-11T00:00:00Z",
      });
      return;
    }
    if (pathname === "/monitoring/resources") {
      // Deliberate failure so the Debug panel captures an error payload with a secret-looking key.
      jsonResponse(res, { detail: "monitoring backend unavailable", password: "should-not-leak" }, 503);
      return;
    }
    if (pathname === "/system/upgrade" && req.method === "POST") {
      let body = "";
      for await (const chunk of req) {
        body += chunk;
      }
      upgrades.push(JSON.parse(body));
      if (failPreflight) {
        jsonResponse(res, { detail: "Upgrade preflight unavailable" }, 503);
      } else {
        jsonResponse(res, { migrations: [] });
      }
      return;
    }
    if (pathname === "/migrations/status") {
      jsonResponse(res, { stores: [] });
      return;
    }
    if (pathname === "/backup/list") {
      jsonResponse(res, { backups: ["web-01-backup.enc"] });
      return;
    }
    if (pathname === "/firewall/status") {
      res.setHeader("X-Fortress-Request-ID", "fixture-firewall-status");
      if (failFirewallStatus) {
        jsonResponse(res, { detail: "Firewall status unavailable" }, 503);
        return;
      }
      jsonResponse(res, {
        backend: "firewalld", active: true, connlimit: {
          status: "configured", preferred_backend: "iptables",
          backends: [
            { name: "iptables", rules: [
              { kind: "allow", port: 443, source: "203.0.113.0/24", status: "missing" },
              { kind: "connlimit", port: 443, limit: 25, status: "unknown" },
            ] },
            { name: "nftables", rules: [
              { kind: "allow", port: 443, source: "203.0.113.0/24", status: "present", handles: [7, 12] },
              { kind: "connlimit", port: 443, limit: 25, status: "missing", handles: [] },
            ] },
          ],
        },
      });
      return;
    }
    if (pathname === "/firewall/rules" || pathname === "/firewall/rules/diff") {
      jsonResponse(res, { rules: [], added: [], removed: [] });
      return;
    }
    if (pathname === "/vms") {
      const url = new URL(req.url, `http://127.0.0.1:${port}`);
      vmQueries.push(url.searchParams.get("include_validation"));
      jsonResponse(res, { vms: [
        { name: "lab-ready", state: "stopped", provider: "qemu", validation: { valid: true } },
        { name: "lab-old", state: "stopped", provider: "qemu", validation: { valid: false, message: "disk_path must be inside FORTRESS_VM_ROOT" } },
        { name: "lab-live", state: "running", provider: "qemu", live_snapshots: true, snapshots },
      ] });
      return;
    }
    if (pathname.startsWith("/vms/lab-live/snapshots") && ["POST", "DELETE"].includes(req.method)) {
      const url = new URL(req.url, `http://127.0.0.1:${port}`);
      let body = "";
      for await (const chunk of req) {
        body += chunk;
      }
      const payload = body ? JSON.parse(body) : null;
      vmSnapshotRequests.push({ method: req.method, path: pathname, live: url.searchParams.get("live"), payload });
      if (pathname === "/vms/lab-live/snapshots" && req.method === "POST") {
        if (!payload?.name || payload.live !== true) {
          jsonResponse(res, { detail: "Expected a named live snapshot" }, 400);
          return;
        }
        snapshots.push({ name: payload.name, live: true });
      } else if (req.method === "DELETE") {
        snapshots.length = 0;
      }
      jsonResponse(res, { message: "Snapshot request complete" });
      return;
    }
    jsonResponse(res, { error: "not found" }, 404);
  });
  return new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", () => resolve({
      server,
      upgrades,
      vmQueries,
      vmSnapshotRequests,
      setPreflightFailure: (enabled) => { failPreflight = enabled; },
      setFirewallStatusFailure: () => { failFirewallStatus = true; },
      setLatestLts: (alias) => { latestLts = alias; },
    }));
    server.on("error", reject);
  });
}

async function launchHarness(options) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fortress-ui-"));
  const apiPort = await getFreePort();
  const uiPort = await getFreePort();
  const api = await startStubApi(apiPort, options);
  const proc = spawn("node", ["server.js"], {
    cwd: path.resolve(path.join(__dirname, "..")),
    env: {
      ...process.env,
      FORTRESS_UI_HOST: "127.0.0.1",
      FORTRESS_UI_PORT: String(uiPort),
      FORTRESS_UI_ADMIN_DB: path.join(tmpDir, "ui_admins.json"),
      FORTRESS_UI_ADMIN_AUDIT_LOG: path.join(tmpDir, "ui_admin_audit.log"),
      FORTRESS_API_URL: `http://127.0.0.1:${apiPort}`,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await waitForReady(proc);
  return { uiPort, proc, api };
}

async function login(page) {
  await page.waitForSelector("#auth-overlay", { visible: true });
  await page.type("#auth-token", "user-token:test-session");
  await page.click('#auth-form button[type="submit"]');
  await page.waitForSelector("#auth-overlay", { hidden: true });
  await page.waitForSelector('.app-card[data-node-id="containers"] .card-summary', { visible: true });
}

async function wizardStep(page) {
  return page.$eval("#wizard .wizard-step.active .wizard-step-index", (el) => Number(el.textContent.trim()));
}

async function loadPuppeteer(t) {
  try {
    return await import("puppeteer");
  } catch (err) {
    t.skip(`puppeteer not available: ${err.message}`);
    return null;
  }
}

test("Settings shows the delegated session expiry and flags expired tokens", async (t) => {
  const puppeteer = await loadPuppeteer(t);
  if (!puppeteer) return;
  const harness = await launchHarness({ tokenExpiry: true });
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 390, height: 844 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await login(page);
    await page.locator('.app-card[data-node-id="settings"] .card-icon-button').click();
    const credentials = '[aria-label="API credentials"]';
    await page.waitForSelector(`${credentials} time[datetime="2099-01-01T00:00:00.000Z"]`);
    await page.locator('[data-action-id="settings-token-expiry"]').click();
    await page.waitForSelector(`${credentials} .pill.danger`);
    const rows = await page.$$eval(`${credentials} .event-item`, (items) => items.map((item) => item.textContent));
    assert.match(rows[0], /retired[\s\S]*Expired/);
    assert.match(rows[1], /current[\s\S]*Active/);
    assert.doesNotMatch(rows.join(""), /private-fixture-token/);
  } finally {
    await browser?.close();
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("Settings saves, edits, and removes image presets and refreshes remote availability", async (t) => {
  const puppeteer = await loadPuppeteer(t);
  if (!puppeteer) return;
  const harness = await launchHarness({ imagePresets: true });
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 390, height: 844 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await login(page);
    await page.locator('.app-card[data-node-id="settings"] .card-icon-button').click();
    const section = '[aria-label="Image presets"]';
    const save = '#image-preset-form button[type="submit"]';
    const alias = "images:almalinux/10/cloud";
    const edit = `[data-action-id="settings-image-edit"][data-image-name="${alias}"]`;
    const remove = `[data-action-id="settings-image-remove"][data-image-name="${alias}"]`;
    await page.locator("#settings-image-alias").fill(alias);
    await page.locator("#settings-image-label").fill("AlmaLinux lab");
    await page.locator(save).click();
    await page.waitForSelector(edit);
    assert.match(await page.$eval(section, (panel) => panel.textContent), /AlmaLinux lab[\s\S]*Unavailable/);
    await page.locator(edit).click();
    assert.equal(await page.$eval("#settings-image-alias", (input) => input.value), alias);
    await page.locator("#settings-image-label").fill("AlmaLinux candidate");
    await page.locator(save).click();
    await page.waitForFunction((selector) => document.querySelector(selector)?.textContent.includes("AlmaLinux candidate"), {}, section);
    harness.api.setLatestLts("ubuntu:26.04");
    await page.locator(`${section} [data-action-id="image-catalog-refresh"]`).click();
    await page.waitForFunction((selector) => document.querySelector(selector)?.textContent.includes("Latest Ubuntu LTS ubuntu:26.04"), {}, section);
    page.once("dialog", (dialog) => dialog.dismiss());
    await page.locator(remove).click();
    await page.waitForSelector(remove, { visible: true });
    page.once("dialog", (dialog) => dialog.accept());
    await page.locator(remove).click();
    await page.waitForSelector(remove, { hidden: true });
  } finally {
    await browser?.close();
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("Firewall displays live connection-limit diagnostics from the session proxy", async (t) => {
  const puppeteer = await loadPuppeteer(t);
  if (!puppeteer) return;
  const harness = await launchHarness();
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 930 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "domcontentloaded" });
    await login(page);
    const response = page.waitForResponse((res) => new URL(res.url()).pathname === "/api/firewall/status");
    await page.locator('.app-card[data-node-id="firewall"] .card-icon-button').click();
    assert.equal((await response).headers()["x-fortress-request-id"], "fixture-firewall-status");

    const panel = '#preview [aria-label="Connection limit diagnostics"]';
    await page.waitForSelector(panel, { visible: true });
    const diagnostics = await page.$eval(panel, (el) => el.innerText.replace(/\s+/g, " "));
    assert.match(diagnostics, /Preferred backend iptables/i);
    assert.match(diagnostics, /Allow 203\.0\.113\.0\/24 on 443\/tcp Present Handles 7, 12/i);
    assert.match(diagnostics, /443\/tcp · limit 25 Missing/i);
    assert.match(diagnostics, /443\/tcp · limit 25 Could not inspect/i);
    await page.setViewport({ width: 390, height: 844 });
    assert.equal(await page.$eval(panel, (el) => el.getBoundingClientRect().right <= innerWidth), true);
    harness.api.setFirewallStatusFailure();
    const failure = page.waitForResponse((res) => new URL(res.url()).pathname === "/api/firewall/status");
    await page.locator('#app-grid [data-action-id="firewall-refresh"]').click();
    assert.equal((await failure).status(), 503);
    await page.waitForFunction(() => !document.querySelector("#preview")?.textContent.includes("Loading firewall"));
    assert.equal(await page.$(panel), null);
  } finally {
    if (browser) await browser.close();
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("VM Labs creates, restores, and deletes a live snapshot through the proxy", async (t) => {
  const puppeteer = await loadPuppeteer(t);
  if (!puppeteer) return;
  const harness = await launchHarness();
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1500, height: 980 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await login(page);
    await page.locator('.app-card[data-node-id="vms"] .card-icon-button').click();

    const vmAction = (id, name = "lab-live") => `#preview [data-action-id="${id}"][data-vm="${name}"]`;
    const next = '#wizard [data-wizard-action="next"]';
    await page.locator(vmAction("vm-snapshot", "lab-ready")).click();
    await page.waitForSelector("#wiz-vm-snap-name", { visible: true });
    assert.equal(await page.$("#wiz-vm-snap-live"), null);
    await page.locator('#wizard [data-wizard-action="close"]').click();

    await page.locator(vmAction("vm-snapshot")).click();
    await page.locator("#wiz-vm-snap-name").fill("checkpoint");
    assert.equal(await page.$eval("#wiz-vm-snap-live", (input) => input.checked), false);
    await page.locator("#wiz-vm-snap-live").click();
    await page.locator(next).click();
    assert.match(await page.$eval("#wizard", (el) => el.textContent), /Live snapshot including VM memory/);
    assert.deepEqual(harness.api.vmSnapshotRequests, []);
    await page.locator(next).click();

    const restore = vmAction("vm-restore");
    await page.waitForSelector(restore, { visible: true });
    assert.match(await page.$eval("#preview", (el) => el.textContent), /checkpoint \(live\)/);
    const endpoint = "/vms/lab-live/snapshots";
    assert.deepEqual(harness.api.vmSnapshotRequests, [
      { method: "POST", path: endpoint, live: null, payload: { name: "checkpoint", live: true } },
    ]);

    const dismissRestore = new Promise((resolve) => page.once("dialog", async (dialog) => {
      await dialog.dismiss();
      resolve(dialog.message());
    }));
    await page.locator(restore).click();
    assert.match(await dismissRestore, /rewinds the disk and VM memory/);
    assert.equal(harness.api.vmSnapshotRequests.length, 1);

    page.once("dialog", (dialog) => dialog.accept());
    const restored = page.waitForResponse((response) =>
      new URL(response.url()).pathname === `/api${endpoint}/checkpoint/restore` && response.ok());
    await page.locator(restore).click();
    await restored;
    assert.equal(harness.api.vmSnapshotRequests[1].live, "true");

    const deleteButton = vmAction("vm-snapshot-delete");
    await page.waitForSelector(deleteButton, { visible: true });
    page.once("dialog", (dialog) => dialog.accept());
    const deleted = page.waitForResponse((response) =>
      new URL(response.url()).pathname === `/api${endpoint}/checkpoint` && response.ok());
    await page.locator(deleteButton).click();
    await deleted;
    await page.waitForSelector(deleteButton, { hidden: true });
    assert.equal(harness.api.vmSnapshotRequests[2].method, "DELETE");
    assert.equal(harness.api.vmSnapshotRequests[2].live, "true");
    assert.equal(harness.api.vmSnapshotRequests.length, 3);
  } finally {
    if (browser) await browser.close();
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("wizard arrow keys + swipe navigate steps, never submit, and progress resumes after reload", async (t) => {
  const puppeteer = await loadPuppeteer(t);
  if (!puppeteer) {
    return;
  }
  const harness = await launchHarness();
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1500, height: 980 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await login(page);

    await page.click('[data-action-id="create-container"]');
    await page.waitForSelector("#wiz-name", { visible: true });

    // ArrowRight with an empty name is blocked by step validation.
    await page.focus("body");
    await page.keyboard.press("ArrowRight");
    await page.waitForFunction(() => (document.querySelector("#wizard .event-item.error") || {}).textContent?.includes("Container name is required"));
    assert.equal(await wizardStep(page), 1);

    // Typing into a field must not navigate on arrow keys.
    await page.type("#wiz-name", "web-01");
    await page.keyboard.press("ArrowRight");
    assert.equal(await wizardStep(page), 1, "arrow keys inside inputs edit text, not steps");

    await page.$eval("#wiz-name", (el) => el.blur());
    await page.keyboard.press("ArrowRight");
    await page.waitForFunction(() => document.querySelector("#wizard .wizard-step.active .wizard-step-index")?.textContent.trim() === "2");
    await page.keyboard.press("ArrowRight");
    await page.waitForFunction(() => document.querySelector("#wizard .wizard-step.active .wizard-step-index")?.textContent.trim() === "3");

    // On the last step ArrowRight must not submit.
    let createCalls = 0;
    page.on("request", (request) => {
      if (request.method() === "POST" && new URL(request.url()).pathname === "/api/containers") {
        createCalls += 1;
      }
    });
    await page.keyboard.press("ArrowRight");
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.equal(createCalls, 0, "keyboard navigation must never submit the wizard");
    assert.equal(await wizardStep(page), 3);

    await page.keyboard.press("ArrowLeft");
    await page.waitForFunction(() => document.querySelector("#wizard .wizard-step.active .wizard-step-index")?.textContent.trim() === "2");

    // Swipe right (finger moves left→right) goes back one step.
    await page.evaluate(() => {
      const viewport = document.querySelector("#wizard .wizard-viewport");
      const rect = viewport.getBoundingClientRect();
      const y = rect.top + rect.height / 2;
      const mk = (x) => new Touch({ identifier: 1, target: viewport, clientX: x, clientY: y });
      viewport.dispatchEvent(new TouchEvent("touchstart", { bubbles: true, touches: [mk(rect.left + 40)], changedTouches: [mk(rect.left + 40)] }));
      viewport.dispatchEvent(new TouchEvent("touchend", { bubbles: true, touches: [], changedTouches: [mk(rect.left + 260)] }));
    });
    await page.waitForFunction(() => document.querySelector("#wizard .wizard-step.active .wizard-step-index")?.textContent.trim() === "1");

    // Swipe left goes forward again.
    await page.evaluate(() => {
      const viewport = document.querySelector("#wizard .wizard-viewport");
      const rect = viewport.getBoundingClientRect();
      const y = rect.top + rect.height / 2;
      const mk = (x) => new Touch({ identifier: 1, target: viewport, clientX: x, clientY: y });
      viewport.dispatchEvent(new TouchEvent("touchstart", { bubbles: true, touches: [mk(rect.left + 300)], changedTouches: [mk(rect.left + 300)] }));
      viewport.dispatchEvent(new TouchEvent("touchend", { bubbles: true, touches: [], changedTouches: [mk(rect.left + 40)] }));
    });
    await page.waitForFunction(() => document.querySelector("#wizard .wizard-step.active .wizard-step-index")?.textContent.trim() === "2");

    const stored = await page.evaluate(() => JSON.parse(window.sessionStorage.getItem("lizard.wizard-progress.v1") || "null"));
    assert.equal(stored.mode, "create-container");
    assert.equal(stored.step, 1);
    assert.equal(stored.fields.name, "web-01");

    // Reload: progress is offered (not auto-applied) and resumes at the saved step with the saved fields.
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector('#fast-actions [data-action-id="wizard-resume"]', { visible: true });
    const bannerText = await page.$eval("#fast-actions .wizard-resume", (el) => el.textContent.replace(/\s+/g, " "));
    assert.match(bannerText, /Create Container/);
    assert.match(bannerText, /step 2\/3/);
    assert.equal(await page.$eval("#wizard-stage", (el) => el.hidden), true, "wizard must not auto-open after reload");

    await page.click('#fast-actions [data-action-id="wizard-resume"]');
    await page.waitForSelector("#wizard .wizard-step.active", { visible: true });
    assert.equal(await wizardStep(page), 2);
    await page.keyboard.press("ArrowLeft");
    await page.waitForSelector("#wiz-name", { visible: true });
    assert.equal(await page.$eval("#wiz-name", (el) => el.value), "web-01");

    // Closing the wizard clears the saved marker.
    await page.click('#wizard [data-wizard-action="close"]');
    const afterClose = await page.evaluate(() => window.sessionStorage.getItem("lizard.wizard-progress.v1"));
    assert.equal(afterClose, null);
    assert.equal(await page.$("#fast-actions .wizard-resume"), null);
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("wizard names and notes render as literal text and progress drops passwords", async (t) => {
  const puppeteer = await loadPuppeteer(t);
  if (!puppeteer) {
    return;
  }
  const harness = await launchHarness();
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1500, height: 980 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await login(page);

    await page.evaluate(() => window.openWizard("host-create"));
    await page.waitForSelector("#wiz-host-name", { visible: true });
    const name = 'Edge "West" & Co.';
    const notes = "Primary <b>edge</b> host";
    await page.type("#wiz-host-name", name);
    await page.type("#wiz-host-notes", notes);
    await page.click('#wizard [data-wizard-action="next"]');
    await page.waitForSelector("#wiz-host-pass", { visible: true });
    await page.click('#wizard [data-wizard-action="back"]');
    await page.waitForSelector("#wiz-host-name", { visible: true });
    assert.equal(await page.$eval("#wiz-host-name", (el) => el.value), name);
    assert.equal(await page.$eval("#wiz-host-notes", (el) => el.value), notes);
    await page.click('#wizard [data-wizard-action="next"]');
    await page.waitForSelector("#wiz-host-pass", { visible: true });
    await page.type("#wiz-host-address", "192.0.2.10");
    await page.type("#wiz-host-pass", "placeholder-secret");
    await page.click('#wizard [data-wizard-action="next"]');
    assert.equal(await wizardStep(page), 3);
    const confirmation = await page.$eval("#wizard .preview-meta", (el) => ({
      text: el.textContent,
      boldNotes: Boolean(el.querySelector("b")),
    }));
    assert.ok(confirmation.text.includes(name));
    assert.ok(confirmation.text.includes(notes));
    assert.equal(confirmation.boldNotes, false);

    const stored = await page.evaluate(() => window.sessionStorage.getItem("lizard.wizard-progress.v1") || "");
    assert.equal(JSON.parse(stored).fields.name, name);
    assert.ok(!stored.includes("placeholder-secret"), "password values must never be persisted");
    assert.ok(!/"password"/.test(stored), "password key must be dropped entirely");

    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector('#fast-actions [data-action-id="wizard-resume-discard"]', { visible: true });
    await page.click('#fast-actions [data-action-id="wizard-resume-discard"]');
    await page.waitForFunction(() => !document.querySelector("#fast-actions .wizard-resume"));
    assert.equal(await page.evaluate(() => window.sessionStorage.getItem("lizard.wizard-progress.v1")), null);

    await page.evaluate(() => window.openWizard("recipe-apply"));
    const next = '#wizard [data-wizard-action="next"]';
    const back = '#wizard [data-wizard-action="back"]';
    await page.click(next);
    await page.waitForSelector("#wiz-recipe-params", { visible: true });
    const parameters = "db_password=placeholder<&";
    await page.type("#wiz-recipe-params", parameters);
    await page.click(next);
    await page.click(back);
    assert.equal(await page.$eval("#wiz-recipe-params", (el) => el.value), parameters);
    const recipeProgress = await page.evaluate(() => JSON.parse(sessionStorage.getItem("lizard.wizard-progress.v1")));
    assert.equal(recipeProgress.fields.parameters, undefined);
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("resuming an upgrade reruns preflight and requires fresh backup confirmation", async (t) => {
  const puppeteer = await loadPuppeteer(t);
  if (!puppeteer) {
    return;
  }
  const harness = await launchHarness();
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1500, height: 980 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await login(page);
    await page.evaluate(() => window.openWizard("system-upgrade"));

    const next = '#wizard [data-wizard-action="next"]';
    const resume = '#fast-actions [data-action-id="wizard-resume"]';
    await page.locator("#wiz-upgrade-full").click();
    await page.click(next);
    await page.waitForFunction(() => document.querySelector("#wizard .wizard-step.active .wizard-step-label")?.textContent === "Preflight");
    await page.click(next);
    await page.waitForSelector("#wiz-upgrade-backup-confirm", { visible: true });
    await page.click("#wiz-upgrade-backup-confirm");
    await page.click(next);
    assert.equal(await wizardStep(page), 4);
    const savedProgress = await page.evaluate(() => sessionStorage.getItem("lizard.wizard-progress.v1"));
    assert.equal(JSON.parse(savedProgress).fields.backup_confirmation, undefined);

    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector(resume, { visible: true });
    assert.equal(harness.api.upgrades.length, 1);
    await page.click(resume);
    await page.waitForSelector("#wiz-upgrade-backup-confirm", { visible: true });
    assert.equal(await wizardStep(page), 3);
    assert.equal(await page.$eval("#wiz-upgrade-backup-confirm", (el) => el.checked), false);
    await page.click(next);
    await page.waitForFunction(() => document.querySelector("#wizard .event-item.error")?.textContent.includes("Backup confirmation is required"));
    assert.equal(await wizardStep(page), 3);

    harness.api.setPreflightFailure(true);
    await page.evaluate((progress) => sessionStorage.setItem("lizard.wizard-progress.v1", progress), savedProgress);
    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector(resume, { visible: true });
    await page.click(resume);
    await page.waitForSelector("#wizard .event-item.error", { visible: true });
    assert.equal(await wizardStep(page), 1);
    assert.equal(await page.$eval(next, (el) => el.disabled), false);
    assert.equal(await page.$eval('#wizard [data-step-index="3"]', (el) => el.disabled), true);

    const expected = { dry_run: true, update_packages: true, full_upgrade: true, apply_migrations: true };
    assert.deepEqual(harness.api.upgrades, [expected, expected, expected]);
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("debug panel copies and exports redacted error payloads", async (t) => {
  const puppeteer = await loadPuppeteer(t);
  if (!puppeteer) {
    return;
  }
  const harness = await launchHarness();
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1500, height: 980 });
    await page.evaluateOnNewDocument(() => {
      window.__copied = [];
      window.__downloads = [];
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText: async (text) => window.__copied.push(text) },
      });
      HTMLAnchorElement.prototype.click = function captureDownload() {
        if (this.download) {
          window.__downloads.push({ name: this.download, href: this.href });
        }
      };
    });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await login(page);

    await page.click('#fast-actions [data-action-id="monitoring-refresh"]');
    await page.waitForSelector('#debug-panel [data-debug-action="copy-latest"]', { visible: true });

    await page.click('#debug-panel [data-debug-action="copy-latest"]');
    await page.waitForFunction(() => window.__copied.length === 1);
    const copied = JSON.parse(await page.evaluate(() => window.__copied[0]));
    assert.equal(copied.format, "lizard.debug-export.v1");
    assert.equal(copied.errors.length, 1);
    assert.equal(copied.errors[0].status, 503);
    assert.ok(!JSON.stringify(copied).includes("should-not-leak"), "secret-looking keys are redacted");

    await page.click('#debug-panel [data-debug-action="export"]');
    await page.waitForFunction(() => window.__downloads.length === 1);
    const download = await page.evaluate(async () => {
      const item = window.__downloads[0];
      const text = await (await fetch(item.href)).text();
      return { name: item.name, text };
    });
    assert.match(download.name, /^lizard-debug-.*\.json$/);
    const exported = JSON.parse(download.text);
    assert.ok(exported.errors.length >= 1);
    assert.ok(!download.text.includes("should-not-leak"));

    await page.click('#debug-panel [data-debug-action="clear"]');
    await page.waitForFunction(() => (document.getElementById("debug-panel").textContent || "").includes("No API errors captured"));
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("fast actions reorder via arrow buttons and drag/drop, persisted in localStorage", async (t) => {
  const puppeteer = await loadPuppeteer(t);
  if (!puppeteer) {
    return;
  }
  const harness = await launchHarness();
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1500, height: 980 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await login(page);

    const topBarOrder = () =>
      page.$$eval("#fast-actions .fast-actions-row [data-action-id]", (els) => els.map((el) => el.getAttribute("data-action-id")));
    const initial = await topBarOrder();
    assert.equal(initial[0], "refresh");
    assert.equal(initial[1], "create-container");

    await page.click('#fast-actions [data-action-id="open-settings"]');
    await page.waitForSelector("#fast-order-list .fast-order-item", { visible: true });

    await page.click('#fast-order-list [data-fast-id="create-container"][data-direction="up"]');
    await page.waitForFunction(() => document.querySelector("#fast-actions .fast-actions-row [data-action-id]")?.getAttribute("data-action-id") === "create-container");

    // Drag the last item onto the first slot.
    const before = await topBarOrder();
    const lastId = before[before.length - 1];
    await page.evaluate((dragId) => {
      const list = document.getElementById("fast-order-list");
      const source = list.querySelector(`[data-fast-order-id="${dragId}"]`);
      const target = list.querySelector(".fast-order-item");
      const dt = new DataTransfer();
      source.dispatchEvent(new DragEvent("dragstart", { bubbles: true, dataTransfer: dt }));
      target.dispatchEvent(new DragEvent("dragover", { bubbles: true, cancelable: true, dataTransfer: dt }));
      target.dispatchEvent(new DragEvent("drop", { bubbles: true, cancelable: true, dataTransfer: dt }));
      source.dispatchEvent(new DragEvent("dragend", { bubbles: true, dataTransfer: dt }));
    }, lastId);
    await page.waitForFunction(
      (id) => document.querySelector("#fast-actions .fast-actions-row [data-action-id]")?.getAttribute("data-action-id") === id,
      {},
      lastId
    );

    const after = await topBarOrder();
    const stored = await page.evaluate(() => JSON.parse(window.localStorage.getItem("lizard.fast-action-profiles.v1")));
    assert.deepEqual(stored, { active: "Default", profiles: [{ name: "Default", actions: after }] });
    assert.equal(after.length, before.length);
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("named fast-action profiles preserve legacy order and VM Labs shows configuration issues", async (t) => {
  const puppeteer = await loadPuppeteer(t);
  if (!puppeteer) return;
  const harness = await launchHarness();
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1440, height: 930 });
    await page.evaluateOnNewDocument(() => {
      if (!localStorage.getItem("lizard.fast-actions.v1")) {
        localStorage.setItem("lizard.fast-actions.v1", JSON.stringify(["system-upgrade", "refresh"]));
      }
    });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "domcontentloaded" });
    await login(page);

    const topBarOrder = () =>
      page.$$eval("#fast-actions .fast-actions-row [data-action-id]", (buttons) => buttons.map((button) => button.dataset.actionId));
    const activeProfile = () => page.$eval("#fast-action-profile", (select) => select.value);
    const openSettings = () => page.locator('#fast-actions [data-action-id="open-settings"]').click();
    const saveProfile = () => page.locator('#fast-action-profile-form button[type="submit"]').click();
    assert.deepEqual(await topBarOrder(), ["system-upgrade", "refresh"]);
    await openSettings();
    assert.equal(await activeProfile(), "Default");
    await page.locator("#fast-action-profile-name").fill("Ops <review>");
    await saveProfile();
    assert.equal(await activeProfile(), "Ops <review>");
    await page.locator('[data-setting-fast-action="create-container"]').click();
    await page.locator('#fast-order-list [data-fast-id="create-container"][data-direction="up"]').click();
    const edited = ["system-upgrade", "create-container", "refresh"];
    assert.deepEqual(await topBarOrder(), edited);
    assert.ok((await page.$eval("#app-grid", (el) => el.textContent)).includes("New Container"));

    await page.locator("#fast-action-profile-name").fill("ops <review>");
    await saveProfile();
    await page.waitForSelector("#fast-action-profile-error", { visible: true });
    assert.match(await page.$eval("#fast-action-profile-error", (el) => el.textContent), /already exists/);
    await page.select("#fast-action-profile", "Default");
    assert.deepEqual(await topBarOrder(), ["system-upgrade", "refresh"]);
    await page.select("#fast-action-profile", "Ops <review>");
    assert.deepEqual(await topBarOrder(), edited);
    await page.reload({ waitUntil: "domcontentloaded" });
    await openSettings();
    assert.equal(await activeProfile(), "Ops <review>");
    assert.deepEqual(await topBarOrder(), edited);

    const remove = '[data-action-id="settings-fast-profile-delete"]';
    page.once("dialog", (dialog) => dialog.dismiss());
    await page.locator(remove).click();
    assert.equal(await activeProfile(), "Ops <review>");
    page.once("dialog", (dialog) => dialog.accept());
    await page.locator(remove).click();
    assert.equal(await activeProfile(), "Default");
    assert.deepEqual(await topBarOrder(), ["system-upgrade", "refresh"]);
    assert.deepEqual(await page.$$eval("#fast-action-profile option", (options) => options.map((option) => option.value)), ["Default"]);

    await page.locator('#breadcrumb [data-nav-node-id="home"]').click();
    await page.locator('.app-card[data-node-id="vms"] .card-icon-button').click();
    await page.waitForFunction(() => document.querySelector("#app-grid .app-home-shell")?.textContent.includes("Configuration issue"));
    assert.deepEqual(harness.api.vmQueries, ["true"]);
    const cards = await page.$$eval("#app-grid .app-home-item", (elements) => elements.map((el) => el.textContent));
    assert.match(cards[0], /lab-old/);
    assert.match(cards[0], /disk_path must be inside FORTRESS_VM_ROOT/);
    assert.doesNotMatch(cards.find((text) => text.includes("lab-ready")), /Configuration issue/);
    assert.match(await page.$eval("#preview", (el) => el.textContent), /disk_path must be inside FORTRESS_VM_ROOT/);
  } finally {
    if (browser) await browser.close();
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});
