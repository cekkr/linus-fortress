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

function startStubApi(port) {
  const server = createServer((req, res) => {
    const pathname = new URL(req.url || "/", `http://127.0.0.1:${port}`).pathname;
    if (pathname === "/status") {
      jsonResponse(res, { status: "ok", containers: [] });
      return;
    }
    if (pathname === "/containers/images/popular") {
      jsonResponse(res, {
        images: [{ name: "ubuntu:lts", label: "Ubuntu LTS", resolved_name: "ubuntu:lts", available: true, remote: "ubuntu" }],
        remotes: ["ubuntu"],
        latest: { ubuntu_lts: "ubuntu:lts" },
        refreshed_at: "2026-02-11T00:00:00Z",
      });
      return;
    }
    if (pathname === "/monitoring/resources") {
      // Deliberate failure so the Debug panel captures an error payload with a secret-looking key.
      jsonResponse(res, { detail: "monitoring backend unavailable", password: "should-not-leak" }, 503);
      return;
    }
    jsonResponse(res, { error: "not found" }, 404);
  });
  return new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", () => resolve(server));
    server.on("error", reject);
  });
}

async function launchHarness() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fortress-ui-"));
  const apiPort = await getFreePort();
  const uiPort = await getFreePort();
  const api = await startStubApi(apiPort);
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
    harness.api.close();
  }
});

test("wizard progress never persists password fields and discard removes the banner", async (t) => {
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
    await page.type("#wiz-host-name", "edge-01");
    await page.click('#wizard [data-wizard-action="next"]');
    await page.waitForSelector("#wiz-host-pass", { visible: true });
    await page.type("#wiz-host-address", "192.0.2.10");
    await page.type("#wiz-host-pass", "placeholder-secret");

    const stored = await page.evaluate(() => window.sessionStorage.getItem("lizard.wizard-progress.v1") || "");
    assert.ok(stored.includes("edge-01"), "non-sensitive fields are persisted");
    assert.ok(!stored.includes("placeholder-secret"), "password values must never be persisted");
    assert.ok(!/"password"/.test(stored), "password key must be dropped entirely");

    await page.reload({ waitUntil: "networkidle0" });
    await page.waitForSelector('#fast-actions [data-action-id="wizard-resume-discard"]', { visible: true });
    await page.click('#fast-actions [data-action-id="wizard-resume-discard"]');
    await page.waitForFunction(() => !document.querySelector("#fast-actions .wizard-resume"));
    assert.equal(await page.evaluate(() => window.sessionStorage.getItem("lizard.wizard-progress.v1")), null);
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.api.close();
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
    harness.api.close();
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
    const stored = await page.evaluate(() => JSON.parse(window.localStorage.getItem("lizard.fast-actions.v1") || "[]"));
    assert.deepEqual(stored, after);
    assert.equal(after.length, before.length);
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.api.close();
  }
});
