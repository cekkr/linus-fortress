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
      const text = chunk.toString();
      if (text.includes("Lizard UI listening")) {
        clearTimeout(timeout);
        resolve();
      }
    });
    proc.on("error", reject);
  });
}

function waitForCondition(predicate, timeoutMs = 5000, intervalMs = 50) {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    const timer = setInterval(() => {
      try {
        if (predicate()) {
          clearInterval(timer);
          resolve(true);
          return;
        }
      } catch (err) {
        clearInterval(timer);
        reject(err);
        return;
      }
      if (Date.now() - start > timeoutMs) {
        clearInterval(timer);
        reject(new Error("Timed out waiting for condition"));
      }
    }, intervalMs);
  });
}

function jsonResponse(res, payload, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

function readJsonBody(req) {
  return new Promise((resolve) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk.toString();
    });
    req.on("end", () => {
      if (!body.trim()) {
        resolve({});
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch {
        resolve({});
      }
    });
  });
}

function startFortressStubApi(port, options = {}) {
  const state = {
    popularHits: 0,
    createPayloads: [],
    updateReloadPayloads: [],
  };

  const imagesPayload =
    options.imagesPayload ||
    {
      images: [
        {
          name: "ubuntu:lts",
          label: "Ubuntu LTS",
          resolved_name: "ubuntu:lts",
          available: true,
          remote: "ubuntu",
          source: "lxd-cli",
        },
        {
          name: "debian:12",
          label: "Debian 12",
          resolved_name: "debian:12",
          available: true,
          remote: "debian",
          source: "lxd-cli",
        },
      ],
      remotes: ["ubuntu", "debian"],
      latest: { ubuntu_lts: "ubuntu:lts" },
      refreshed_at: "2026-02-11T00:00:00Z",
    };
  const updateReloadResponse =
    options.updateReloadResponse ||
    {
      updated: false,
      message: "Already up to date",
      migrations: { applied: [] },
      reload: { scheduled: false },
      stash: { used: true, restore_conflict: false },
    };

  const server = createServer((req, res) => {
    const url = new URL(req.url || "/", `http://127.0.0.1:${port}`);
    const pathname = url.pathname;
    void (async () => {
      if (pathname === "/status") {
        jsonResponse(res, options.statusPayload || { status: "ok", containers: [] });
        return;
      }
      if (pathname === "/containers/images/popular") {
        if (req.method === "GET") {
          state.popularHits += 1;
          jsonResponse(res, imagesPayload);
          return;
        }
        if (req.method === "POST") {
          jsonResponse(res, { message: "saved" });
          return;
        }
      }
      if (pathname === "/containers/images/popular/remove" && req.method === "POST") {
        jsonResponse(res, { message: "removed" });
        return;
      }
      if (pathname === "/container/create" && req.method === "POST") {
        const payload = await readJsonBody(req);
        state.createPayloads.push(payload);
        jsonResponse(res, { message: `Container ${payload.name || "unknown"} created` });
        return;
      }
      if (pathname === "/system/update-reload" && req.method === "POST") {
        const payload = await readJsonBody(req);
        state.updateReloadPayloads.push(payload);
        jsonResponse(res, updateReloadResponse);
        return;
      }
      jsonResponse(res, { error: "not found" }, 404);
    })().catch((err) => {
      jsonResponse(res, { error: err.message || "stub failure" }, 500);
    });
  });

  return new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", () => resolve({ server, state }));
    server.on("error", reject);
  });
}

async function launchUiHarness(stubOptions = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fortress-ui-"));
  const adminDb = path.join(tmpDir, "ui_admins.json");
  const adminLog = path.join(tmpDir, "ui_admin_audit.log");
  const apiPort = await getFreePort();
  const uiPort = await getFreePort();
  const api = await startFortressStubApi(apiPort, stubOptions);

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
  await waitForReady(proc);
  return { tmpDir, uiPort, proc, api };
}

async function loginWithDelegatedToken(page) {
  await page.waitForSelector("#auth-overlay", { visible: true });
  await page.type("#auth-token", "user-token:test-session");
  await page.click("#auth-form button[type=\"submit\"]");
  await page.waitForSelector("#auth-overlay", { hidden: true });
  await page.waitForSelector(".app-card[data-node-id=\"containers\"] .card-summary", { visible: true });
}

test("bridge opens before info panel, stays aligned, and startup image refresh is scheduled", async (t) => {
  let puppeteer;
  try {
    puppeteer = await import("puppeteer");
  } catch (err) {
    t.skip(`puppeteer not available: ${err.message}`);
    return;
  }

  const harness = await launchUiHarness();
  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1600, height: 1000 });
    await page.evaluateOnNewDocument(() => {
      const nativeSetInterval = window.setInterval.bind(window);
      window.__intervalDelays = [];
      window.setInterval = (handler, timeout, ...args) => {
        window.__intervalDelays.push(Number(timeout));
        return nativeSetInterval(handler, timeout, ...args);
      };
    });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await loginWithDelegatedToken(page);

    await waitForCondition(() => harness.api.state.popularHits >= 1, 6000, 50);
    const intervalDelays = await page.evaluate(() => window.__intervalDelays || []);
    assert.ok(intervalDelays.includes(600000), "expected 10-minute image refresh interval");

    const timing = await page.evaluate(async () => {
      const nodeId = "containers";
      const clickSelector = `.app-card[data-node-id="${nodeId}"] .card-summary`;
      const clickTarget = document.querySelector(clickSelector);
      if (!clickTarget) {
        return null;
      }
      const start = performance.now();
      clickTarget.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));

      return await new Promise((resolve) => {
        let bridgeStart = null;
        let panelStart = null;
        const deadline = start + 1900;

        const sample = (now) => {
          const card = document.querySelector(`.app-card[data-node-id="${nodeId}"]`);
          const row = card ? card.closest(".app-row") : null;
          const bridge = row ? row.querySelector(".app-row-bridge") : null;
          const rowMore = row ? row.querySelector(".app-row-more") : null;
          if (bridge && bridgeStart === null && bridge.getBoundingClientRect().height > 1) {
            bridgeStart = now - start;
          }
          if (rowMore && panelStart === null && rowMore.getBoundingClientRect().height > 1) {
            panelStart = now - start;
          }

          const settled = now - start >= 900;
          if (now < deadline && (!settled || bridgeStart === null || panelStart === null)) {
            requestAnimationFrame(sample);
            return;
          }

          const frame = card ? card.querySelector(".app-card-frame") : null;
          const panel = row ? row.querySelector(".app-row-more .row-more-content") : null;
          const rowMoreRect = rowMore ? rowMore.getBoundingClientRect() : null;
          const rowRect = row ? row.getBoundingClientRect() : null;
          const frameRect = frame ? frame.getBoundingClientRect() : null;
          const bridgeRect = bridge ? bridge.getBoundingClientRect() : null;
          const panelRect = panel ? panel.getBoundingClientRect() : null;
          const style = bridge ? getComputedStyle(bridge) : null;
          const connectorLeft = style ? parseFloat(style.getPropertyValue("--connector-left-px")) : NaN;
          const connectorWidth = style ? parseFloat(style.getPropertyValue("--connector-width-px")) : NaN;
          resolve({
            bridgeStart,
            panelStart,
            rowLeft: rowRect ? rowRect.left : null,
            frameLeft: frameRect ? frameRect.left : null,
            frameWidth: frameRect ? frameRect.width : null,
            connectorLeft,
            connectorWidth,
            bridgeBottom: bridgeRect ? bridgeRect.top + bridgeRect.height : null,
            rowMoreTop: rowMoreRect ? rowMoreRect.top : null,
            panelTop: panelRect ? panelRect.top : null,
          });
        };

        requestAnimationFrame(sample);
      });
    });

    assert.ok(timing, "missing bridge timing payload");
    assert.notEqual(timing.bridgeStart, null, "bridge did not animate");
    assert.notEqual(timing.panelStart, null, "panel did not animate");
    assert.ok(
      timing.panelStart > timing.bridgeStart + 100,
      `expected bridge to start before panel (bridge=${timing.bridgeStart}, panel=${timing.panelStart})`
    );
    const leftDelta = Math.abs((timing.frameLeft - timing.rowLeft) - timing.connectorLeft);
    const widthDelta = Math.abs(timing.frameWidth - timing.connectorWidth);
    const seamDelta = Math.abs(timing.bridgeBottom - timing.rowMoreTop);
    assert.ok(leftDelta <= 1.1, `bridge left offset drifted (${leftDelta})`);
    assert.ok(widthDelta <= 1.1, `bridge width drifted (${widthDelta})`);
    assert.ok(seamDelta <= 1.2, `bridge/row seam drifted (${seamDelta})`);

    const collapseMetrics = await page.evaluate(async () => {
      const nodeId = "containers";
      const row = document.querySelector(`.app-card[data-node-id="${nodeId}"]`)?.closest(".app-row");
      if (!row) {
        return null;
      }
      const siblings = Array.from(row.querySelectorAll(".app-card")).filter((card) => card.dataset.nodeId !== nodeId);
      const before = siblings.map((card) => ({
        id: card.dataset.nodeId,
        height: card.getBoundingClientRect().height,
      }));
      const clickTarget = document.querySelector(`.app-card[data-node-id="${nodeId}"] .card-summary`);
      clickTarget?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      await new Promise((resolve) => setTimeout(resolve, 130));
      const after = siblings.map((card) => ({
        id: card.dataset.nodeId,
        height: card.getBoundingClientRect().height,
        animating: card.classList.contains("is-collapsing") || card.classList.contains("is-expanding"),
      }));
      return { before, after };
    });

    assert.ok(collapseMetrics, "missing collapse metrics");
    for (const beforeItem of collapseMetrics.before) {
      const afterItem = collapseMetrics.after.find((item) => item.id === beforeItem.id);
      assert.ok(afterItem, `missing sibling ${beforeItem.id}`);
      assert.equal(afterItem.animating, false, `sibling ${beforeItem.id} should not animate`);
      assert.ok(
        Math.abs(afterItem.height - beforeItem.height) <= 0.5,
        `sibling ${beforeItem.id} height changed during collapse`
      );
    }
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("create-container wizard blocks invalid steps and submits only valid payload", async (t) => {
  let puppeteer;
  try {
    puppeteer = await import("puppeteer");
  } catch (err) {
    t.skip(`puppeteer not available: ${err.message}`);
    return;
  }

  const harness = await launchUiHarness({
    imagesPayload: {
      images: [
        {
          name: "ubuntu:lts",
          label: "Ubuntu LTS",
          resolved_name: "ubuntu:lts",
          available: true,
          remote: "ubuntu",
          source: "lxd-cli",
        },
        {
          name: "images:broken/9/cloud",
          label: "Broken 9",
          resolved_name: "images:broken/9/cloud",
          available: false,
          remote: "images",
          source: "lxd-cli",
          reason: "LXD remote 'images' is not configured (known remotes: local).",
          debug: { known_remotes: ["local"] },
        },
      ],
      remotes: ["local"],
      latest: { ubuntu_lts: "ubuntu:lts" },
      refreshed_at: "2026-02-11T00:00:00Z",
    },
  });

  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1500, height: 980 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await loginWithDelegatedToken(page);

    await page.click('[data-action-id="create-container"]');
    await page.waitForFunction(() => {
      const stage = document.getElementById("wizard-stage");
      return Boolean(stage && !stage.hidden);
    });

    await page.click('#wizard [data-wizard-action="next"]');
    await page.waitForFunction(() => {
      const el = document.querySelector("#wizard .event-item.error");
      return Boolean(el && (el.textContent || "").includes("Container name is required"));
    });

    await page.type("#wiz-name", "web-01");
    await page.evaluate(() => {
      const select = document.querySelector("#wiz-distro");
      if (!select) {
        return;
      }
      select.value = "images:broken/9/cloud";
      select.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.click('#wizard [data-wizard-action="next"]');
    const unavailableError = await page.$eval("#wizard .event-item.error", (el) => el.textContent || "");
    assert.match(unavailableError, /(unavailable|not configured)/i);
    assert.ok(await page.$("#wiz-name"), "wizard should remain on identity step after invalid image");
    const wizardText = await page.$eval("#wizard", (el) => el.textContent || "");
    assert.match(wizardText, /LXD remote 'images' is not configured/i);

    await page.select("#wiz-distro", "ubuntu:lts");
    await page.click('#wizard [data-wizard-action="next"]');
    await page.waitForSelector("#wiz-cpu", { visible: true });

    await page.$eval("#wiz-cpu", (el) => {
      el.value = "";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.click('#wizard [data-wizard-action="next"]');
    const resourceError = await page.$eval("#wizard .event-item.error", (el) => el.textContent || "");
    assert.match(resourceError, /CPU, RAM, and disk limits are required/i);

    await page.$eval("#wiz-cpu", (el) => {
      el.value = "2";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.$eval("#wiz-ram", (el) => {
      el.value = "1GB";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.$eval("#wiz-disk", (el) => {
      el.value = "20GB";
      el.dispatchEvent(new Event("input", { bubbles: true }));
    });
    await page.click('#wizard [data-wizard-action="next"]');
    await page.waitForFunction(() => {
      const wizard = document.getElementById("wizard");
      return Boolean(wizard && (wizard.textContent || "").includes("Confirm the container launch profile."));
    });

    await page.click('#wizard [data-wizard-action="next"]');
    await page.waitForFunction(() => {
      const stage = document.getElementById("wizard-stage");
      return Boolean(stage && stage.hidden);
    });

    await waitForCondition(() => harness.api.state.createPayloads.length === 1, 5000, 50);
    const payload = harness.api.state.createPayloads[0];
    assert.equal(payload.name, "web-01");
    assert.equal(payload.distro, "ubuntu:lts");
    assert.equal(payload.cpu_limit, "2");
    assert.equal(payload.ram_limit, "1GB");
    assert.equal(payload.disk_limit, "20GB");
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});

test("check update + reload action triggers browser reload", async (t) => {
  let puppeteer;
  try {
    puppeteer = await import("puppeteer");
  } catch (err) {
    t.skip(`puppeteer not available: ${err.message}`);
    return;
  }

  const harness = await launchUiHarness({
    updateReloadResponse: {
      updated: false,
      message: "Already up to date",
      migrations: { applied: [] },
      reload: { scheduled: false },
      stash: { used: true, restore_conflict: false },
    },
  });

  let browser;
  try {
    browser = await puppeteer.launch({ args: ["--no-sandbox", "--disable-setuid-sandbox"] });
    const page = await browser.newPage();
    await page.setViewport({ width: 1450, height: 960 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await loginWithDelegatedToken(page);

    const dialogs = [];
    page.on("dialog", async (dialog) => {
      dialogs.push(dialog.message());
      await dialog.accept();
    });

    const navigationPromise = page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: 9000 });
    await page.click('#fast-actions [data-action-id="system-update-reload"]');
    await navigationPromise;

    assert.ok(dialogs.length >= 1, "expected confirmation dialog");
    assert.match(dialogs[0], /check for repository updates/i);
    await waitForCondition(() => harness.api.state.updateReloadPayloads.length === 1, 5000, 50);
    const payload = harness.api.state.updateReloadPayloads[0];
    assert.equal(payload.apply_migrations, true);
    assert.equal(payload.restart_mode, "auto");
    assert.equal(payload.auto_stash, true);
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.api.server.close();
  }
});
