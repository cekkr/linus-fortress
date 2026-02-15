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

function jsonResponse(res, payload, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

function startStubApi(port) {
  const imagesPayload = {
    images: [
      {
        name: "ubuntu:lts",
        label: "Ubuntu LTS",
        resolved_name: "ubuntu:lts",
        available: true,
        remote: "images",
        source: "lxc",
      },
    ],
    remotes: ["images"],
    latest: { ubuntu_lts: "ubuntu:lts" },
    refreshed_at: "2026-02-11T00:00:00Z",
  };

  const server = createServer((req, res) => {
    const url = new URL(req.url || "/", `http://127.0.0.1:${port}`);
    if (url.pathname === "/status") {
      jsonResponse(res, { status: "ok", containers: [] });
      return;
    }
    if (url.pathname === "/containers/images/popular") {
      jsonResponse(res, imagesPayload);
      return;
    }
    jsonResponse(res, { error: "not found" }, 404);
  });

  return new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", () => resolve(server));
    server.on("error", reject);
  });
}

test("preview-meta inherits foreground color inside wizard stage (no hard-coded dark values)", async (t) => {
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
  const apiServer = await startStubApi(apiPort);

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
    await page.setViewport({ width: 1600, height: 980 });
    await page.goto(`http://127.0.0.1:${uiPort}`, { waitUntil: "networkidle0" });

    await page.waitForSelector("#auth-overlay", { visible: true });
    await page.type("#auth-token", "user-token:preview-meta-inheritance");
    await page.click("#auth-form button[type=\"submit\"]");
    await page.waitForSelector("#auth-overlay", { hidden: true });

    await page.waitForSelector(".app-card[data-node-id=\"containers\"] .card-summary", { visible: true });
    await page.click(".app-card[data-node-id=\"containers\"] .card-summary");
    await page.waitForSelector("#app-grid .row-more-content", { visible: true });

    const triggered = await page.evaluate(() => {
      const action = document.querySelector('#app-grid .row-more-content [data-action-id="create-container"]');
      if (!action) {
        return false;
      }
      action.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      return true;
    });
    assert.equal(triggered, true, "failed to trigger create-container wizard");

    await page.waitForSelector("#wizard-stage", { visible: true });
    await page.waitForSelector("#wiz-name", { visible: true });
    await page.type("#wiz-name", "web-01");

    await page.click('#wizard [data-wizard-action="next"]');
    await page.waitForSelector("#wiz-cpu", { visible: true });
    await page.click('#wizard [data-wizard-action="next"]');
    await page.waitForSelector("#wizard .preview-meta span", { visible: true });

    const colors = await page.evaluate(() => {
      const parseRgb = (value) => {
        const raw = String(value || "");
        const match = raw.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/i);
        if (!match) {
          return null;
        }
        return [Number(match[1]), Number(match[2]), Number(match[3])];
      };

      const stage = document.getElementById("wizard-stage");
      const span = document.querySelector("#wizard .preview-meta span");
      if (!stage || !span) {
        return null;
      }
      const stageColor = parseRgb(getComputedStyle(stage).color);
      const spanColor = parseRgb(getComputedStyle(span).color);
      return { stageColor, spanColor, opacity: getComputedStyle(span).opacity };
    });

    assert.ok(colors, "failed to read computed colors for wizard preview meta");
    assert.deepEqual(colors.spanColor, colors.stageColor, "wizard preview-meta values should inherit stage foreground color");
  } finally {
    if (browser) {
      await browser.close();
    }
    proc.kill("SIGTERM");
    apiServer.close();
  }
});
