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

function startStubApi(port) {
  const histories = new Map([
    ["app", [
      { status: "error", dry_run: true, timestamp: "2026-11-10T11:00:00Z", request_id: "<i>fixture-error</i>" },
      { status: "success", dry_run: false, timestamp: "2026-11-09T10:00:00Z", request_id: "fixture-success" },
    ]],
    ["empty", []],
    ["unavailable", null],
    ["manual", undefined],
  ]);
  const sites = Array.from(histories.keys(), (id) => ({
    id, primary_domain: `${id}.example.com`, container_name: "web", status: "active",
  }));
  const server = createServer((req, res) => {
    let payload;
    if (req.url === "/status") {
      payload = { status: "ok", containers: [] };
    } else if (req.url === "/sites") {
      payload = { sites };
    } else {
      const [, resource, id, ...segments] = (req.url || "").split("/");
      if (resource === "sites" && histories.has(id)) {
        const tlsStatus = {
          status: "valid", auto_renewal_supported: id !== "manual", renewal_history: histories.get(id),
        };
        const view = segments.join("/");
        if (view === "tls/status") {
          payload = { site_id: id, tls_status: tlsStatus };
        } else if (view === "backups") {
          payload = { backups: [] };
        } else if (!view) {
          payload = { site: sites.find((site) => site.id === id) };
        }
      }
    }
    if (payload) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(payload));
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });
  return new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", () => resolve(server));
    server.on("error", reject);
  });
}

test("leaf app renders stage home panel instead of blank grid", async (t) => {
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
    await page.goto(`http://127.0.0.1:${uiPort}`, { waitUntil: "networkidle0" });

    await page.waitForSelector("#auth-overlay", { visible: true });
    await page.type("#auth-token", "user-token:demo-token");
    await page.click("#auth-form button[type=\"submit\"]");
    await page.waitForSelector("#auth-overlay", { hidden: true });

    await page.waitForSelector(".app-card[data-node-id=\"containers\"] .card-icon-button", { visible: true });
    await page.click(".app-card[data-node-id=\"containers\"] .card-icon-button");

    await page.waitForSelector(".app-home-shell", { visible: true });
    const homeTitle = await page.$eval(".app-home-title", (el) => el.textContent || "");
    assert.match(homeTitle, /Containers Home/i);

    const emptyMessage = await page.$eval(".app-home-empty", (el) => el.textContent || "");
    assert.match(emptyMessage, /No containers found/i);

    await t.test("site preview shows renewal outcomes and request IDs at phone width", async () => {
      await page.setViewport({ width: 390, height: 844 });
      await page.evaluate(() => window.selectNode("home"));
      await page.click('.app-card[data-node-id="sites"] .card-icon-button');
      const history = "#preview details[data-site-renewal-history]";
      await page.waitForSelector(`${history} summary`, { visible: true });
      assert.match(await page.$eval(`${history} summary`, (el) => el.textContent), /1 failed/);
      await page.click(`${history} summary`);
      await page.waitForSelector(`${history}[open] code`, { visible: true });

      const attempts = await page.$$eval(`${history} .event-item`, (rows) => rows.map((row) => ({
        text: row.textContent.replace(/\s+/g, " "),
        requestId: row.querySelector("code").textContent,
        elementsInRequestId: row.querySelector("code").children.length,
      })));
      assert.match(attempts[0].text, /Failed Dry run/);
      assert.equal(attempts[0].requestId, "<i>fixture-error</i>");
      assert.equal(attempts[0].elementsInRequestId, 0);
      assert.match(attempts[1].text, /Completed Renewal/);
      assert.equal(attempts[1].requestId, "fixture-success");
      assert.deepEqual(await page.$$eval("#preview [data-site-renewal-history]:not(details)", (rows) =>
        rows.map((el) => el.textContent)), ["No recorded renewal attempts", "Renewal history unavailable"]);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth), 390);
    });
  } finally {
    if (browser) {
      await browser.close();
    }
    proc.kill("SIGTERM");
    apiServer.close();
  }
});
