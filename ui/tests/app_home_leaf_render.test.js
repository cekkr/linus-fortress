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
  const server = createServer((req, res) => {
    if (req.url === "/status") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", containers: [] }));
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
  } finally {
    if (browser) {
      await browser.close();
    }
    proc.kill("SIGTERM");
    apiServer.close();
  }
});
