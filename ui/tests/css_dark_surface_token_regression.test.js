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
const cssPath = path.resolve(__dirname, "../public/css/app.css");
const BASELINE_FILE = path.join(__dirname, "fixtures", "dark_surface_token_hashes.json");
const UPDATE_BASELINES = process.env.UPDATE_DARK_SURFACE_BASELINES === "1";

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

function startFortressStubApi(port) {
  const containers = [
    {
      name: "alpha-web",
      status: "running",
      type: "container",
      state: {
        status: "running",
        network: {
          eth0: {
            addresses: [
              {
                family: "inet",
                address: "10.12.0.11",
              },
            ],
          },
        },
      },
      config: {
        "user.lizard.stack": "lamp",
      },
    },
    {
      name: "beta-api",
      status: "running",
      type: "container",
      state: {
        status: "running",
        network: {
          eth0: {
            addresses: [
              {
                family: "inet",
                address: "10.12.0.12",
              },
            ],
          },
        },
      },
      config: {
        "user.lizard.stack": "generic",
      },
    },
  ];

  const imagesPayload = {
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
        remote: "images",
        source: "lxd-cli",
      },
    ],
    remotes: ["ubuntu", "images"],
    latest: { ubuntu_lts: "ubuntu:lts" },
    refreshed_at: "2026-02-11T00:00:00Z",
  };

  const server = createServer((req, res) => {
    const url = new URL(req.url || "/", `http://127.0.0.1:${port}`);
    const pathname = url.pathname;
    void (async () => {
      if (pathname === "/status") {
        jsonResponse(res, { status: "ok", containers });
        return;
      }
      if (pathname === "/containers/images/popular" && req.method === "GET") {
        jsonResponse(res, imagesPayload);
        return;
      }
      if (pathname === "/containers/images/popular" && req.method === "POST") {
        await readJsonBody(req);
        jsonResponse(res, { message: "saved" });
        return;
      }
      if (pathname === "/containers/images/popular/remove" && req.method === "POST") {
        await readJsonBody(req);
        jsonResponse(res, { message: "removed" });
        return;
      }
      if (pathname === "/containers/probe" && req.method === "POST") {
        await readJsonBody(req);
        jsonResponse(res, { health_checks: [], detected_services: [] });
        return;
      }
      if (pathname === "/container/create" && req.method === "POST") {
        await readJsonBody(req);
        jsonResponse(res, { message: "Container created" });
        return;
      }
      jsonResponse(res, { error: "not found" }, 404);
    })().catch((err) => {
      jsonResponse(res, { error: err.message || "stub failure" }, 500);
    });
  });

  return new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", () => resolve(server));
    server.on("error", reject);
  });
}

async function launchUiHarness() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fortress-ui-"));
  const adminDb = path.join(tmpDir, "ui_admins.json");
  const adminLog = path.join(tmpDir, "ui_admin_audit.log");
  const apiPort = await getFreePort();
  const uiPort = await getFreePort();
  const apiServer = await startFortressStubApi(apiPort);

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
  return { uiPort, proc, apiServer };
}

async function loginWithDelegatedToken(page) {
  await page.waitForSelector("#auth-overlay", { visible: true });
  await page.type("#auth-token", "user-token:css-regression-session");
  await page.click("#auth-form button[type=\"submit\"]");
  await page.waitForSelector("#auth-overlay", { hidden: true });
  await page.waitForSelector(".app-card[data-node-id=\"containers\"] .card-summary", { visible: true });
}

function sha256(buffer) {
  return createHash("sha256").update(buffer).digest("hex");
}

async function screenshotElement(page, selector) {
  await page.waitForFunction(
    (target) => {
      const el = document.querySelector(target);
      if (!el) {
        return false;
      }
      const rect = el.getBoundingClientRect();
      return rect.width > 8 && rect.height > 8;
    },
    {},
    selector
  );

  for (let attempt = 0; attempt < 4; attempt += 1) {
    const handle = await page.$(selector);
    assert.ok(handle, `Missing screenshot target: ${selector}`);
    try {
      return await handle.screenshot({ type: "png" });
    } catch (err) {
      const message = err && err.message ? String(err.message) : "";
      const retryable =
        message.includes("detached") || message.includes("not visible") || message.includes("not an HTMLElement");
      if (!retryable || attempt === 3) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error(`Unable to capture screenshot for ${selector}`);
}

function loadBaselines() {
  if (!fs.existsSync(BASELINE_FILE)) {
    return {};
  }
  try {
    const raw = fs.readFileSync(BASELINE_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

test("dark surface CSS uses tokenized utility color contract", () => {
  const css = fs.readFileSync(cssPath, "utf8");

  const requiredTokens = [
    "--action-ghost-bg",
    "--action-ghost-border",
    "--action-ghost-fg",
    "--pill-bg",
    "--pill-running-bg",
    "--pill-danger-bg",
    "--event-item-bg",
    "--event-item-error-bg",
    "--event-item-summary",
    "--event-item-pre-bg",
  ];
  for (const token of requiredTokens) {
    assert.match(css, new RegExp(`${token}\\s*:`), `Missing token ${token}`);
  }

  const darkContextMatch = css.match(
    /\.app-card\.expanded\s+\.app-card-frame,\s*\n\.app-card\.expanded\s+\.app-card-tab,\s*\n\.row-more-content,\s*\n\.wizard-stage\s*\{([\s\S]*?)\n\}/
  );
  assert.ok(darkContextMatch, "Dark surface context selector block is missing");
  const darkContextBlock = darkContextMatch ? darkContextMatch[1] : "";
  for (const token of [
    "--action-ghost-bg",
    "--pill-running-bg",
    "--pill-danger-bg",
    "--event-item-bg",
    "--event-item-error-bg",
    "--event-item-pre-bg",
  ]) {
    assert.match(darkContextBlock, new RegExp(`${token}\\s*:`), `Missing dark-context override for ${token}`);
  }

  assert.match(
    css,
    /\.action\.ghost\s*\{[\s\S]*var\(--action-ghost-bg\)[\s\S]*var\(--action-ghost-border\)/,
    "Ghost action must consume tokenized background and border"
  );
  assert.match(css, /\.pill\s*\{[\s\S]*var\(--pill-bg\)/, "Base pill must consume --pill-bg");
  assert.match(css, /\.pill\.running\s*\{[\s\S]*var\(--pill-running-bg\)/, "Running pill must consume token");
  assert.match(css, /\.event-item\s*\{[\s\S]*var\(--event-item-bg\)/, "Event item must consume tokenized background");
  assert.match(css, /\.event-item\.error\s*\{[\s\S]*var\(--event-item-error-bg\)/, "Error event item must consume token");
});

test("dark surface visual regression stays stable for row-more panel and wizard", async (t) => {
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
    await page.setViewport({ width: 1600, height: 980 });
    await page.goto(`http://127.0.0.1:${harness.uiPort}`, { waitUntil: "networkidle0" });
    await page.addStyleTag({
      content: "*,*::before,*::after{animation:none !important;transition:none !important;}",
    });
    await page.addStyleTag({
      content: `
        .app-row,
        .app-card-frame,
        .app-card-tab,
        .row-more-content {
          --unibody-bg-x: 0px !important;
          --unibody-bg-y: 0px !important;
        }
      `,
    });
    await loginWithDelegatedToken(page);

    const expanded = await page.evaluate(() => {
      const summary = document.querySelector('.app-card[data-node-id="containers"] .card-summary');
      if (!summary) {
        return false;
      }
      summary.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      return true;
    });
    assert.equal(expanded, true, "failed to expand containers card");
    await page.waitForSelector("#app-grid .row-more-content", { visible: true });
    await page.waitForFunction(() => {
      const target = document.querySelector("#app-grid .row-more-content");
      return Boolean(target && (target.textContent || "").includes("Fast Actions"));
    });
    await page.waitForFunction(() => {
      const target = document.querySelector("#app-grid .row-more-content");
      if (!target) {
        return false;
      }
      const styles = getComputedStyle(target);
      const bgWidth = Number.parseFloat(styles.getPropertyValue("--unibody-bg-width"));
      const bgX = Number.parseFloat(styles.getPropertyValue("--unibody-bg-x"));
      return Number.isFinite(bgWidth) && bgWidth > 100 && Number.isFinite(bgX);
    });

    const rowMorePng = await screenshotElement(page, "#app-grid .row-more-content");

    const wizardTriggered = await page.evaluate(() => {
      const action = document.querySelector('#app-grid .row-more-content [data-action-id="create-container"]');
      if (!action) {
        return false;
      }
      action.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
      return true;
    });
    assert.equal(wizardTriggered, true, "failed to trigger create-container wizard");
    await page.waitForFunction(() => {
      const stage = document.getElementById("wizard-stage");
      return Boolean(stage && !stage.hidden);
    });
    await page.waitForFunction(() => {
      const wizard = document.getElementById("wizard");
      if (!wizard) {
        return false;
      }
      const text = wizard.textContent || "";
      return text.includes("Selected image") && !text.includes("Checking LXD images");
    });
    await page.waitForFunction(() => {
      const availablePill = document.querySelector("#wizard .event-item .pill.running");
      return Boolean(availablePill && (availablePill.textContent || "").toLowerCase().includes("available"));
    });

    const wizardPng = await screenshotElement(page, "#wizard-stage .wizard-shell");

    const observed = {
      row_more_dark_surface: sha256(rowMorePng),
      wizard_dark_surface: sha256(wizardPng),
    };

    if (UPDATE_BASELINES) {
      fs.mkdirSync(path.dirname(BASELINE_FILE), { recursive: true });
      fs.writeFileSync(BASELINE_FILE, `${JSON.stringify(observed, null, 2)}\n`);
      return;
    }

    const baselines = loadBaselines();
    assert.ok(
      baselines.row_more_dark_surface,
      "Missing row_more_dark_surface baseline. Run with UPDATE_DARK_SURFACE_BASELINES=1."
    );
    assert.ok(
      baselines.wizard_dark_surface,
      "Missing wizard_dark_surface baseline. Run with UPDATE_DARK_SURFACE_BASELINES=1."
    );
    assert.equal(
      observed.row_more_dark_surface,
      baselines.row_more_dark_surface,
      "Row-more dark surface visual regression detected."
    );
    assert.equal(
      observed.wizard_dark_surface,
      baselines.wizard_dark_surface,
      "Wizard dark surface visual regression detected."
    );
  } finally {
    if (browser) {
      await browser.close();
    }
    harness.proc.kill("SIGTERM");
    harness.apiServer.close();
  }
});
