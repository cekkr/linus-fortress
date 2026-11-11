#!/usr/bin/env node
// Capture Lizard UI screenshots for the README / docs.
//
// Spawns ui/server.js against the deterministic demo API in ./demo-api.mjs (never a real
// Fortress API), signs in through the token overlay with a placeholder token, drives the UI
// to each screen, and writes images to docs/screenshots/ (override with --out).
//
//   cd ui && npm run screenshots                     # all shots
//   cd ui && npm run screenshots -- --only deck-home,monitoring
//   cd ui && npm run screenshots -- --out /tmp/shots --format png
//   cd ui && npm run screenshots -- --list
//
// WebP (quality 90) is the default: ~5x smaller than PNG, so regenerating shots does not
// bloat git history. GitHub renders WebP in README files.
//
// Requires the puppeteer dev dependency (npm install downloads Chromium).
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startDemoApi } from "./demo-api.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const UI_DIR = path.resolve(__dirname, "..");
const REPO_DIR = path.resolve(UI_DIR, "..");
const DEFAULT_OUT_DIR = path.join(REPO_DIR, "docs", "screenshots");
const FIXED_CLOCK_ISO = "2026-11-11T09:30:00.000Z";
const DESKTOP = { width: 1440, height: 900, deviceScaleFactor: 1 };
const MOBILE = { width: 390, height: 844, deviceScaleFactor: 2, isMobile: true, hasTouch: true };

function parseArgs(argv) {
  const args = { out: DEFAULT_OUT_DIR, only: null, list: false, offlineFonts: false, format: "webp" };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--out") {
      args.out = path.resolve(argv[++i]);
    } else if (arg === "--only") {
      args.only = new Set(String(argv[++i] || "").split(",").map((s) => s.trim()).filter(Boolean));
    } else if (arg === "--list") {
      args.list = true;
    } else if (arg === "--format") {
      args.format = String(argv[++i] || "").toLowerCase();
      if (!["webp", "png"].includes(args.format)) {
        throw new Error("--format must be webp or png");
      }
    } else if (arg === "--offline-fonts") {
      args.offlineFonts = true;
    } else if (arg === "--help" || arg === "-h") {
      console.log("Usage: capture-screenshots.mjs [--out DIR] [--only a,b] [--format webp|png] [--list] [--offline-fonts]");
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }
  return args;
}

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
    const timeout = setTimeout(() => reject(new Error("UI server did not start")), 15000);
    proc.stdout.on("data", (chunk) => {
      if (chunk.toString().includes("Lizard UI listening")) {
        clearTimeout(timeout);
        resolve();
      }
    });
    proc.on("exit", (code) => reject(new Error(`UI server exited early (${code})`)));
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function settle(page, { idle = 350, extra = 250 } = {}) {
  try {
    await page.waitForNetworkIdle({ idleTime: idle, timeout: 8000 });
  } catch {
    // Long-lived pollers are fine; continue.
  }
  await page.evaluate(async () => {
    if (document.fonts && document.fonts.ready) {
      await document.fonts.ready;
    }
  });
  await page.waitForFunction(
    () => !/loading\.\.\./i.test((document.querySelector("#app-grid")?.textContent || "") + (document.querySelector("#preview")?.textContent || "")),
    { timeout: 6000 }
  ).catch(() => {});
  await sleep(extra);
}

async function closeWizard(page) {
  await page.evaluate(() => {
    // `state` is a top-level const in app.js: reachable as a global binding, not as window.state.
    // eslint-disable-next-line no-undef
    if (state.wizard.active) {
      window.closeWizardState();
      window.renderWizard();
    }
  });
}

async function goHome(page) {
  await closeWizard(page);
  // eslint-disable-next-line no-undef
  await page.evaluate(() => window.selectNode(state.rootId || "home"));
  await settle(page);
}

async function openApp(page, nodeId) {
  await closeWizard(page);
  await page.evaluate((id) => window.selectNode(id), nodeId);
  await page.waitForSelector("#app-grid", { visible: true });
  await settle(page);
}

// Throwaway UI admin for the temp admin store: random per run, never printed or written to the repo.
const DEMO_ADMIN = {
  username: "demo-admin",
  password: `Demo${crypto.randomBytes(9).toString("hex")}A1`,
};

async function bootstrapDemoAdmin(baseUrl) {
  const response = await fetch(`${baseUrl}/api/admin/bootstrap`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(DEMO_ADMIN),
  });
  if (!response.ok) {
    throw new Error(`Admin bootstrap failed (${response.status}): ${await response.text()}`);
  }
}

async function signIn(page, { beforeAdminSubmit } = {}) {
  await page.waitForSelector("#admin-overlay", { visible: true });
  await page.type("#admin-username", DEMO_ADMIN.username);
  if (beforeAdminSubmit) {
    await beforeAdminSubmit();
  }
  await page.type("#admin-password", DEMO_ADMIN.password);
  await page.click('#admin-form button[type="submit"]');
  await page.waitForSelector("#auth-overlay", { visible: true });
  // Placeholder token: the demo API accepts anything and the UI keeps it server-side.
  await page.type("#auth-token", "user-token:demo-screenshots");
  await page.click('#auth-form button[type="submit"]');
  await page.waitForSelector("#auth-overlay", { hidden: true });
  await page.waitForSelector('.app-card[data-node-id="containers"]', { visible: true });
  await settle(page);
}

// Each shot: id (file name), title + caption (README), viewport, prepare(page).
const SHOTS = [
  {
    id: "deck-home",
    title: "Control deck",
    caption: "App deck with the pages tree, fast-actions bar, and the inspector (preview, operation, command log, debug).",
    viewport: DESKTOP,
    prepare: goHome,
  },
  {
    id: "app-card-details",
    title: "App card details",
    caption: "Clicking a card title opens the unibody more-info panel with deep actions.",
    viewport: DESKTOP,
    prepare: async (page) => {
      await goHome(page);
      await page.evaluate(() => window.toggleAppCardDetails("containers"));
      await sleep(900);
      await settle(page);
    },
  },
  {
    id: "containers",
    title: "Containers",
    caption: "Container handles with live status and the LXD image catalog (remote filters, availability).",
    viewport: DESKTOP,
    prepare: (page) => openApp(page, "containers"),
  },
  {
    id: "container-lamp",
    title: "LAMP container",
    caption: "Container sub-apps for a LAMP-tagged container: access, network, packages, recipes, backups, terminal, LAMP services.",
    viewport: DESKTOP,
    prepare: (page) => openApp(page, "container:lamp-shop"),
  },
  {
    id: "create-container-wizard",
    title: "Create-container wizard",
    caption: "Full-stage slide wizard with step breadcrumbs, validation, and keyboard (← / →) navigation.",
    viewport: DESKTOP,
    prepare: async (page) => {
      await openApp(page, "containers");
      await page.evaluate(() => window.openWizard("create-container"));
      await page.waitForSelector("#wiz-name", { visible: true });
      await page.type("#wiz-name", "shop-02");
      await settle(page);
    },
  },
  {
    id: "monitoring",
    title: "Monitoring",
    caption: "Host and container resource metrics with threshold alerts and anomaly flags.",
    viewport: DESKTOP,
    prepare: (page) => openApp(page, "monitoring"),
  },
  {
    id: "routing",
    title: "Domain routing",
    caption: "nginx routes with TLS mode, wildcard domains, and per-route refresh/delete actions.",
    viewport: DESKTOP,
    prepare: (page) => openApp(page, "routing"),
  },
  {
    id: "sites",
    title: "PHP sites",
    caption: "Site lifecycle: runtime, TLS status, database binding, backups and rollback.",
    viewport: DESKTOP,
    prepare: (page) => openApp(page, "sites"),
  },
  {
    id: "recipes",
    title: "Recipes",
    caption: "Versioned install recipes with LAMP health-check trends.",
    viewport: DESKTOP,
    prepare: (page) => openApp(page, "recipes"),
  },
  {
    id: "firewall",
    title: "Firewall",
    caption: "Firewall backend status and rule inventory (ufw/firewalld).",
    viewport: DESKTOP,
    prepare: (page) => openApp(page, "firewall"),
  },
  {
    id: "vms",
    title: "VM labs",
    caption: "QEMU/VirtualBox test VMs with start/stop/snapshot quick controls.",
    viewport: DESKTOP,
    prepare: (page) => openApp(page, "vms"),
  },
  {
    id: "settings",
    title: "Settings",
    caption: "Update + reload, guided system upgrade, and drag-to-reorder fast actions.",
    viewport: DESKTOP,
    prepare: (page) => openApp(page, "settings"),
  },
  {
    id: "mobile-deck",
    title: "Mobile layout",
    caption: "The deck at phone width.",
    viewport: MOBILE,
    prepare: goHome,
  },
];

function screenshotOptions(file, format) {
  return format === "webp" ? { path: file, type: "webp", quality: 90 } : { path: file, type: "png" };
}

async function installDeterministicEnvironment(page) {
  await page.setExtraHTTPHeaders({ "Accept-Language": "en-US,en;q=0.9" });
  await page.emulateTimezone("UTC");
  await page.evaluateOnNewDocument((fixedIso) => {
    const RealDate = Date;
    const offset = new RealDate(fixedIso).valueOf() - RealDate.now();
    class ShiftedDate extends RealDate {
      constructor(...args) {
        if (args.length === 0) {
          super(RealDate.now() + offset);
          return;
        }
        super(...args);
      }
      static now() {
        return RealDate.now() + offset;
      }
    }
    ShiftedDate.parse = RealDate.parse;
    ShiftedDate.UTC = RealDate.UTC;
    globalThis.Date = ShiftedDate;
  }, FIXED_CLOCK_ISO);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.list) {
    console.log(`${"admin-login".padEnd(26)} Admin sign-in overlay`);
    for (const shot of SHOTS) {
      console.log(`${shot.id.padEnd(26)} ${shot.title}`);
    }
    return;
  }
  const selected = SHOTS.filter((shot) => !args.only || args.only.has(shot.id));
  const loginOnly = args.only && args.only.has("admin-login") && !selected.length;
  if (!selected.length && !loginOnly) {
    throw new Error("No shots selected (see --list)");
  }

  let puppeteer;
  try {
    puppeteer = (await import("puppeteer")).default;
  } catch (err) {
    throw new Error(`puppeteer is required (cd ui && npm install): ${err.message}`);
  }

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "lizard-shots-"));
  const apiPort = await getFreePort();
  const uiPort = await getFreePort();
  const api = await startDemoApi(apiPort);
  const proc = spawn(process.execPath, ["server.js"], {
    cwd: UI_DIR,
    env: {
      ...process.env,
      FORTRESS_UI_HOST: "127.0.0.1",
      FORTRESS_UI_PORT: String(uiPort),
      FORTRESS_UI_ADMIN_DB: path.join(tmpDir, "ui_admins.json"),
      FORTRESS_UI_ADMIN_AUDIT_LOG: path.join(tmpDir, "ui_admin_audit.log"),
      FORTRESS_UI_ENV_FILE: path.join(tmpDir, "none.env"),
      FORTRESS_API_URL: `http://127.0.0.1:${apiPort}`,
      FORTRESS_DEBUG: "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let browser;
  try {
    await waitForReady(proc);
    await bootstrapDemoAdmin(`http://127.0.0.1:${uiPort}`);
    fs.mkdirSync(args.out, { recursive: true });
    browser = await puppeteer.launch({
      args: ["--no-sandbox", "--disable-setuid-sandbox", "--force-color-profile=srgb", "--lang=en-US", "--hide-scrollbars"],
    });

    // One page per viewport kind so mobile emulation does not leak into desktop shots.
    const pages = new Map();
    const pageFor = async (viewport) => {
      const key = viewport === MOBILE ? "mobile" : "desktop";
      if (pages.has(key)) {
        return pages.get(key);
      }
      const context = await browser.createBrowserContext();
      const page = await context.newPage();
      await installDeterministicEnvironment(page);
      await page.setViewport(viewport);
      if (args.offlineFonts) {
        await page.setRequestInterception(true);
        page.on("request", (request) => {
          const url = request.url();
          if (url.includes("fonts.googleapis.com") || url.includes("fonts.gstatic.com")) {
            request.abort();
            return;
          }
          request.continue();
        });
      }
      await page.goto(`http://127.0.0.1:${uiPort}`, { waitUntil: "networkidle0" });
      const captureLogin = key === "desktop" && (!args.only || args.only.has("admin-login"));
      await signIn(page, {
        beforeAdminSubmit: captureLogin
          ? async () => {
              const file = path.join(args.out, `admin-login.${args.format}`);
              await page.screenshot(screenshotOptions(file, args.format));
              console.log(`captured ${file}`);
            }
          : null,
      });
      await page.addStyleTag({ content: "*,*::before,*::after{caret-color:transparent !important;}" });
      pages.set(key, page);
      return page;
    };

    if (loginOnly) {
      await pageFor(DESKTOP);
    }
    for (const shot of selected) {
      const page = await pageFor(shot.viewport);
      await shot.prepare(page);
      await page.addStyleTag({ content: "*,*::before,*::after{animation-play-state:paused !important;}" });
      const file = path.join(args.out, `${shot.id}.${args.format}`);
      await page.screenshot(screenshotOptions(file, args.format));
      await page.evaluate(() => {
        for (const style of document.querySelectorAll("style")) {
          if (style.textContent.includes("animation-play-state:paused")) {
            style.remove();
          }
        }
      });
      const kb = Math.round(fs.statSync(file).size / 1024);
      console.log(`captured ${file} (${kb} KB)`);
    }

    if (api.unmatched.size) {
      console.warn(`demo API had no fixture for: ${Array.from(api.unmatched).sort().join(", ")}`);
    }
  } finally {
    if (browser) {
      await browser.close();
    }
    proc.kill("SIGTERM");
    api.server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
