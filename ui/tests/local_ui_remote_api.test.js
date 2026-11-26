import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import net from "node:net";
import { request } from "undici";
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
    const timeout = setTimeout(() => reject(new Error("UI server did not start")), 8000);
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

async function fetchJson(url, options = {}) {
  const res = await request(url, options);
  const text = await res.body.text();
  const payload = text ? JSON.parse(text) : null;
  return { status: res.statusCode, payload, headers: res.headers };
}

function startStubApi(port) {
  let statusRequests = 0;
  const server = createServer((req, res) => {
    if (req.url === "/status") {
      statusRequests += 1;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({
        status: "ok", containers: [],
        credential: {
          type: "delegated", expires_at: statusRequests === 1 ? "2099-01-01T00:00:00Z" : "2099-02-01T00:00:00Z",
          can_list_tokens: true, token: "unexpected-upstream-secret",
        },
      }));
      return;
    }
    if (req.url === "/api-users?expiry_summary=true") {
      if (req.headers["x-user-token"] !== "demo-token") {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ detail: "Permission denied" }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ users: [{
        username: "expired-fixture", token_hint: "exam...mple", expired: true,
        expires_at: "2001-01-01T00:00:00Z", token: "unexpected-upstream-secret",
      }] }));
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

test("local UI + remote API config allows admin bootstrap and delegated session", async () => {
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

  try {
    await waitForReady(proc);
    const baseUrl = `http://127.0.0.1:${uiPort}`;

    const session1 = await fetchJson(`${baseUrl}/api/admin/session`);
    assert.equal(session1.status, 200);
    assert.equal(session1.payload.bootstrap_required, true);
    assert.equal(session1.payload.admin_db, adminDb);
    assert.equal(fs.existsSync(adminDb), true);

    const bootstrap = await fetchJson(`${baseUrl}/api/admin/bootstrap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "StrongPass1234" }),
    });
    assert.equal(bootstrap.status, 200);

    const session2 = await fetchJson(`${baseUrl}/api/admin/session`);
    assert.equal(session2.status, 200);
    assert.equal(session2.payload.bootstrap_required, false);

    const login = await fetchJson(`${baseUrl}/api/admin/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "admin", password: "StrongPass1234" }),
    });
    assert.equal(login.status, 200);
    const adminCookie = login.headers["set-cookie"];
    assert.ok(adminCookie);

    const tokenResp = await fetchJson(`${baseUrl}/api/session`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: Array.isArray(adminCookie) ? adminCookie.join("; ") : adminCookie,
      },
      body: JSON.stringify({ token: "demo-token" }),
    });
    assert.equal(tokenResp.status, 200);

    const adminSession = Array.isArray(adminCookie) ? adminCookie[0] : adminCookie;
    const sessionCookie = tokenResp.headers["set-cookie"];
    const tokenSession = Array.isArray(sessionCookie) ? sessionCookie[0] : sessionCookie;
    const headers = { Cookie: [adminSession, tokenSession].map((cookie) => cookie.split(";")[0]).join("; ") };
    const session = await fetchJson(`${baseUrl}/api/session`, { headers });
    assert.deepEqual(session.payload.credential, {
      type: "delegated", expires_at: "2099-01-01T00:00:00.000Z", can_list_tokens: true,
    });
    const apps = await fetchJson(`${baseUrl}/api/apps`, { headers });
    assert.equal(apps.payload.credential.expires_at, "2099-02-01T00:00:00.000Z");
    const refreshed = await fetchJson(`${baseUrl}/api/session`, { headers });
    assert.deepEqual(refreshed.payload.credential, apps.payload.credential);

    const inventory = await fetchJson(`${baseUrl}/api/tokens/expiry`, { headers });
    assert.equal(inventory.status, 200);
    assert.deepEqual(inventory.payload.users, [{
      username: "expired-fixture", token_hint: "exam...mple", expires_at: "2001-01-01T00:00:00.000Z", expired: true,
    }]);
    const denied = await fetchJson(`${baseUrl}/api/tokens/expiry`, { headers: { Cookie: adminSession.split(";")[0] } });
    assert.equal(denied.status, 403);
  } finally {
    proc.kill("SIGTERM");
    apiServer.close();
  }
});
