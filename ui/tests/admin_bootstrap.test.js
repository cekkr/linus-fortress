import { test } from "node:test";
import assert from "node:assert/strict";
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
  return { status: res.statusCode, payload };
}

test("local UI bootstrap works with remote API config and initializes admin store", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fortress-ui-"));
  const adminDb = path.join(tmpDir, "ui_admins.json");
  const adminLog = path.join(tmpDir, "ui_admin_audit.log");
  const port = await getFreePort();

  const env = {
    ...process.env,
    FORTRESS_UI_HOST: "127.0.0.1",
    FORTRESS_UI_PORT: String(port),
    FORTRESS_UI_ADMIN_DB: adminDb,
    FORTRESS_UI_ADMIN_AUDIT_LOG: adminLog,
    FORTRESS_API_URL: "https://example.invalid:8443",
  };

  const proc = spawn("node", ["server.js"], {
    cwd: path.resolve(path.join(__dirname, "..")),
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForReady(proc);
    const baseUrl = `http://127.0.0.1:${port}`;

    const session1 = await fetchJson(`${baseUrl}/api/admin/session`);
    assert.equal(session1.status, 200);
    assert.equal(session1.payload.bootstrap_required, true);
    assert.equal(session1.payload.admin_db, adminDb);
    assert.equal(fs.existsSync(adminDb), true);

    const bootstrapPayload = {
      username: "admin",
      password: "StrongPass1234",
    };
    const bootstrap = await fetchJson(`${baseUrl}/api/admin/bootstrap`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(bootstrapPayload),
    });
    assert.equal(bootstrap.status, 200);

    const session2 = await fetchJson(`${baseUrl}/api/admin/session`);
    assert.equal(session2.status, 200);
    assert.equal(session2.payload.bootstrap_required, false);
  } finally {
    proc.kill("SIGTERM");
  }
});
