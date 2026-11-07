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
      if (chunk.toString().includes("Lizard UI listening")) {
        clearTimeout(timeout);
        resolve();
      }
    });
    proc.on("error", reject);
  });
}

function cookieHeader(...setCookies) {
  return setCookies
    .flat()
    .filter(Boolean)
    .map((value) => value.split(";")[0])
    .join("; ");
}

test("proxied path params are URI-encoded before reaching the Fortress API", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fortress-ui-enc-"));
  const apiPort = await getFreePort();
  const uiPort = await getFreePort();
  const seen = [];
  const apiServer = createServer((req, res) => {
    seen.push(req.url);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(req.url === "/status" ? { status: "ok", containers: "[]" } : { ok: true }));
  });
  await new Promise((resolve) => apiServer.listen(apiPort, "127.0.0.1", resolve));

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

  try {
    await waitForReady(proc);
    const baseUrl = `http://127.0.0.1:${uiPort}`;
    const json = { "Content-Type": "application/json" };
    await request(`${baseUrl}/api/admin/bootstrap`, {
      method: "POST",
      headers: json,
      body: JSON.stringify({ username: "admin", password: "StrongPass1234" }),
    }).then((r) => r.body.text());
    const login = await request(`${baseUrl}/api/admin/login`, {
      method: "POST",
      headers: json,
      body: JSON.stringify({ username: "admin", password: "StrongPass1234" }),
    });
    await login.body.text();
    const adminCookie = login.headers["set-cookie"];
    const session = await request(`${baseUrl}/api/session`, {
      method: "POST",
      headers: { ...json, Cookie: cookieHeader(adminCookie) },
      body: JSON.stringify({ token: "demo-token" }),
    });
    await session.body.text();
    assert.equal(session.statusCode, 200);
    const cookies = cookieHeader(adminCookie, session.headers["set-cookie"]);

    const cases = [
      ["GET", "/api/sites/a%2Fb%3Fx%3D1", "/sites/a%2Fb%3Fx%3D1"],
      ["GET", "/api/containers/web%20one/logs", "/containers/web%20one/logs"],
      ["DELETE", "/api/routing/%2A.example.com%23frag", "/routing/*.example.com%23frag"],
      ["GET", "/api/vms/vm%2F..%2Fadmin", "/vms/vm%2F..%2Fadmin"],
    ];
    for (const [method, uiPath, expected] of cases) {
      seen.length = 0;
      const res = await request(`${baseUrl}${uiPath}`, { method, headers: { Cookie: cookies } });
      await res.body.text();
      assert.equal(res.statusCode, 200, `${method} ${uiPath}`);
      assert.deepEqual(seen, [expected], `${method} ${uiPath}`);
    }
  } finally {
    proc.kill("SIGTERM");
    apiServer.close();
  }
});
