import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
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

function jsonResponse(res, payload, status = 200) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

function startLxdLikeApi(port) {
  const lxdExtensions = Array.from({ length: 28 }, (_, index) => `ext-${index + 1}`);
  const server = createServer((req, res) => {
    const url = new URL(req.url || "/", `http://127.0.0.1:${port}`);
    if (url.pathname === "/status") {
      jsonResponse(res, { error: "not found" }, 404);
      return;
    }
    if (url.pathname === "/1.0") {
      jsonResponse(res, {
        type: "sync",
        status: "Success",
        status_code: 200,
        metadata: {
          api_extensions: lxdExtensions,
          server_name: "lxd",
        },
      });
      return;
    }
    jsonResponse(res, { error: "not found" }, 404);
  });
  return new Promise((resolve, reject) => {
    server.listen(port, "127.0.0.1", () => resolve(server));
    server.on("error", reject);
  });
}

async function fetchJson(url, options = {}) {
  const res = await request(url, options);
  const text = await res.body.text();
  return {
    status: res.statusCode,
    payload: text ? JSON.parse(text) : null,
  };
}

test("apps endpoint reports LXD identity hint when API URL points to LXD daemon", async () => {
  const apiPort = await getFreePort();
  const uiPort = await getFreePort();
  const apiServer = await startLxdLikeApi(apiPort);

  const env = {
    ...process.env,
    FORTRESS_UI_HOST: "127.0.0.1",
    FORTRESS_UI_PORT: String(uiPort),
    FORTRESS_UI_ADMIN_ENABLED: "0",
    FORTRESS_UI_API_KEY: "integration-key",
    FORTRESS_API_URL: `http://127.0.0.1:${apiPort}`,
  };

  const proc = spawn("node", ["server.js"], {
    cwd: path.resolve(path.join(__dirname, "..")),
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  try {
    await waitForReady(proc);
    const response = await fetchJson(`http://127.0.0.1:${uiPort}/api/apps`);
    assert.equal(response.status, 200);
    assert.equal(response.payload.fortress.status, "error");
    assert.match(response.payload.fortress.error, /LXD daemon/i);
    assert.match(response.payload.fortress.error, /FORTRESS_API_URL/i);
    assert.match(response.payload.fortress.error, /:8443/i);
  } finally {
    proc.kill("SIGTERM");
    apiServer.close();
  }
});
