import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { DemoController } from "./api/demo-controller.js";
import { buildDeterministicDemoSequence } from "./core/index.js";
import { projectCheck, projectIssue } from "./github/projections.js";
import { publishWithInstallation } from "./github/publisher.js";
import { triggerFromPush, verifyWebhookSignature } from "./github/webhook.js";

const controller = new DemoController();
const port = Number.parseInt(process.env.PORT ?? "4317", 10);
const publicDirectory = resolve(process.env.AFTERSHOCK_PUBLIC_DIR ?? "public");
const publicAssets = new Map([
  ["/", { file: "index.html", type: "text/html; charset=utf-8" }],
  ["/styles.css", { file: "styles.css", type: "text/css; charset=utf-8" }],
  ["/app.js", { file: "app.js", type: "text/javascript; charset=utf-8" }],
]);

function sendJson(response: ServerResponse, status: number, value: unknown): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
  });
  response.end(JSON.stringify(value, null, 2));
}

async function readBody(request: IncomingMessage, limit = 1_048_576): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += bytes.byteLength;
    if (size > limit) throw new Error("request_body_too_large");
    chunks.push(bytes);
  }
  return Buffer.concat(chunks);
}

function installationIdFrom(payload: unknown): number | null {
  if (!payload || typeof payload !== "object") return null;
  const installation = (payload as Record<string, unknown>).installation;
  if (!installation || typeof installation !== "object") return null;
  const id = (installation as Record<string, unknown>).id;
  return typeof id === "number" && Number.isSafeInteger(id) && id > 0 ? id : null;
}

async function route(request: IncomingMessage, response: ServerResponse): Promise<void> {
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
  if (request.method === "OPTIONS") {
    response.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type",
    });
    response.end();
    return;
  }
  if (request.method === "GET" && publicAssets.has(url.pathname)) {
    const asset = publicAssets.get(url.pathname)!;
    try {
      const bytes = await readFile(resolve(publicDirectory, asset.file));
      response.writeHead(200, {
        "content-type": asset.type,
        "cache-control": "no-store",
        "content-security-policy": "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      });
      response.end(bytes);
    } catch (error) {
      const missing = error instanceof Error && "code" in error && error.code === "ENOENT";
      sendJson(response, missing ? 404 : 500, { error: missing ? "ui_asset_not_found" : "ui_asset_read_failed" });
    }
    return;
  }
  if (request.method === "GET" && url.pathname === "/health") {
    sendJson(response, 200, { ok: true, service: "aftershock" });
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/view") {
    sendJson(response, 200, controller.view());
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/github/projection") {
    const view = controller.view();
    sendJson(response, 200, { check: projectCheck(view), issue: projectIssue(view) });
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/core/sequence") {
    sendJson(response, 200, buildDeterministicDemoSequence());
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/feasibility/receipt") {
    const path = resolve(process.env.AFTERSHOCK_RECEIPT_PATH ?? "artifacts/feasibility/apm-wasmer-receipt.json");
    try {
      sendJson(response, 200, JSON.parse(await readFile(path, "utf8")));
    } catch (error) {
      const missing = error instanceof Error && "code" in error && error.code === "ENOENT";
      sendJson(response, missing ? 404 : 500, { error: missing ? "receipt_not_found" : "invalid_receipt" });
    }
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/demo/reset") {
    sendJson(response, 200, controller.reset());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/demo/advance") {
    sendJson(response, 200, controller.advance());
    return;
  }
  if (request.method === "POST" && url.pathname === "/api/github/webhook") {
    const secret = process.env.GITHUB_WEBHOOK_SECRET ?? "";
    if (!secret) {
      sendJson(response, 503, { error: "github_webhook_not_configured" });
      return;
    }
    const body = await readBody(request);
    const signature = request.headers["x-hub-signature-256"];
    if (!verifyWebhookSignature(body, Array.isArray(signature) ? signature[0] : signature, secret)) {
      sendJson(response, 401, { error: "invalid_webhook_signature" });
      return;
    }
    if (request.headers["x-github-event"] !== "push") {
      sendJson(response, 202, { accepted: true, ignored: "event_not_used_by_demo" });
      return;
    }
    let payload: unknown;
    try {
      payload = JSON.parse(body.toString("utf8"));
    } catch {
      sendJson(response, 400, { error: "invalid_json" });
      return;
    }
    const trigger = triggerFromPush(payload);
    if (!trigger) {
      sendJson(response, 422, { error: "invalid_push_payload" });
      return;
    }
    const view = controller.invalidateForHead(trigger.headSha);
    const installationId = installationIdFrom(payload);
    const published = process.env.AFTERSHOCK_PUBLISH_GITHUB === "1" && installationId
      ? await publishWithInstallation(installationId, view)
      : null;
    sendJson(response, 202, { accepted: true, trigger, view, published });
    return;
  }
  if (request.method === "GET" && url.pathname === "/api/events") {
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
      "access-control-allow-origin": "*",
    });
    const emit = (value: unknown) => response.write(`event: view\ndata: ${JSON.stringify(value)}\n\n`);
    emit(controller.view());
    controller.on("view", emit);
    request.on("close", () => controller.off("view", emit));
    return;
  }
  sendJson(response, 404, { error: "not_found" });
}

const server = createServer((request, response) => {
  void route(request, response).catch((error: unknown) => {
    if (!response.headersSent) {
      sendJson(response, error instanceof Error && error.message === "request_body_too_large" ? 413 : 500, {
        error: error instanceof Error ? error.message : "internal_error",
      });
    } else {
      response.end();
    }
  });
});
server.listen(port, "127.0.0.1", () => {
  console.log(`Aftershock demo API listening on http://127.0.0.1:${port}`);
});
