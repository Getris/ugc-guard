import assert from "node:assert/strict";
import test from "node:test";
import { createGuard, HtmlRule } from "../dist/index.js";
import { createExpressMiddleware } from "../dist/adapters/express.js";
import { createFastifyPreHandler } from "../dist/adapters/fastify.js";

function expressResponse() {
  return {
    statusCode: 200,
    payload: undefined,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.payload = payload; return payload; }
  };
}

test("Express adapter normalizes accepted content", async () => {
  const request = { body: { text: "  hello   world  " }, user: { id: "u1" } };
  const response = expressResponse();
  let nextCalled = false;
  const middleware = createExpressMiddleware(createGuard());
  await middleware(request, response, () => { nextCalled = true; });
  assert.equal(nextCalled, true);
  assert.equal(request.body.text, "hello world");
  assert.equal(request.ugcGuard?.decision, "allow");
});

test("Express adapter does not expose findings by default", async () => {
  const request = { body: { text: "<script>alert(1)</script>" } };
  const response = expressResponse();
  const middleware = createExpressMiddleware(createGuard({ rules: [new HtmlRule()] }));
  await middleware(request, response, () => {});
  assert.equal(response.statusCode, 422);
  assert.equal(Object.hasOwn(response.payload, "findings"), false);
});

test("Express adapter can expose findings explicitly", async () => {
  const request = { body: { text: "<script>alert(1)</script>" } };
  const response = expressResponse();
  const middleware = createExpressMiddleware(createGuard({ rules: [new HtmlRule()] }), { exposeFindings: true });
  await middleware(request, response, () => {});
  assert.equal(Array.isArray(response.payload.findings), true);
});

test("Fastify adapter validates request body", async () => {
  const reply = {
    statusCode: 200,
    payload: undefined,
    code(code) { this.statusCode = code; return this; },
    send(payload) { this.payload = payload; return payload; }
  };
  const handler = createFastifyPreHandler(createGuard());
  await handler({ body: null }, reply);
  assert.equal(reply.statusCode, 400);
  assert.equal(reply.payload.error, "INVALID_REQUEST_BODY");
});
