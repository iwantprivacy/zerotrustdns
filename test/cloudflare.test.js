import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { isRetryableCloudflareStatus } from "../lib/cloudflare.js";

describe("isRetryableCloudflareStatus", () => {
  it("retries 408/425/429/5xx only — never 401/403/404", () => {
    for (const s of [408, 425, 429, 500, 502, 503, 504]) {
      assert.equal(isRetryableCloudflareStatus(s), true, `expected retry for ${s}`);
    }
    for (const s of [400, 401, 403, 404, 422]) {
      assert.equal(isRetryableCloudflareStatus(s), false, `expected fail-fast for ${s}`);
    }
  });
});
