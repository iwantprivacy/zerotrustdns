import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { main, parseArgs } from "../index.js";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

describe("CLI parsing", () => {
  it("accepts the supported modes", () => {
    assert.deepEqual(parseArgs([]), { isDryRun: false });
    assert.deepEqual(parseArgs(["--dry"]), { isDryRun: true });
  });

  it("rejects unknown options", () => {
    assert.throws(() => parseArgs(["--delte"]), /Unknown option/);
    assert.throws(() => parseArgs(["--delete"]), /Unknown option/);
  });

  it("rejects unknown options before any network access", async () => {
    let fetchCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls += 1;
      throw new Error("network should not be reached");
    };
    await assert.rejects(main(["--delete"]), /Unknown option/);
    assert.equal(fetchCalls, 0);
  });
});

describe("main orchestration", () => {
  it("keeps dry-run completely outside the Cloudflare API", async () => {
    let cloudflareCalls = 0;
    globalThis.fetch = async (url) => {
      if (String(url).includes("api.cloudflare.com")) {
        cloudflareCalls += 1;
        throw new Error("Cloudflare API must not be called during dry-run");
      }
      const text = String(url).includes("exclusions")
        ? "allow.example.net\n"
        : "0.0.0.0 ads.example.com\n";
      return new Response(text, { status: 200, headers: { "content-type": "text/plain" } });
    };

    await main(["--dry"]);
    assert.equal(cloudflareCalls, 0);
  });

  it("fails credential validation before any network access", async () => {
    const originalToken = process.env.CLOUDFLARE_API_TOKEN;
    const originalAccount = process.env.CLOUDFLARE_ACCOUNT_ID;
    delete process.env.CLOUDFLARE_API_TOKEN;
    delete process.env.CLOUDFLARE_ACCOUNT_ID;
    let networkCalls = 0;
    globalThis.fetch = async () => {
      networkCalls += 1;
      throw new Error("network must not be reached");
    };

    try {
      await assert.rejects(main([]), /Missing required env vars/);
      assert.equal(networkCalls, 0);
    } finally {
      if (originalToken === undefined) delete process.env.CLOUDFLARE_API_TOKEN;
      else process.env.CLOUDFLARE_API_TOKEN = originalToken;
      if (originalAccount === undefined) delete process.env.CLOUDFLARE_ACCOUNT_ID;
      else process.env.CLOUDFLARE_ACCOUNT_ID = originalAccount;
    }
  });
});
