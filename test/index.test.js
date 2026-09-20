import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { main } from "../index.js";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
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
