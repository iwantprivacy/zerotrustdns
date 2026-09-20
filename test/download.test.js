import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import { downloadLists, fetchOne } from "../lib/lists.js";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function response(body, status = 200, headers = {}) {
  return new Response(body, { status, headers });
}

describe("download safety", () => {
  it("fails closed when any configured source fails", async () => {
    globalThis.fetch = async (url) => {
      if (url.includes("broken")) return response("not found", 404);
      return response("good.example.com\n", 200, { "content-type": "text/plain" });
    };

    await assert.rejects(
      downloadLists(
        ["https://sources.example/allow?token=hidden"],
        ["https://sources.example/block", "https://sources.example/broken?sig=hidden"]
      ),
      (error) => {
        assert.match(error.message, /Failed to download/);
        assert.doesNotMatch(error.message, /hidden/);
        return true;
      }
    );
  });

  it("clears the timeout after a successful body read", async () => {
    const timers = [];
    const text = await fetchOne("https://sources.example/list", {
      fetchImpl: async () => response("example.com\n"),
      setTimeoutImpl: (handler, ms) => {
        const timer = { handler, ms, cleared: false };
        timers.push(timer);
        return timer;
      },
      clearTimeoutImpl: (timer) => {
        timer.cleared = true;
      },
      sleepImpl: async () => {},
    });

    assert.equal(text, "example.com\n");
    assert.equal(timers.length, 1);
    assert.equal(timers[0].cleared, true);
  });

  it("rejects partial responses and oversized bodies", async () => {
    await assert.rejects(
      fetchOne("https://sources.example/partial", {
        fetchImpl: async () => response("example.com\n", 206),
        sleepImpl: async () => {},
      }),
      /HTTP 206/
    );

    await assert.rejects(
      fetchOne("https://sources.example/large", {
        maxBytes: 3,
        fetchImpl: async () => response("abcd"),
        sleepImpl: async () => {},
      }),
      /response exceeds maximum size/
    );

    await assert.rejects(
      fetchOne("https://sources.example/html-error", {
        fetchImpl: async () => response("<!doctype html><html>error</html>", 200, { "content-type": "text/html" }),
        sleepImpl: async () => {},
      }),
      /unexpected error-document response/
    );

    for (const [body, contentType] of [
      ["<?xml version=\"1.0\"?><error>failed</error>", "text/xml"],
      ["<error>failed</error>", "application/problem+xml"],
      ["{\"error\":true}", "text/plain"],
      ["[\"error\"]", "text/plain"],
    ]) {
      await assert.rejects(
        fetchOne("https://sources.example/document-error", {
          fetchImpl: async () => response(body, 200, { "content-type": contentType }),
          sleepImpl: async () => {},
        }),
        /unexpected error-document response/
      );
    }

    await assert.rejects(
      fetchOne("https://sources.example/truncated", {
        fetchImpl: async () => response("example.com\n", 200, { "content-length": "100" }),
        sleepImpl: async () => {},
      }),
      /response body length mismatch/
    );
  });

  it("enforces aggregate source limits", async () => {
    const fetchImpl = async () => response("example.com\n");
    await assert.rejects(
      downloadLists(
        ["https://sources.example/allow-1", "https://sources.example/allow-2"],
        [],
        { maxSources: 1, fetchImpl, sleepImpl: async () => {} }
      ),
      /source count exceeds maximum/
    );
    await assert.rejects(
      downloadLists(
        ["https://sources.example/allow"],
        [],
        { maxTotalBytes: 1, fetchImpl, sleepImpl: async () => {} }
      ),
      /(?:aggregate allowlist source size exceeds maximum|response exceeds maximum size)/
    );
    await assert.rejects(
      downloadLists(
        ["https://sources.example/allow"],
        ["https://sources.example/block"],
        { maxSources: 1, fetchImpl, sleepImpl: async () => {} }
      ),
      /blocklist source count exceeds maximum/
    );
  });

  it("retries a native transport error exposed through cause.code", async () => {
    let attempts = 0;
    const text = await fetchOne("https://sources.example/retry", {
      fetchImpl: async () => {
        attempts += 1;
        if (attempts === 1) {
          const error = new TypeError("socket reset");
          error.cause = { code: "ECONNRESET" };
          throw error;
        }
        return response("example.com\n");
      },
      sleepImpl: async () => {},
    });

    assert.equal(text, "example.com\n");
    assert.equal(attempts, 2);
  });
});