import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseItemLimit,
  parseUrlList,
  assertCloudflareEnv,
  DEFAULT_ITEM_LIMIT,
  DEFAULT_BLOCKLIST_URLS,
} from "../lib/config.js";

describe("parseItemLimit", () => {
  it("accepts positive integers", () => {
    assert.equal(parseItemLimit("1000"), 1000);
    assert.equal(parseItemLimit("300000"), 300_000);
  });
  it("falls back on missing/invalid/non-positive input", () => {
    assert.equal(parseItemLimit(undefined), DEFAULT_ITEM_LIMIT);
    assert.equal(parseItemLimit(""), DEFAULT_ITEM_LIMIT);
    assert.equal(parseItemLimit("abc"), DEFAULT_ITEM_LIMIT);
    assert.equal(parseItemLimit("0"), DEFAULT_ITEM_LIMIT);
    assert.equal(parseItemLimit("-5"), DEFAULT_ITEM_LIMIT);
  });
});

describe("parseUrlList", () => {
  it("returns defaults when unset/blank", () => {
    assert.deepEqual(parseUrlList(undefined, DEFAULT_BLOCKLIST_URLS), DEFAULT_BLOCKLIST_URLS);
    assert.deepEqual(parseUrlList("   \n  ", DEFAULT_BLOCKLIST_URLS), DEFAULT_BLOCKLIST_URLS);
  });
  it("splits one-URL-per-line, trims, drops blanks (incl. CRLF)", () => {
    const out = parseUrlList("https://a.example.com/x\r\n\n  https://b.example.com/y  \n", ["fallback"]);
    assert.deepEqual(out, ["https://a.example.com/x", "https://b.example.com/y"]);
  });
  it("drops non-https URLs fail-closed", () => {
    const out = parseUrlList("http://evil.example.com\nfile:///etc/passwd\nhttps://ok.example.com\n", ["fallback"]);
    assert.deepEqual(out, ["https://ok.example.com"]);
  });
  it("throws when explicitly set but nothing valid remains", () => {
    assert.throws(() => parseUrlList("http://only.example.com\n", ["fallback"]), /No valid https/);
  });
});

describe("assertCloudflareEnv", () => {
  it("passes with both vars present, without exposing values", () => {
    const out = assertCloudflareEnv({ CLOUDFLARE_API_TOKEN: "t", CLOUDFLARE_ACCOUNT_ID: "a" });
    assert.deepEqual(out, { token: "t", accountId: "a" });
  });
  it("throws fail-closed when either var is missing", () => {
    assert.throws(() => assertCloudflareEnv({}), /Missing required env vars/);
    assert.throws(() => assertCloudflareEnv({ CLOUDFLARE_API_TOKEN: "t" }), /Missing required env vars/);
    assert.throws(() => assertCloudflareEnv({ CLOUDFLARE_ACCOUNT_ID: "a" }), /Missing required env vars/);
  });
});
