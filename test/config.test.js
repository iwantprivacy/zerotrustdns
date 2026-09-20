import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseItemLimit,
  parseRatio,
  parseUrlList,
  assertCloudflareEnv,
  DEFAULT_ITEM_LIMIT,
  DEFAULT_LIST_ACCOUNT_LIMIT,
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
    assert.equal(parseItemLimit("2junk"), DEFAULT_ITEM_LIMIT);
    assert.equal(parseItemLimit("1.5"), DEFAULT_ITEM_LIMIT);
    assert.equal(parseItemLimit("1e3"), DEFAULT_ITEM_LIMIT);
  });
});

describe("quota defaults", () => {
  it("stay within the documented Standard list capacity", () => {
    assert.equal(DEFAULT_LIST_ACCOUNT_LIMIT, 100);
    assert.equal(DEFAULT_ITEM_LIMIT, 100_000);
  });
});

describe("parseRatio", () => {
  it("accepts values from 0 through 1 and falls back otherwise", () => {
    assert.equal(parseRatio("0"), 0);
    assert.equal(parseRatio("0.5"), 0.5);
    assert.equal(parseRatio("1"), 1);
    assert.equal(parseRatio("2"), 0.5);
    assert.equal(parseRatio("-1"), 0.5);
    assert.equal(parseRatio("not-a-ratio"), 0.5);
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
  it("rejects non-https and credential-bearing URLs", () => {
    assert.throws(
      () => parseUrlList("http://evil.example.com\nhttps://ok.example.com\n", ["fallback"]),
      /Only valid https URLs are allowed/
    );
    assert.throws(
      () => parseUrlList("https://user:pass@example.com/list\n", ["fallback"]),
      /No valid https URLs found/
    );
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
