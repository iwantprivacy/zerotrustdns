import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  parseDomains,
  normalizeDomain,
  isValidDomain,
  isComment,
  isRetryableDownloadStatus,
} from "../lib/lists.js";

describe("isValidDomain", () => {
  it("accepts normal domains", () => {
    assert.equal(isValidDomain("example.com"), true);
    assert.equal(isValidDomain("sub.example.co.uk"), true);
    assert.equal(isValidDomain("xn--e1afmkfd.example.vn"), true);
    assert.equal(isValidDomain("103.179.189.35"), false);
  });
  it("rejects garbage", () => {
    assert.equal(isValidDomain(""), false);
    assert.equal(isValidDomain("localhost"), false);
    assert.equal(isValidDomain("-bad.com"), false);
    assert.equal(isValidDomain("bad..com"), false);
    assert.equal(isValidDomain("has space.com"), false);
    assert.equal(isValidDomain("UPPER.COM"), true);
    assert.equal(isValidDomain("example.xn--p1ai"), true);
  });
});

describe("isComment", () => {
  it("detects comment prefixes", () => {
    assert.equal(isComment("# hosts file"), true);
    assert.equal(isComment("! adblock title"), true);
    assert.equal(isComment("// comment"), true);
    assert.equal(isComment("/* block */"), true);
    assert.equal(isComment("example.com"), false);
  });
});

describe("normalizeDomain", () => {
  it("strips hosts-file prefixes", () => {
    assert.equal(normalizeDomain("0.0.0.0 ads.example.com"), "ads.example.com");
    assert.equal(normalizeDomain("127.0.0.1 tracker.example.com"), "tracker.example.com");
    assert.equal(normalizeDomain("a.example.com/path"), "");
  });
  it("strips adblock syntax and wildcards", () => {
    assert.equal(normalizeDomain("||ads.example.com^"), "ads.example.com");
    assert.equal(normalizeDomain("||ads.example.com^$third-party"), "ads.example.com");
    assert.equal(normalizeDomain("||ads.example.com$important"), "ads.example.com");
    assert.equal(normalizeDomain("*.ads.example.com"), "ads.example.com");
  });
  it("strips @@|| allowlist exceptions", () => {
    assert.equal(normalizeDomain("@@||good.example.com^", true), "good.example.com");
  });
  it("canonicalizes case, trailing dots, and Unicode IDNs", () => {
    assert.equal(normalizeDomain("ADS.Example.COM."), "ads.example.com");
    assert.equal(normalizeDomain("пример.рф"), "xn--e1afmkfd.xn--p1ai");
  });
});

describe("parseDomains", () => {
  it("dedupes and skips comments/invalid lines", () => {
    const out = parseDomains("# title\n! comment\nads.example.com\nads.example.com\nnot a domain\n", "", 100);
    assert.deepEqual(out, ["ads.example.com"]);
  });
  it("parses hosts + adblock formats", () => {
    const out = parseDomains(
      "103.179.189.35 a.example.com b.example.com # inline comment\n||c.example.com$important\n*.d.example.com\n",
      "",
      100
    );
    assert.deepEqual(out, ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]);
  });
  it("excludes allowlisted domains", () => {
    const out = parseDomains("good.example.com\nbad.example.com\n", "good.example.com\n", 100);
    assert.deepEqual(out, ["bad.example.com"]);
  });
  it("collapses subdomains when the parent is blocked or allowlisted", () => {
    const blocked = parseDomains("example.com\nsub.example.com\n", "", 100);
    assert.deepEqual(blocked, ["example.com"]);
    const allowed = parseDomains("sub.example.com\nother.example.com\n", "sub.example.com\n", 100);
    assert.deepEqual(allowed, ["other.example.com"]);
  });
  it("collapses parents independently of input order", () => {
    const parentFirst = parseDomains("example.com\nsub.example.com\n", "", 100);
    const childFirst = parseDomains("sub.example.com\nexample.com\n", "", 100);
    assert.deepEqual(childFirst, parentFirst);
  });
  it("lets a descendant allowlist protect against an ancestor block", () => {
    const out = parseDomains("example.com\ngood.example.com\nbad.example.com\n", "good.example.com\n", 100);
    assert.deepEqual(out, ["bad.example.com"]);
  });
  it("respects the item limit", () => {
    const out = parseDomains("a.example.com\nb.example.com\nc.example.com\n", "", 2);
    assert.deepEqual(out, ["a.example.com", "b.example.com"]);
    assert.equal(out.truncated, true);
  });
});

describe("isRetryableDownloadStatus", () => {
  it("retries 408/425/429/5xx only", () => {
    for (const s of [408, 425, 429, 500, 502, 503, 504, 599]) {
      assert.equal(isRetryableDownloadStatus(s), true, `expected retry for ${s}`);
    }
    for (const s of [200, 400, 401, 403, 404, 422, 301]) {
      assert.equal(isRetryableDownloadStatus(s), false, `expected no retry for ${s}`);
    }
  });
});
