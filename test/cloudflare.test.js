import { afterEach, describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  getLists,
  getRules,
  isManagedList,
  isManagedRule,
  isRetryableCloudflareStatus,
  retryAfterMs,
  syncLists,
  upsertRule,
} from "../lib/cloudflare.js";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function jsonResponse(payload, status = 200, headers = {}) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

describe("Cloudflare status and retry helpers", () => {
  it("retries 408/425/429/5xx only — never 401/403/404", () => {
    for (const status of [408, 425, 429, 500, 502, 503, 504]) {
      assert.equal(isRetryableCloudflareStatus(status), true, `expected retry for ${status}`);
    }
    for (const status of [400, 401, 403, 404, 422]) {
      assert.equal(isRetryableCloudflareStatus(status), false, `expected fail-fast for ${status}`);
    }
  });

  it("honors numeric, zero, and HTTP-date Retry-After values", () => {
    assert.equal(retryAfterMs({ headers: new Headers({ "retry-after": "0" }) }), 0);
    assert.equal(retryAfterMs({ headers: new Headers({ "retry-after": "2" }) }), 2000);
    const future = new Date(Date.now() + 5000).toUTCString();
    const parsed = retryAfterMs({ headers: new Headers({ "retry-after": future }) });
    assert.ok(parsed >= 0 && parsed <= 60_000);
  });
});

describe("Cloudflare pagination", () => {
  it("fetches every list page", async () => {
    const calls = [];
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const page = Number(parsed.searchParams.get("page"));
      calls.push({ page, method: options.method ?? "GET" });
      const result = page === 1 ? [{ id: "l1" }] : [{ id: "l2" }];
      return jsonResponse({
        success: true,
        result,
        result_info: { page, per_page: 1, total_count: 2 },
      });
    };

    const { result } = await getLists();
    assert.deepEqual(result.map(({ id }) => id), ["l1", "l2"]);
    assert.deepEqual(calls.map(({ page }) => page), [1, 2]);
  });

  it("fails closed when pagination metadata says items are missing", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return jsonResponse({
        success: true,
        result: calls === 1 ? [{ id: "l1" }] : [],
        result_info: { page: calls, per_page: 1, total_count: 2 },
      });
    };

    await assert.rejects(getLists(), /pagination incomplete/);
  });

  it("accepts a short single-page response when pagination metadata is omitted", async () => {
    globalThis.fetch = async () => jsonResponse({ success: true, result: [{ id: "l1" }] });
    const { result } = await getLists();
    assert.deepEqual(result.map(({ id }) => id), ["l1"]);
  });

  it("fails closed when metadata is omitted at the page-size boundary", async () => {
    const result = Array.from({ length: 1000 }, (_, index) => ({ id: `l${index}` }));
    globalThis.fetch = async () => jsonResponse({ success: true, result });
    await assert.rejects(getLists(), /pagination metadata missing/);
  });

  it("rejects inconsistent page metadata", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return jsonResponse({
        success: true,
        result: [{ id: `l${calls}` }],
        result_info: { page: calls === 1 ? 1 : 3, per_page: 1, total_count: 2 },
      });
    };
    await assert.rejects(getLists(), /pagination metadata mismatch/);
  });

  it("rejects duplicate resource IDs across pages", async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls += 1;
      return jsonResponse({
        success: true,
        result: [{ id: "same-id" }],
        result_info: { page: calls, per_page: 1, total_count: 2 },
      });
    };
    await assert.rejects(getLists(), /duplicate id/);
  });
});

describe("Cloudflare resource ownership", () => {
  it("only treats exact managed names and DOMAIN lists as owned", () => {
    assert.equal(isManagedList({ type: "DOMAIN", name: "zerotrustdns List - Chunk 1" }), true);
    assert.equal(isManagedList({ type: "EMAIL", name: "zerotrustdns List - Chunk 1" }), false);
    assert.equal(isManagedList({ type: "DOMAIN", name: "zerotrustdns List - backup" }), false);
    assert.equal(isManagedRule({ name: "zerotrustdns Filter Lists" }), true);
    assert.equal(isManagedRule({ name: "zerotrustdns Filter Lists - backup" }), false);
  });
});

describe("syncLists", () => {
  it("rejects an over-quota plan before any list mutation", async () => {
    const mutations = [];
    const existing = Array.from({ length: 100 }, (_, index) => ({
      id: `unrelated-${index}`,
      name: `unrelated-${index}`,
      type: "DOMAIN",
    }));
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      if (method !== "GET") mutations.push(method);
      assert.equal(parsed.pathname.endsWith("/lists"), true);
      return jsonResponse({
        success: true,
        result: existing,
        result_info: { page: 1, per_page: 1000, total_count: 100, total_pages: 1 },
      });
    };

    await assert.rejects(syncLists(["new.example.com"]), /quota would be exceeded/);
    assert.deepEqual(mutations, []);
  });

  it("rejects a suspicious large shrink before any list mutation", async () => {
    const existingItems = Array.from({ length: 1000 }, (_, index) => `existing-${index}.example.com`);
    let mutations = 0;
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      if (method !== "GET") mutations += 1;
      if (method === "GET" && parsed.pathname.endsWith("/lists")) {
        return jsonResponse({
          success: true,
          result: [{ id: "l1", name: "zerotrustdns List - Chunk 1", type: "DOMAIN" }],
          result_info: { page: 1, total_count: 1, total_pages: 1 },
        });
      }
      if (method === "GET" && parsed.pathname.endsWith("/items")) {
        return jsonResponse({
          success: true,
          result: existingItems.map((value) => ({ value })),
          result_info: { page: 1, total_count: existingItems.length, total_pages: 1 },
        });
      }
      throw new Error(`unexpected ${method} ${parsed.pathname}`);
    };

    await assert.rejects(syncLists(["only-one.example.com"]), /suspicious domain shrink/);
    assert.equal(mutations, 0);
  });

  it("rejects a suspicious shrink below 1000 existing domains", async () => {
    const existingItems = Array.from({ length: 999 }, (_, index) => `existing-${index}.example.com`);
    let mutations = 0;
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      if (method !== "GET") mutations += 1;
      if (method === "GET" && parsed.pathname.endsWith("/lists")) {
        return jsonResponse({
          success: true,
          result: [{ id: "l1", name: "zerotrustdns List - Chunk 1", type: "DOMAIN" }],
          result_info: { page: 1, per_page: 1000, total_count: 1, total_pages: 1 },
        });
      }
      if (method === "GET" && parsed.pathname.endsWith("/items")) {
        return jsonResponse({
          success: true,
          result: existingItems.map((value) => ({ value })),
          result_info: { page: 1, per_page: 1000, total_count: existingItems.length, total_pages: 1 },
        });
      }
      throw new Error(`unexpected ${method} ${parsed.pathname}`);
    };

    await assert.rejects(syncLists(["only-one.example.com"]), /suspicious domain shrink/);
    assert.equal(mutations, 0);
  });

  it("returns empty managed chunks for deletion without deleting before rule replacement", async () => {
    const calls = [];
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      calls.push({ path: parsed.pathname, method });
      if (method === "GET" && parsed.pathname.endsWith("/lists")) {
        return jsonResponse({
          success: true,
          result: [
            { id: "l1", name: "zerotrustdns List - Chunk 1", type: "DOMAIN" },
            { id: "l2", name: "zerotrustdns List - Chunk 2", type: "DOMAIN" },
          ],
          result_info: { page: 1, per_page: 1000, total_count: 2, total_pages: 1 },
        });
      }
      if (method === "GET" && parsed.pathname.endsWith("/items")) {
        return jsonResponse({
          success: true,
          result: [{ value: parsed.pathname.includes("/l1/") ? "keep.example.com" : "remove.example.com" }],
          result_info: { page: 1, per_page: 1000, total_count: 1, total_pages: 1 },
        });
      }
      throw new Error(`unexpected ${method} ${parsed.pathname}`);
    };

    const result = await syncLists(["keep.example.com"]);
    assert.deepEqual(result.obsoleteLists.map(({ id }) => id), ["l2"]);
    assert.equal(calls.some(({ method }) => method === "PATCH" || method === "DELETE"), false);
  });

  it("paginates list items before computing removals", async () => {
    let items = ["keep.example.com", "stale.example.com"];
    const calls = [];
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      const page = Number(parsed.searchParams.get("page") ?? 1);
      calls.push({ path: parsed.pathname, method, page, body: options.body });
      if (method === "GET" && parsed.pathname.endsWith("/lists")) {
        return jsonResponse({
          success: true,
          result: [{ id: "l1", name: "zerotrustdns List - Chunk 1", type: "DOMAIN" }],
          result_info: { page: 1, per_page: 1000, total_count: 1, total_pages: 1 },
        });
      }
      if (method === "GET" && parsed.pathname.endsWith("/items")) {
        const result = items.slice(page - 1, page);
        return jsonResponse({
          success: true,
          result: result.map((value) => ({ value })),
          result_info: { page, per_page: 1, total_count: items.length, total_pages: items.length },
        });
      }
      if (method === "PATCH") {
        items = ["keep.example.com"];
        return jsonResponse({ success: true, result: {} });
      }
      throw new Error(`unexpected ${method} ${parsed.pathname}`);
    };

    await syncLists(["keep.example.com"]);
    assert.deepEqual(
      calls.filter(({ path, method }) => method === "GET" && path.endsWith("/items")).map(({ page }) => page),
      [1, 2, 1]
    );
    assert.match(calls.find(({ method }) => method === "PATCH").body, /stale\.example\.com/);
  });

  it("fails closed when a provider removes every duplicate occurrence", async () => {
    let items = ["keep.example.com", "keep.example.com"];
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      if (method === "GET" && parsed.pathname.endsWith("/lists")) {
        return jsonResponse({
          success: true,
          result: [{ id: "l1", name: "zerotrustdns List - Chunk 1", type: "DOMAIN" }],
          result_info: { page: 1, total_count: 1, total_pages: 1 },
        });
      }
      if (method === "GET" && parsed.pathname.endsWith("/items")) {
        return jsonResponse({
          success: true,
          result: items.map((value) => ({ value })),
          result_info: { page: 1, total_count: items.length, total_pages: 1 },
        });
      }
      if (method === "PATCH") {
        const body = JSON.parse(options.body);
        items = body.append?.map(({ value }) => value) ?? [];
        return jsonResponse({ success: true, result: {} });
      }
      throw new Error(`unexpected ${method} ${parsed.pathname}`);
    };

    await assert.rejects(syncLists(["keep.example.com"]), /list verification failed/);
  });

  it("fails closed on malformed list-item records", async () => {
    let mutations = 0;
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      if (method !== "GET") mutations += 1;
      if (method === "GET" && parsed.pathname.endsWith("/lists")) {
        return jsonResponse({
          success: true,
          result: [{ id: "l1", name: "zerotrustdns List - Chunk 1", type: "DOMAIN" }],
          result_info: { page: 1, per_page: 1000, total_count: 1, total_pages: 1 },
        });
      }
      if (method === "GET" && parsed.pathname.endsWith("/items")) {
        return jsonResponse({
          success: true,
          result: [{ value: "keep.example.com" }, {}],
          result_info: { page: 1, per_page: 1000, total_count: 2, total_pages: 1 },
        });
      }
      throw new Error(`unexpected ${method} ${parsed.pathname}`);
    };

    await assert.rejects(syncLists(["keep.example.com"]), /Malformed list item/);
    assert.equal(mutations, 0);
  });

  it("attempts compensation when a later list patch fails", async () => {
    const l1Original = [...Array.from({ length: 999 }, (_, index) => `keep1-${index}.example.com`), "old1.example.com"];
    const l2Original = [...Array.from({ length: 999 }, (_, index) => `keep2-${index}.example.com`), "old2.example.com"];
    const items = new Map([
      ["l1", [...l1Original]],
      ["l2", [...l2Original]],
    ]);
    const desired = [
      ...l1Original.slice(0, -1),
      ...l2Original.slice(0, -1),
      "new1.example.com",
      "new2.example.com",
    ];
    const patchBodies = [];
    let patchCount = 0;
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      if (method === "GET" && parsed.pathname.endsWith("/lists")) {
        return jsonResponse({
          success: true,
          result: [
            { id: "l1", name: "zerotrustdns List - Chunk 1", type: "DOMAIN" },
            { id: "l2", name: "zerotrustdns List - Chunk 2", type: "DOMAIN" },
          ],
          result_info: { page: 1, total_count: 2, total_pages: 1 },
        });
      }
      if (method === "GET" && parsed.pathname.endsWith("/items")) {
        const id = parsed.pathname.split("/").at(-2);
        return jsonResponse({
          success: true,
          result: items.get(id).map((value) => ({ value })),
          result_info: { page: 1, total_count: items.get(id).length, total_pages: 1 },
        });
      }
      if (method === "PATCH") {
        patchCount += 1;
        const id = parsed.pathname.split("/").at(-1);
        const body = JSON.parse(options.body);
        patchBodies.push({ id, body });
        if (id === "l2" && patchCount === 2) return jsonResponse({ success: false }, 400);
        const current = items.get(id).filter((value) => !(body.remove ?? []).includes(value));
        items.set(id, [...current, ...(body.append ?? []).map(({ value }) => value)]);
        return jsonResponse({ success: true, result: {} });
      }
      throw new Error(`unexpected ${method} ${parsed.pathname}`);
    };

    await assert.rejects(syncLists(desired), /Cloudflare API error 400/);
    assert.deepEqual(items.get("l1"), l1Original);
    assert.deepEqual(items.get("l2"), l2Original);
    assert.ok(patchBodies.some(({ id, body }) => id === "l1" && body.append?.some(({ value }) => value === "old1.example.com")));
  });

  it("does not retry an ambiguous list-creation POST", async () => {
    let postAttempts = 0;
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      if (method === "GET" && parsed.pathname.endsWith("/lists")) {
        return jsonResponse({ success: true, result: [], result_info: { page: 1, total_count: 0, total_pages: 1 } });
      }
      if (method === "POST" && parsed.pathname.endsWith("/lists")) {
        postAttempts += 1;
        const error = new TypeError("socket reset after server accepted request");
        error.cause = { code: "ECONNRESET" };
        throw error;
      }
      throw new Error(`unexpected ${method} ${parsed.pathname}`);
    };

    await assert.rejects(syncLists(["new.example.com"]), /network error/);
    assert.equal(postAttempts, 1);
  });
});

describe("upsertRule", () => {
  it("updates one canonical rule and removes duplicate exact-name rules", async () => {
    const calls = [];
    let rules = [
      { id: "r1", name: "zerotrustdns Filter Lists" },
      { id: "r2", name: "zerotrustdns Filter Lists" },
    ];
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      calls.push({ path: parsed.pathname, method, body: options.body });
      if (method === "GET") {
        return jsonResponse({
          success: true,
          result: rules,
          result_info: { page: 1, total_count: rules.length, total_pages: 1 },
        });
      }
      if (method === "DELETE") {
        rules = rules.filter(({ id }) => id !== "r2");
        return new Response(null, { status: 204 });
      }
      if (method === "PUT") {
        rules = [
          {
            id: "r1",
            name: "zerotrustdns Filter Lists",
            description: "Managed by zerotrustdns. Do not rename this rule.",
            enabled: true,
            action: "block",
            filters: ["dns"],
            traffic: "(any(dns.domains[*] in $l1))",
            rule_settings: { block_page_enabled: false, block_reason: "Blocked by zerotrustdns." },
          },
        ];
      }
      return jsonResponse({ success: true, result: {} });
    };

    await upsertRule([{ id: "l1" }, { id: "l1" }]);
    assert.deepEqual(
      calls.filter(({ method }) => method !== "GET").map(({ path, method }) => `${method} ${path}`),
      [
        "PUT /client/v4/accounts/undefined/gateway/rules/r1",
        "DELETE /client/v4/accounts/undefined/gateway/rules/r2",
      ]
    );
    assert.match(calls.find(({ method }) => method === "PUT").body, /l1/);
  });

  it("rejects an empty list set instead of creating an ineffective rule", async () => {
    await assert.rejects(upsertRule([]), /without managed lists/);
  });

  it("rejects a read-back rule that does not actually block", async () => {
    let rule = null;
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      if (method === "GET") {
        return jsonResponse({
          success: true,
          result: rule ? [rule] : [],
          result_info: { page: 1, total_count: rule ? 1 : 0, total_pages: 1 },
        });
      }
      if (method === "POST") {
        rule = {
          id: "bad-rule",
          name: "zerotrustdns Filter Lists",
          description: "Managed by zerotrustdns. Do not rename this rule.",
          enabled: false,
          action: "allow",
          filters: ["dns"],
          traffic: "any(dns.domains[*] in $l1)",
          rule_settings: { block_page_enabled: false, block_reason: "Blocked by zerotrustdns." },
        };
        return jsonResponse({ success: true, result: rule });
      }
      throw new Error(`unexpected ${method} ${parsed.pathname}`);
    };

    await assert.rejects(upsertRule([{ id: "l1" }]), /rule verification failed/);
  });

  it("accepts provider-formatted traffic with omitted optional fields", async () => {
    let rule = null;
    globalThis.fetch = async (url, options) => {
      const parsed = new URL(url);
      const method = options.method ?? "GET";
      if (method === "GET") {
        return jsonResponse({
          success: true,
          result: rule ? [rule] : [],
          result_info: { page: 1, total_count: rule ? 1 : 0, total_pages: 1 },
        });
      }
      rule = {
        id: "canonical-rule",
        name: "zerotrustdns Filter Lists",
        enabled: true,
        action: "block",
        filters: ["dns"],
        traffic: "( any ( dns.domains[*] in $l1 ) )",
      };
      return jsonResponse({ success: true, result: rule });
    };

    await upsertRule([{ id: "l1" }]);
  });
});
