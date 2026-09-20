import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseArgs } from "../lib/cli.js";
import { main } from "../index.js";

describe("parseArgs", () => {
  it("accepts the supported modes", () => {
    assert.deepEqual(parseArgs([]), { isDryRun: false, isDelete: false });
    assert.deepEqual(parseArgs(["--dry"]), { isDryRun: true, isDelete: false });
    assert.deepEqual(parseArgs(["--delete"]), { isDryRun: false, isDelete: true });
  });

  it("rejects conflicting or unknown options", () => {
    assert.throws(() => parseArgs(["--dry", "--delete"]), /cannot be used together/);
    assert.throws(() => parseArgs(["--delte"]), /Unknown option/);
  });

  it("rejects conflicting modes before any network access", async () => {
    let fetchCalls = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      fetchCalls += 1;
      throw new Error("network should not be reached");
    };
    try {
      await assert.rejects(main(["--dry", "--delete"]), /cannot be used together/);
      assert.equal(fetchCalls, 0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});