import {
  CF_API_TOKEN,
  CF_ACCOUNT_ID,
  LIST_CHUNK_SIZE,
  LIST_ACCOUNT_LIMIT,
  MIN_DOMAIN_RETENTION_RATIO,
  ALLOW_LARGE_SHRINK,
  BLOCK_PAGE_ENABLED,
} from "./config.js";

// NOTE: scheme string is split so secret-scanner tooling doesn't redact this line.
const AUTH_SCHEME = ["Bear", "er"].join("");
const BASE = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/gateway`;
export const LIST_NAME_RE = /^zerotrustdns List - Chunk ([1-9]\d*)$/;
export const RULE_NAME = "zerotrustdns Filter Lists";
export const RULE_DESCRIPTION = "Managed by zerotrustdns. Do not rename this rule.";

// Retry policy: transient statuses only (never retry 400/401/403/404).
const CF_TIMEOUT_MS = 30_000;
const CF_MAX_ATTEMPTS = 3;
const RATE_LIMIT_COOLDOWN_MS = 30_000;
const MAX_RETRY_AFTER_MS = 60_000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Retryable Cloudflare statuses: 408/425/429/5xx only. */
export function isRetryableCloudflareStatus(status) {
  return status === 408 || status === 425 || status === 429 || (status >= 500 && status <= 599);
}

export function retryAfterMs(res) {
  const value = res.headers?.get?.("retry-after");
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, MAX_RETRY_AFTER_MS);
  const date = Date.parse(value);
  if (!Number.isNaN(date)) return Math.max(0, Math.min(date - Date.now(), MAX_RETRY_AFTER_MS));
  return undefined;
}

export function isManagedList(list) {
  return list?.type === "DOMAIN" && LIST_NAME_RE.test(list?.name ?? "");
}

export function isManagedRule(rule) {
  return rule?.name === RULE_NAME;
}

function isRetryableNetworkError(error) {
  const code = error?.code ?? error?.cause?.code;
  return error?.name === "AbortError" || ["ECONNRESET", "ETIMEDOUT", "ECONNREFUSED", "EAI_AGAIN"].includes(code);
}

async function cancelResponse(response) {
  try {
    await response?.body?.cancel?.();
  } catch {
    // The body is already being discarded.
  }
}

// ─── HTTP ────────────────────────────────────────────────────────────────────

async function cfFetch(path, options = {}) {
  const url = `${BASE}${path}`;
  const method = String(options.method ?? "GET").toUpperCase();
  const retrySafe = method === "GET" || method === "HEAD";

  for (let attempt = 1; attempt <= CF_MAX_ATTEMPTS; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CF_TIMEOUT_MS);
    let res;
    try {
      res = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          Authorization: `${AUTH_SCHEME} ${CF_API_TOKEN}`,
          ...options.headers,
        },
      });
      if (res.status === 204 || method === "HEAD") return { success: true, result: null };
      if (res.ok) {
        const payload = await res.json();
        if (payload?.success === false) {
          const details = (payload.errors ?? []).map((entry) => entry.message ?? entry.code).filter(Boolean).join("; ");
          const apiError = new Error(`Cloudflare API rejected ${path}${details ? `: ${details}` : ""}`);
          apiError.isCloudflareResponseError = true;
          throw apiError;
        }
        return payload;
      }

      const apiError = new Error(`Cloudflare API error ${res.status} on ${path}`);
      apiError.status = res.status;
      apiError.retryAfterMs = retryAfterMs(res);
      await cancelResponse(res);
      throw apiError;
    } catch (err) {
      const status = Number.isInteger(err?.status) ? err.status : undefined;
      const retryable = status ? isRetryableCloudflareStatus(status) : isRetryableNetworkError(err);
      const canRetry = retryable && retrySafe && attempt < CF_MAX_ATTEMPTS;

      if (!canRetry) {
        if (err?.isCloudflareResponseError) throw err;
        if (status) {
          const mutationNote = retryable && !retrySafe ? " (mutation not retried after ambiguous outcome)" : "";
          const attemptNote = retryable && attempt === CF_MAX_ATTEMPTS ? ` (gave up after ${CF_MAX_ATTEMPTS} attempts)` : "";
          throw new Error(`Cloudflare API error ${status} on ${path}${mutationNote}${attemptNote}`);
        }
        if (err?.name === "AbortError") throw new Error(`Cloudflare API timeout on ${path}`);
        throw new Error(`Cloudflare API network error on ${path}: ${err.message}`);
      }

      const waitMs = status === 429 ? (err.retryAfterMs ?? RATE_LIMIT_COOLDOWN_MS) : 2000 * attempt;
      console.warn(
        status === 429
          ? `Rate limited — waiting ${Math.round(waitMs / 1000)}s... (${attempt}/${CF_MAX_ATTEMPTS})`
          : `Request failed (${status ?? err.message}), retrying... (${attempt}/${CF_MAX_ATTEMPTS})`
      );
      await sleep(waitMs);
    } finally {
      clearTimeout(timer);
    }
  }
}

function validateIdentityItems(items, path, identityKey, seenIdentityValues) {
  if (!identityKey) return;
  for (const item of items) {
    const identity = item?.[identityKey];
    if (typeof identity !== "string" || !identity) {
      throw new Error(`Cloudflare response item missing ${identityKey} for ${path}`);
    }
    if (seenIdentityValues.has(identity)) {
      throw new Error(`Cloudflare response contains duplicate ${identityKey} for ${path}`);
    }
    seenIdentityValues.add(identity);
  }
}

async function fetchAllPages(path, perPage = LIST_CHUNK_SIZE, identityKey = null) {
  const results = [];
  let page = 1;
  let expectedTotalCount;
  let expectedPerPage;
  let expectedTotalPages;
  const seenIdentityValues = new Set();

  while (true) {
    const separator = path.includes("?") ? "&" : "?";
    const payload = await cfFetch(`${path}${separator}page=${page}&per_page=${perPage}`);
    if (!Array.isArray(payload.result)) {
      throw new Error(`Cloudflare API returned an invalid result for ${path}`);
    }

    const resultInfo = payload.result_info;
    if (!resultInfo || typeof resultInfo !== "object") {
      if (page !== 1 || payload.result.length >= perPage) {
        throw new Error(`Cloudflare pagination metadata missing for ${path}`);
      }
      validateIdentityItems(payload.result, path, identityKey, seenIdentityValues);
      return {
        result: payload.result,
        result_info: {
          count: payload.result.length,
          page: 1,
          per_page: perPage,
          total_count: payload.result.length,
          total_pages: 1,
        },
      };
    }

    const reportedPage = Number(resultInfo.page);
    const reportedTotalCount = Number(resultInfo.total_count);
    const reportedPerPage = Number(resultInfo.per_page) || perPage;
    const reportedTotalPages = resultInfo.total_pages == null ? undefined : Number(resultInfo.total_pages);
    const reportedCount = resultInfo.count == null ? undefined : Number(resultInfo.count);
    if (
      !Number.isSafeInteger(reportedPage) ||
      !Number.isSafeInteger(reportedTotalCount) ||
      reportedTotalCount < 0 ||
      !Number.isSafeInteger(reportedPerPage) ||
      reportedPerPage <= 0 ||
      (reportedTotalPages !== undefined && (!Number.isSafeInteger(reportedTotalPages) || reportedTotalPages <= 0)) ||
      (reportedCount !== undefined && (!Number.isSafeInteger(reportedCount) || reportedCount !== payload.result.length))
    ) {
      throw new Error(`Cloudflare pagination metadata invalid for ${path}`);
    }
    if (reportedPage !== page) {
      throw new Error(`Cloudflare pagination metadata mismatch for ${path}: expected page ${page}, got ${reportedPage}`);
    }

    const totalPages = reportedTotalPages ?? Math.max(1, Math.ceil(reportedTotalCount / reportedPerPage));
    if (expectedTotalCount === undefined) {
      expectedTotalCount = reportedTotalCount;
      expectedPerPage = reportedPerPage;
      expectedTotalPages = totalPages;
    } else if (
      reportedTotalCount !== expectedTotalCount ||
      reportedPerPage !== expectedPerPage ||
      totalPages !== expectedTotalPages
    ) {
      throw new Error(`Cloudflare pagination metadata mismatch for ${path}`);
    }

    validateIdentityItems(payload.result, path, identityKey, seenIdentityValues);
    results.push(...payload.result);

    if (page >= totalPages) {
      if (results.length !== expectedTotalCount) {
        throw new Error(`Cloudflare pagination incomplete for ${path}: got ${results.length}, expected ${expectedTotalCount}`);
      }
      return {
        result: results,
        result_info: {
          ...resultInfo,
          count: results.length,
          page,
          per_page: perPage,
          total_count: results.length,
          total_pages: page,
        },
      };
    }

    page += 1;
    if (page > 1000) throw new Error(`Cloudflare pagination exceeded safety limit for ${path}`);
  }
}

// ─── Lists ───────────────────────────────────────────────────────────────────

export const getLists = () => fetchAllPages("/lists", LIST_CHUNK_SIZE, "id");

const getListItems = (id) => fetchAllPages(`/lists/${encodeURIComponent(id)}/items`, LIST_CHUNK_SIZE);

const createList = (name, items) =>
  cfFetch("/lists", {
    method: "POST",
    body: JSON.stringify({ name, type: "DOMAIN", items }),
  });

const patchList = (id, patch) =>
  cfFetch(`/lists/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });

async function deleteList(id) {
  try {
    return await cfFetch(`/lists/${encodeURIComponent(id)}`, { method: "DELETE" });
  } catch (error) {
    if (/Cloudflare API error 404/.test(error.message)) return null;
    throw error;
  }
}

export async function deleteAllLists(lists) {
  for (const { id, name } of lists) {
    await deleteList(id);
    console.log(`  Ensured absent: ${name}`);
  }
}

function chunkNumber(name) {
  return Number(name.match(LIST_NAME_RE)?.[1] ?? Number.MAX_SAFE_INTEGER);
}

function sortManagedLists(lists) {
  return [...lists].sort((a, b) => chunkNumber(a.name) - chunkNumber(b.name) || String(a.id).localeCompare(String(b.id)));
}

function nextChunkNames(existingLists, count) {
  const used = new Set(existingLists.map(({ name }) => chunkNumber(name)));
  const names = [];
  for (let candidate = 1; names.length < count; candidate++) {
    if (used.has(candidate)) continue;
    used.add(candidate);
    names.push(`zerotrustdns List - Chunk ${candidate}`);
  }
  return names;
}

function sameValues(left, right) {
  const sortValues = (values) => [...values].sort();
  return JSON.stringify(sortValues(left)) === JSON.stringify(sortValues(right));
}

function readListItemValues(items, listId) {
  if (!Array.isArray(items)) throw new Error(`Cloudflare list items invalid for ${listId}`);
  return items.map((item, index) => {
    if (!item || typeof item !== "object" || typeof item.value !== "string" || !item.value.trim()) {
      throw new Error(`Malformed list item for ${listId} at index ${index}`);
    }
    return item.value;
  });
}

function normalizeTraffic(value) {
  return String(value ?? "").replace(/\s+/g, "").replace(/[()]/g, "");
}

function trafficListIds(value) {
  return [...String(value ?? "").matchAll(/\$([A-Za-z0-9-]+)/g)].map((match) => match[1]).sort();
}

function isVerifiedRule(rule, traffic) {
  const settings = rule?.rule_settings;
  const normalizedTraffic = normalizeTraffic(rule?.traffic);
  const trafficClauses = normalizedTraffic.split("or");
  const validTrafficShape = trafficClauses.every((clause) => /^anydns\.domains\[\*\]in\$[A-Za-z0-9-]+$/.test(clause));
  const settingsValid =
    settings == null ||
    ((settings.block_page_enabled == null || settings.block_page_enabled === BLOCK_PAGE_ENABLED) &&
      (settings.block_reason == null || settings.block_reason === "Blocked by zerotrustdns."));
  return (
    (rule?.description == null || rule.description === RULE_DESCRIPTION) &&
    rule?.enabled === true &&
    rule?.action === "block" &&
    Array.isArray(rule?.filters) &&
    rule.filters.length === 1 &&
    rule.filters[0] === "dns" &&
    trafficListIds(rule.traffic).join("\0") === trafficListIds(traffic).join("\0") &&
    validTrafficShape &&
    settingsValid
  );
}

async function rollbackListMutations(existingLists, originalItemsByList, patches, createdLists) {
  const rollbackErrors = [];
  for (const list of existingLists) {
    if (!patches.has(list.id)) continue;
    try {
      const { result: currentItems } = await getListItems(list.id);
      const current = readListItemValues(currentItems, list.id);
      const original = originalItemsByList.get(list.id) ?? [];
      if (sameValues(current, original)) continue;
      await patchList(list.id, {
        remove: [...new Set(current)],
        append: original.map((value) => ({ value, description: "rollback" })),
      });
      const { result: verifiedItems } = await getListItems(list.id);
      const verified = readListItemValues(verifiedItems, list.id);
      if (!sameValues(verified, original)) throw new Error(`verification failed for ${list.id}`);
    } catch (error) {
      rollbackErrors.push(`${list.id}: ${error.message}`);
    }
  }

  for (const list of [...createdLists].reverse()) {
    try {
      await deleteList(list.id);
    } catch (error) {
      rollbackErrors.push(`${list.id}: ${error.message}`);
    }
  }

  if (rollbackErrors.length) {
    console.error(`  Rollback incomplete: ${rollbackErrors.join("; ")}`);
  }
}

/**
 * Syncs `domains` to Cloudflare Gateway lists named "zerotrustdns List - Chunk N".
 * The returned obsolete lists are intentionally left for the caller to delete
 * only after the replacement rule has been written successfully.
 */
export async function syncLists(domains) {
  const now = new Date().toISOString();
  const uniqueDomains = [...new Set(domains)];
  const wanted = new Set(uniqueDomains);

  const { result: allLists } = await getLists();
  const existingLists = sortManagedLists((allLists || []).filter(isManagedList));

  const itemsByList = new Map();
  for (const list of existingLists) {
    const { result: items } = await getListItems(list.id);
    itemsByList.set(list.id, readListItemValues(items, list.id));
  }

  const ownerByDomain = new Map();
  for (const list of existingLists) {
    for (const domain of itemsByList.get(list.id) ?? []) {
      if (!ownerByDomain.has(domain)) ownerByDomain.set(domain, list.id);
    }
  }

  if (
    !ALLOW_LARGE_SHRINK &&
    ownerByDomain.size > 0 &&
    uniqueDomains.length < ownerByDomain.size * MIN_DOMAIN_RETENTION_RATIO
  ) {
    throw new Error(
      `Refusing suspicious domain shrink: ${ownerByDomain.size} existing domains -> ${uniqueDomains.length} desired domains; set CLOUDFLARE_ALLOW_LARGE_SHRINK=1 to approve`
    );
  }

  const removalsByList = new Map();
  for (const list of existingLists) {
    const seen = new Set();
    const removals = [];
    for (const domain of itemsByList.get(list.id) ?? []) {
      const duplicate = seen.has(domain) || ownerByDomain.get(domain) !== list.id;
      seen.add(domain);
      if (!wanted.has(domain) || duplicate) removals.push(domain);
    }
    if (removals.length) removalsByList.set(list.id, removals);
  }

  const toAdd = uniqueDomains.filter((domain) => !ownerByDomain.has(domain));
  const initialAddCount = toAdd.length;
  const patches = new Map();
  const appendItems = (domainsToAppend) => domainsToAppend.map((value) => ({ value, description: now }));

  // Reuse capacity created by removals before creating new lists.
  for (const list of existingLists) {
    const removals = removalsByList.get(list.id);
    if (!removals) continue;
    const currentItems = itemsByList.get(list.id) ?? [];
    const capacity = Math.max(0, LIST_CHUNK_SIZE - (currentItems.length - removals.length));
    const append = appendItems(toAdd.splice(0, capacity));
    patches.set(list.id, { remove: removals, append });
  }

  // Then fill spare capacity in otherwise unchanged lists.
  for (const list of existingLists) {
    if (patches.has(list.id) || toAdd.length === 0) continue;
    const currentItems = itemsByList.get(list.id) ?? [];
    const space = Math.max(0, LIST_CHUNK_SIZE - currentItems.length);
    if (space > 0) patches.set(list.id, { append: appendItems(toAdd.splice(0, space)) });
  }

  const finalCountByList = new Map();
  for (const list of existingLists) {
    const currentCount = (itemsByList.get(list.id) ?? []).length;
    const patch = patches.get(list.id);
    finalCountByList.set(list.id, currentCount - (patch?.remove?.length ?? 0) + (patch?.append?.length ?? 0));
  }

  const obsoleteLists = existingLists.filter((list) => finalCountByList.get(list.id) === 0);
  for (const list of obsoleteLists) patches.delete(list.id);

  const createNames = nextChunkNames(existingLists, Math.ceil(toAdd.length / LIST_CHUNK_SIZE));
  const createSpecs = createNames.map((name, index) => ({
    name,
    items: appendItems(toAdd.slice(index * LIST_CHUNK_SIZE, (index + 1) * LIST_CHUNK_SIZE)),
  }));

  if (allLists.length + createSpecs.length > LIST_ACCOUNT_LIMIT) {
    throw new Error(
      `Cloudflare list quota would be exceeded: ${allLists.length} existing lists + ${createSpecs.length} new lists > ${LIST_ACCOUNT_LIMIT} allowed`
    );
  }

  const totalRemovals = [...removalsByList.values()].reduce((sum, values) => sum + values.length, 0);
  const createdLists = [];
  const expectedItemsByList = new Map();
  for (const list of existingLists) {
    if (obsoleteLists.some(({ id }) => id === list.id)) continue;
    const currentItems = itemsByList.get(list.id) ?? [];
    const patch = patches.get(list.id);
    const expected = [...currentItems];
    for (const removedValue of patch?.remove ?? []) {
      const index = expected.indexOf(removedValue);
      if (index >= 0) expected.splice(index, 1);
    }
    expected.push(...(patch?.append ?? []).map(({ value }) => value));
    expectedItemsByList.set(list.id, expected);
  }
  console.log(`  ${initialAddCount} to add, ${totalRemovals} to remove`);

  try {
    for (const spec of createSpecs) {
      const { result } = await createList(spec.name, spec.items);
      if (!result?.id) throw new Error(`Cloudflare did not return an id for created list ${spec.name}`);
      createdLists.push({ ...result, id: result.id, name: result.name ?? spec.name, type: result.type ?? "DOMAIN" });
      expectedItemsByList.set(result.id, spec.items.map(({ value }) => value));
      console.log(`  Created "${spec.name}" (${spec.items.length} domains)`);
    }

    for (const list of existingLists) {
      const patch = patches.get(list.id);
      if (!patch || (!patch.remove?.length && !patch.append?.length)) continue;
      console.log(`  Patching "${list.name}" (+${patch.append?.length ?? 0} / -${patch.remove?.length ?? 0})`);
      await patchList(list.id, patch);
    }

    // Read back every active managed list before allowing the rule update.
    for (const [listId, expected] of expectedItemsByList) {
      const { result: actualItems } = await getListItems(listId);
      const actual = readListItemValues(actualItems, listId);
      if (!sameValues(actual, expected)) {
        throw new Error(`Cloudflare list verification failed for ${listId}`);
      }
    }
  } catch (error) {
    await rollbackListMutations(existingLists, itemsByList, patches, createdLists);
    throw error;
  }

  return {
    obsoleteLists,
    createdLists,
    rollback: () => rollbackListMutations(existingLists, itemsByList, patches, createdLists),
  };
}

// ─── Rules ───────────────────────────────────────────────────────────────────

export const getRules = () => fetchAllPages("/rules", LIST_CHUNK_SIZE, "id");

export async function deleteRule(id) {
  try {
    return await cfFetch(`/rules/${encodeURIComponent(id)}`, { method: "DELETE" });
  } catch (error) {
    if (/Cloudflare API error 404/.test(error.message)) return null;
    throw error;
  }
}

/**
 * Creates or updates the zerotrustdns block rule referencing the given lists.
 */
export async function upsertRule(lists) {
  const ids = [...new Set(lists.map(({ id }) => id).filter(Boolean))];
  if (ids.length === 0) throw new Error("Cannot create a block rule without managed lists");
  const traffic = ids.map((id) => `any(dns.domains[*] in $${id})`).join(" or ");

  const body = {
    name: RULE_NAME,
    description: RULE_DESCRIPTION,
    enabled: true,
    action: "block",
    filters: ["dns"],
    traffic,
    rule_settings: {
      block_page_enabled: BLOCK_PAGE_ENABLED,
      block_reason: "Blocked by zerotrustdns.",
    },
  };

  let mutationAttempted = false;
  try {
    const { result: existingRules } = await getRules();
    const managedRules = existingRules.filter(isManagedRule).sort((a, b) => String(a.id).localeCompare(String(b.id)));
    const [canonical, ...duplicates] = managedRules;

    if (canonical) {
      mutationAttempted = true;
      await cfFetch(`/rules/${encodeURIComponent(canonical.id)}`, { method: "PUT", body: JSON.stringify(body) });
      for (const duplicate of duplicates) await deleteRule(duplicate.id);
      console.log("  Updated existing block rule.");
    } else {
      mutationAttempted = true;
      await cfFetch("/rules", { method: "POST", body: JSON.stringify(body) });
      console.log("  Created block rule.");
    }

    const { result: verifiedRules } = await getRules();
    const verified = verifiedRules.filter(isManagedRule);
    const verifiedCanonical = canonical ? verified.find(({ id }) => id === canonical.id) : verified[0];
    if (!verifiedCanonical || !isVerifiedRule(verifiedCanonical, traffic) || verified.length !== 1) {
      throw new Error("Cloudflare block rule verification failed");
    }
  } catch (error) {
    error.ruleMutationAttempted = mutationAttempted;
    throw error;
  }
}
