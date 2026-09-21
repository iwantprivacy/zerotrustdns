/**
 * Downloads and parses blocklist/allowlist filter files.
 */

import { domainToASCII } from "node:url";
import { isIP } from "node:net";
import { LIST_ITEM_LIMIT } from "./config.js";

// ─── Download ─────────────────────────────────────────────────────────────────

const FETCH_TIMEOUT_MS = 30_000;
const FETCH_MAX_ATTEMPTS = 3;
const FETCH_MAX_BYTES = 50 * 1024 * 1024;
const FETCH_MAX_SOURCES = 32;
const FETCH_MAX_TOTAL_BYTES = 200 * 1024 * 1024;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Retryable download statuses: rate-limit / transient / server errors only. */
export function isRetryableDownloadStatus(status) {
  return status === 408 || status === 425 || status === 429 || (status >= 500 && status <= 599);
}

function backoffMs(attempt, retryAfterMs = 0) {
  return Math.max(retryAfterMs, 1000 * 2 ** (attempt - 1));
}

function parseRetryAfterMs(value) {
  if (!value) return 0;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds, 300) * 1000;
  const date = Date.parse(value);
  if (!Number.isNaN(date)) return Math.max(0, Math.min(date - Date.now(), 300_000));
  return 0;
}

function safeSourceLabel(rawUrl) {
  try {
    const url = new URL(rawUrl);
    return url.hostname;
  } catch {
    return "configured source";
  }
}

function safeErrorMessage(error) {
  return String(error?.message ?? error ?? "unknown error").replace(/https?:\/\/\S+/gi, "[redacted-url]");
}

function transportCode(error) {
  return error?.code ?? error?.cause?.code;
}

function isRetryableDownloadError(error) {
  const code = transportCode(error);
  return (
    error?.name === "AbortError" ||
    code === "ECONNRESET" ||
    code === "ETIMEDOUT" ||
    code === "ECONNREFUSED" ||
    code === "EAI_AGAIN"
  );
}

async function cancelResponse(response) {
  try {
    await response?.body?.cancel?.();
  } catch {
    // The original response is already being discarded.
  }
}

async function readResponseText(response, maxBytes) {
  const rawDeclaredLength = response.headers?.get?.("content-length");
  const declaredLength = rawDeclaredLength == null ? undefined : Number(rawDeclaredLength);
  const contentEncoding = response.headers?.get?.("content-encoding");
  if (
    declaredLength !== undefined &&
    (!Number.isSafeInteger(declaredLength) || declaredLength < 0)
  ) {
    await cancelResponse(response);
    throw new Error("invalid content-length header");
  }
  if (declaredLength !== undefined && declaredLength > maxBytes) {
    await cancelResponse(response);
    throw new Error(`response exceeds maximum size of ${maxBytes} bytes`);
  }

  const verifyLength = (actualLength) => {
    if (declaredLength !== undefined && !contentEncoding && declaredLength !== actualLength) {
      throw new Error(`response body length mismatch: expected ${declaredLength} bytes, got ${actualLength}`);
    }
  };

  if (!response.body?.getReader) {
    const text = await response.text();
    const actualLength = Buffer.byteLength(text, "utf8");
    verifyLength(actualLength);
    if (actualLength > maxBytes) {
      throw new Error(`response exceeds maximum size of ${maxBytes} bytes`);
    }
    return text;
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const chunks = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value?.byteLength ?? value?.length ?? 0;
      if (totalBytes > maxBytes) {
        throw new Error(`response exceeds maximum size of ${maxBytes} bytes`);
      }
      chunks.push(decoder.decode(value, { stream: true }));
    }
    chunks.push(decoder.decode());
    verifyLength(totalBytes);
    return chunks.join("");
  } catch (error) {
    try {
      await reader.cancel();
    } catch {
      // The stream is already closed or cancelled.
    }
    throw error;
  }
}

/**
 * Fetches one URL sequentially with timeout + bounded retry on
 * 408/425/429/5xx only. Redirects and incomplete responses fail closed.
 */
export async function fetchOne(
  url,
  {
    timeoutMs = FETCH_TIMEOUT_MS,
    maxAttempts = FETCH_MAX_ATTEMPTS,
    maxBytes = FETCH_MAX_BYTES,
    fetchImpl = globalThis.fetch,
    setTimeoutImpl = setTimeout,
    clearTimeoutImpl = clearTimeout,
    sleepImpl = sleep,
  } = {}
) {
  let lastError;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const controller = new AbortController();
    const timer = setTimeoutImpl(() => controller.abort(), timeoutMs);
    let retryAfterMs = 0;
    try {
      const response = await fetchImpl(url, { signal: controller.signal, redirect: "manual" });
      if (response.status >= 300 && response.status < 400) {
        await cancelResponse(response);
        const error = new Error(`HTTP ${response.status} redirect rejected`);
        error.status = response.status;
        throw error;
      }
      if (response.status !== 200) {
        retryAfterMs = parseRetryAfterMs(response.headers?.get?.("retry-after"));
        await cancelResponse(response);
        const error = new Error(`HTTP ${response.status}`);
        error.status = response.status;
        throw error;
      }

      const text = await readResponseText(response, maxBytes);
      if (!text.trim()) throw new Error("empty response body");
      const contentType = (response.headers?.get?.("content-type") ?? "").split(";", 1)[0].trim().toLowerCase();
      const sample = text.replace(/^\uFEFF/, "").trimStart().toLowerCase();
      const isErrorMediaType =
        /^(?:text\/(?:html|xml|json)|application\/(?:json|xml|[^;]+\+(?:json|xml)))$/.test(contentType);
      const looksLikeErrorDocument =
        sample.startsWith("<?xml") ||
        sample.startsWith("<!doctype html") ||
        sample.startsWith("<html") ||
        sample.startsWith("<error") ||
        sample.startsWith("{") ||
        /^\[\s*["{]/.test(sample);
      if (isErrorMediaType || looksLikeErrorDocument) {
        throw new Error("unexpected error-document response");
      }
      return text;
    } catch (error) {
      lastError = error?.name === "AbortError" ? new Error(`timeout after ${timeoutMs}ms`) : error;
      const status = lastError?.status;
      const retryable = isRetryableDownloadError(error) || (Number.isInteger(status) && isRetryableDownloadStatus(status));
      if (!retryable || attempt === maxAttempts) throw lastError;
      console.warn(`  Retry ${attempt}/${maxAttempts} for ${safeSourceLabel(url)} (${safeErrorMessage(lastError)})...`);
      await sleepImpl(backoffMs(attempt, retryAfterMs));
    } finally {
      clearTimeoutImpl(timer);
    }
  }
  throw lastError;
}

/**
 * Downloads all URLs sequentially (avoids upstream rate limiting)
 * and returns the combined raw text. Invalid or failed sources abort the download.
 */
async function fetchAll(urls, sourceKind, options = {}) {
  const {
    maxSources: configuredMaxSources,
    maxTotalBytes: configuredMaxTotalBytes,
    budget: configuredBudget,
    ...fetchOptions
  } = options;
  const maxSources = configuredMaxSources ?? FETCH_MAX_SOURCES;
  const maxTotalBytes = configuredMaxTotalBytes ?? FETCH_MAX_TOTAL_BYTES;
  const budget = configuredBudget ?? { sourceCount: 0, totalBytes: 0 };
  if (budget.sourceCount + urls.length > maxSources) {
    throw new Error(`${sourceKind} source count exceeds maximum of ${maxSources}`);
  }
  budget.sourceCount += urls.length;
  const chunks = [];
  for (const [index, url] of urls.entries()) {
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error(`Invalid ${sourceKind} source ${index + 1}`);
    }
    if (parsed.protocol !== "https:" || parsed.username || parsed.password) {
      throw new Error(`Invalid ${sourceKind} source ${index + 1}`);
    }
    try {
      const remainingBytes = maxTotalBytes - budget.totalBytes;
      if (remainingBytes <= 0) {
        throw new Error(`aggregate ${sourceKind} source size exceeds maximum of ${maxTotalBytes} bytes`);
      }
      const text = await fetchOne(url, {
        ...fetchOptions,
        maxBytes: Math.min(fetchOptions.maxBytes ?? FETCH_MAX_BYTES, remainingBytes),
      });
      budget.totalBytes += Buffer.byteLength(text, "utf8");
      if (budget.totalBytes > maxTotalBytes) {
        throw new Error(`aggregate ${sourceKind} source size exceeds maximum of ${maxTotalBytes} bytes`);
      }
      chunks.push(text);
    } catch (err) {
      throw new Error(`Failed to download ${sourceKind} source ${index + 1} (${safeSourceLabel(url)}): ${safeErrorMessage(err)}`, {
        cause: err,
      });
    }
  }
  return chunks.join("\n");
}

export async function downloadLists(allowlistUrls, blocklistUrls, options = {}) {
  const budget = { sourceCount: 0, totalBytes: 0 };
  const allowlistRaw = await fetchAll(allowlistUrls, "allowlist", { ...options, budget });
  const blocklistRaw = await fetchAll(blocklistUrls, "blocklist", { ...options, budget });
  return { allowlistRaw, blocklistRaw };
}

// ─── Parsing ──────────────────────────────────────────────────────────────────

const DOMAIN_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function canonicalDomain(value) {
  const withoutFinalDot = String(value ?? "").trim().replace(/\.$/, "").toLowerCase();
  if (!withoutFinalDot || /[\s/?#\\,:;$^|*]/.test(withoutFinalDot)) return "";
  const ascii = domainToASCII(withoutFinalDot);
  return ascii.toLowerCase();
}

export function isValidDomain(value) {
  const domain = canonicalDomain(value);
  const labels = domain.split(".");
  return (
    !isIP(domain) &&
    domain.length >= 3 &&
    domain.length <= 253 &&
    labels.length >= 2 &&
    labels.at(-1).length >= 2 &&
    labels.every((label) => label.length <= 63 && DOMAIN_LABEL_RE.test(label))
  );
}

export function isComment(line) {
  return line.startsWith("#") || line.startsWith("!") || line.startsWith("//") || line.startsWith("/*");
}

/**
 * Strips hosts-file prefixes, adblock syntax, and wildcards to extract a plain domain.
 */
export function normalizeDomain(line, isAllowlist = false) {
  let s = isAllowlist ? line.replace(/^@@\|\|/, "") : line;
  s = s
    .replace(/^(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+/, "") // hosts format
    .replace(/^\|\|/, "")    // adblock ||domain^
    .replace(/\^.*$/, "")    // strip ^ and everything after
    .replace(/\$.*$/, "")    // strip adblock options without ^
    .replace(/^\*\./, "")    // wildcard prefix
    .trim();
  return canonicalDomain(s);
}

function domainsFromLine(line, isAllowlist = false) {
  const trimmed = String(line ?? "").trim();
  if (!trimmed || isComment(trimmed)) return [];

  const withoutInlineComment = trimmed.split("#", 1)[0].trim();
  if (!withoutInlineComment) return [];
  const tokens = withoutInlineComment.split(/\s+/);
  if (isIP(tokens[0])) {
    return tokens.slice(1).map((token) => normalizeDomain(token)).filter(Boolean);
  }

  const domain = normalizeDomain(withoutInlineComment, isAllowlist);
  return domain ? [domain] : [];
}

/**
 * Parses blocklist + allowlist raw text and returns a deduplicated array of
 * domains to block, with parent-domain collapsing and allowlist filtering.
 */
export function parseDomains(blocklistRaw, allowlistRaw, limit = LIST_ITEM_LIMIT) {
  // Build allowlist set
  const allowlist = new Set();
  for (const line of allowlistRaw.split("\n")) {
    for (const domain of domainsFromLine(line, true)) {
      if (isValidDomain(domain)) allowlist.add(domain);
    }
  }

  // An ancestor block would also block an explicitly allowlisted descendant.
  // Exclude such ancestors so the allowlist remains meaningful.
  const allowlistedAncestors = new Set();
  for (const domain of allowlist) {
    const parts = domain.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
      allowlistedAncestors.add(parts.slice(i).join("."));
    }
  }

  // Parse and canonicalize all blocklist candidates before collapsing parents.
  const candidates = new Set();

  for (const line of blocklistRaw.split("\n")) {
    for (const domain of domainsFromLine(line)) {
      if (!isValidDomain(domain)) continue;
      if (allowlist.has(domain) || allowlistedAncestors.has(domain)) continue;

      const parts = domain.split(".");
      let hasAllowlistedParent = false;
      for (let i = 1; i < parts.length - 1; i++) {
        const parent = parts.slice(i).join(".");
        if (allowlist.has(parent)) {
          hasAllowlistedParent = true;
          break;
        }
      }
      if (!hasAllowlistedParent) candidates.add(domain);
    }
  }

  const ordered = [...candidates].sort((a, b) => {
    const depthDifference = a.split(".").length - b.split(".").length;
    return depthDifference || (a < b ? -1 : a > b ? 1 : 0);
  });
  const blocked = new Set();
  const result = [];
  const itemLimit = Number.isSafeInteger(limit) && limit > 0 ? limit : 0;
  let processedCandidates = 0;

  for (const domain of ordered) {
    if (result.length >= itemLimit) break;
    processedCandidates += 1;
    const parts = domain.split(".");
    let hasBlockedParent = false;
    for (let i = 1; i < parts.length - 1; i++) {
      if (blocked.has(parts.slice(i).join("."))) {
        hasBlockedParent = true;
        break;
      }
    }
    if (hasBlockedParent) continue;
    blocked.add(domain);
    result.push(domain);
  }

  let omittedUncoveredCount = 0;
  if (processedCandidates < ordered.length) {
    const emitted = new Set(result);
    for (const domain of ordered) {
      if (emitted.has(domain)) continue;
      const parts = domain.split(".");
      let coveredByEmittedParent = false;
      for (let i = 1; i < parts.length - 1; i++) {
        if (emitted.has(parts.slice(i).join("."))) {
          coveredByEmittedParent = true;
          break;
        }
      }
      if (!coveredByEmittedParent) omittedUncoveredCount += 1;
    }
  }

  Object.defineProperties(result, {
    truncated: { value: processedCandidates < ordered.length, enumerable: false },
    rawCandidatesNotProcessed: { value: Math.max(0, ordered.length - processedCandidates), enumerable: false },
    omittedUncoveredCount: { value: omittedUncoveredCount, enumerable: false },
  });

  return result;
}
