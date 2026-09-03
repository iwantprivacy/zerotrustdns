/**
 * Downloads and parses blocklist/allowlist filter files.
 */

// ─── Download ─────────────────────────────────────────────────────────────────

export const FETCH_TIMEOUT_MS = 30_000;
export const FETCH_MAX_ATTEMPTS = 3;

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

/**
 * Fetches one URL sequentially with timeout + bounded retry on
 * 408/425/429/5xx only. Other 4xx fail fast (no point retrying).
 */
async function fetchOne(url, { timeoutMs = FETCH_TIMEOUT_MS, maxAttempts = FETCH_MAX_ATTEMPTS } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { signal: controller.signal, redirect: "follow" });
      if (res.ok) return await res.text();
      const retryAfterMs = parseRetryAfterMs(res.headers.get("retry-after"));
      lastError = new Error(`HTTP ${res.status}`);
      if (!isRetryableDownloadStatus(res.status) || attempt === maxAttempts) throw lastError;
      console.warn(`  Retry ${attempt}/${maxAttempts} for ${url} (HTTP ${res.status})...`);
      await sleep(backoffMs(attempt, retryAfterMs));
    } catch (err) {
      clearTimeout(timer);
      if (err?.name === "AbortError") {
        lastError = new Error(`timeout after ${timeoutMs}ms`);
      } else {
        lastError = err;
      }
      const retryable =
        err?.name === "AbortError" ||
        err?.code === "ECONNRESET" ||
        err?.code === "ETIMEDOUT" ||
        (err?.message?.startsWith("HTTP ") && isRetryableDownloadStatus(Number(err.message.slice(5))));
      if (!retryable || attempt === maxAttempts) throw lastError;
      console.warn(`  Retry ${attempt}/${maxAttempts} for ${url} (${lastError.message})...`);
      await sleep(backoffMs(attempt));
      continue;
    }
    clearTimeout(timer);
  }
  throw lastError;
}

/**
 * Downloads all URLs sequentially (avoids upstream rate limiting)
 * and returns the combined raw text. Non-https URLs are skipped fail-closed.
 */
async function fetchAll(urls) {
  const chunks = [];
  for (const url of urls) {
    if (!url.startsWith("https://")) {
      console.warn(`  Skipping non-https URL: ${url}`);
      continue;
    }
    try {
      chunks.push(await fetchOne(url));
    } catch (err) {
      console.warn(`  Failed to download ${url}: ${err.message}`);
    }
  }
  return chunks.join("\n");
}

export async function downloadLists(allowlistUrls, blocklistUrls) {
  const allowlistRaw = await fetchAll(allowlistUrls);
  const blocklistRaw = await fetchAll(blocklistUrls);
  return { allowlistRaw, blocklistRaw };
}

// ─── Parsing ──────────────────────────────────────────────────────────────────

const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function isValidDomain(value) {
  return DOMAIN_RE.test(value);
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
    .replace(/^\*\./, "")    // wildcard prefix
    .trim();
  return s;
}

/**
 * Parses blocklist + allowlist raw text and returns a deduplicated array of
 * domains to block, with parent-domain collapsing and allowlist filtering.
 */
export function parseDomains(blocklistRaw, allowlistRaw, limit = 300_000) {
  // Build allowlist set
  const allowlist = new Set();
  for (const line of allowlistRaw.split("\n")) {
    const s = line.trim();
    if (!s || isComment(s)) continue;
    const domain = normalizeDomain(s, true);
    if (isValidDomain(domain)) allowlist.add(domain);
  }

  // Parse blocklist
  const blocked = new Set();
  const result = [];

  for (const line of blocklistRaw.split("\n")) {
    if (result.length >= limit) break;

    const s = line.trim();
    if (!s || isComment(s)) continue;

    const domain = normalizeDomain(s);
    if (!isValidDomain(domain)) continue;
    if (blocked.has(domain)) continue;

    // Skip if any parent domain is allowlisted or already blocked
    const parts = domain.split(".");
    let skip = false;
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join(".");
      if (allowlist.has(parent)) { skip = true; break; }
      if (blocked.has(parent)) { skip = true; break; }
    }
    if (skip) continue;
    if (allowlist.has(domain)) continue;

    blocked.add(domain);
    result.push(domain);
  }

  return result;
}
