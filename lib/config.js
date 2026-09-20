try { process.loadEnvFile(); } catch (error) { if (error.code !== "ENOENT") throw error; }

export const CF_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
export const CF_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
export const LIST_CHUNK_SIZE = 1000; // Cloudflare max items per list
export const DEFAULT_LIST_ACCOUNT_LIMIT = 300; // Project default; override for the account's actual quota
export const BLOCK_PAGE_ENABLED = process.env.BLOCK_PAGE_ENABLED === "1";

export const DEFAULT_ITEM_LIMIT = LIST_CHUNK_SIZE * DEFAULT_LIST_ACCOUNT_LIMIT;
export const DEFAULT_MIN_DOMAIN_RETENTION_RATIO = 0.5;

// Default filter lists — override via BLOCKLIST_URLS / ALLOWLIST_URLS in .env
// (one URL per line)
export const DEFAULT_BLOCKLIST_URLS = [
  "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
  "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
];

export const DEFAULT_ALLOWLIST_URLS = [
  "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
  "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/banks.txt",
  "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/android.txt",
  "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/windows.txt",
  "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/mac.txt",
];

/**
 * Pure: parse the item-limit env value. Returns a positive int,
 * falling back to `fallback` on missing/invalid/non-positive input.
 */
export function parseItemLimit(raw, fallback = DEFAULT_ITEM_LIMIT) {
  const text = String(raw ?? "").trim();
  const n = typeof raw === "number" ? raw : /^[1-9]\d*$/.test(text) ? Number(text) : NaN;
  if (!Number.isSafeInteger(n) || n <= 0) return fallback;
  return n;
}

/** Pure: parse a 0..1 retention ratio, falling back on invalid input. */
export function parseRatio(raw, fallback = DEFAULT_MIN_DOMAIN_RETENTION_RATIO) {
  if (raw == null || String(raw).trim() === "") return fallback;
  const value = Number(raw);
  return Number.isFinite(value) && value >= 0 && value <= 1 ? value : fallback;
}

/**
 * Pure: parse a one-URL-per-line env value. Only https:// URLs without
 * embedded credentials are accepted. Returns `fallback` when `raw` is
 * unset/blank. Throws when any configured entry is invalid.
 */
export function parseUrlList(raw, fallback) {
  if (raw == null || String(raw).trim() === "") return [...fallback];
  const entries = String(raw)
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  const urls = [];
  let invalidCount = 0;
  for (const entry of entries) {
    try {
      const parsed = new URL(entry);
      if (parsed.protocol !== "https:" || !parsed.hostname || parsed.username || parsed.password) {
        throw new Error("invalid source URL");
      }
      urls.push(entry);
    } catch {
      invalidCount += 1;
    }
  }
  if (urls.length === 0) throw new Error("No valid https URLs found in list env var");
  if (invalidCount > 0) {
    throw new Error("Only valid https URLs are allowed in list env var");
  }
  return urls;
}

/**
 * Fail-closed env validation. Call before any Cloudflare API access
 * (sync/delete) — never log the token. Throws on missing creds.
 * Dry-run previews must NOT call this (no API access, no creds needed).
 */
export function assertCloudflareEnv(env = process.env) {
  const token = env.CLOUDFLARE_API_TOKEN;
  const accountId = env.CLOUDFLARE_ACCOUNT_ID;
  if (!token || !accountId) {
    throw new Error("Missing required env vars: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID");
  }
  return { token, accountId };
}

export const LIST_ITEM_LIMIT = parseItemLimit(process.env.CLOUDFLARE_LIST_ITEM_LIMIT);
// Override when other Lists already consume part of the account quota.
export const LIST_ACCOUNT_LIMIT = parseItemLimit(process.env.CLOUDFLARE_LIST_ACCOUNT_LIMIT, DEFAULT_LIST_ACCOUNT_LIMIT);
export const MIN_DOMAIN_RETENTION_RATIO = parseRatio(process.env.CLOUDFLARE_MIN_DOMAIN_RETENTION_RATIO);
export const ALLOW_LARGE_SHRINK = process.env.CLOUDFLARE_ALLOW_LARGE_SHRINK === "1";
export const BLOCKLIST_URLS = parseUrlList(process.env.BLOCKLIST_URLS, DEFAULT_BLOCKLIST_URLS);
export const ALLOWLIST_URLS = parseUrlList(process.env.ALLOWLIST_URLS, DEFAULT_ALLOWLIST_URLS);
