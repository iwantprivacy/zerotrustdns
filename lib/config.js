try { process.loadEnvFile(); } catch (error) { if (error.code !== "ENOENT") throw error; }

export const CF_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
export const CF_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
export const LIST_CHUNK_SIZE = 1000; // Cloudflare max items per list
export const BLOCK_PAGE_ENABLED = process.env.BLOCK_PAGE_ENABLED === "1";

export const DEFAULT_ITEM_LIMIT = 300_000; // Cloudflare free tier: 300k domains

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
  const n = typeof raw === "number" ? raw : parseInt(String(raw ?? ""), 10);
  if (!Number.isSafeInteger(n) || n <= 0) return fallback;
  return n;
}

/**
 * Pure: parse a one-URL-per-line env value. Only https:// URLs are kept
 * (fail-closed against file:// or other schemes). Returns `fallback` when
 * `raw` is unset/blank. Throws when `raw` is set but yields zero valid URLs.
 */
export function parseUrlList(raw, fallback) {
  if (raw == null || String(raw).trim() === "") return [...fallback];
  const urls = String(raw)
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((s) => s.startsWith("https://"));
  if (urls.length === 0) throw new Error("No valid https:// URLs found in list env var");
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
export const BLOCKLIST_URLS = parseUrlList(process.env.BLOCKLIST_URLS, DEFAULT_BLOCKLIST_URLS);
export const ALLOWLIST_URLS = parseUrlList(process.env.ALLOWLIST_URLS, DEFAULT_ALLOWLIST_URLS);
