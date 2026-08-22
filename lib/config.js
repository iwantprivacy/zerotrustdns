try { process.loadEnvFile(); } catch (error) { if (error.code !== "ENOENT") throw error; }

export const CF_API_TOKEN = process.env.CLOUDFLARE_API_TOKEN;
export const CF_ACCOUNT_ID = process.env.CLOUDFLARE_ACCOUNT_ID;
export const LIST_ITEM_LIMIT = parseInt(process.env.CLOUDFLARE_LIST_ITEM_LIMIT, 10) || 300_000;
export const LIST_CHUNK_SIZE = 1000; // Cloudflare max items per list
export const BLOCK_PAGE_ENABLED = process.env.BLOCK_PAGE_ENABLED === "1";

if (!CF_API_TOKEN || !CF_ACCOUNT_ID) {
  console.error("Missing required env vars: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID");
  process.exit(1);
}

// Default filter lists — override via BLOCKLIST_URLS / ALLOWLIST_URLS in .env
// (one URL per line)
export const BLOCKLIST_URLS = process.env.BLOCKLIST_URLS
  ? process.env.BLOCKLIST_URLS.split("\n").filter(Boolean)
  : [
      "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
      "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
      "https://raw.githubusercontent.com/chungbuild/blocklist/main/gambling",
    ];

export const ALLOWLIST_URLS = process.env.ALLOWLIST_URLS
  ? process.env.ALLOWLIST_URLS.split("\n").filter(Boolean)
  : [
      "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
      "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/banks.txt",
      "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/android.txt",
      "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/windows.txt",
      "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/mac.txt",
    ];
