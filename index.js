/**
 * Zero Trust DNS — Cloudflare Gateway Ad Blocker
 * Downloads filter lists and syncs them to Cloudflare Zero Trust Gateway.
 *
 * Usage:
 *   node index.js          → download lists + sync to Cloudflare
 *   node index.js --dry    → download lists + preview changes (no API calls)
 *   node index.js --delete → delete all zerotrustdns lists and rules from Cloudflare
 */

import { downloadLists, parseDomains } from "./lib/lists.js";
import { syncLists, deleteAllLists, upsertRule, deleteRule, getLists, getRules } from "./lib/cloudflare.js";
import { BLOCKLIST_URLS, ALLOWLIST_URLS, LIST_ITEM_LIMIT } from "./lib/config.js";

const args = process.argv.slice(2);
const isDryRun = args.includes("--dry");
const isDelete = args.includes("--delete");

if (isDelete) {
  console.log("Deleting all zerotrustdns lists and rules from Cloudflare...");

  const { result: rules } = await getRules();
  const rulesToDelete = rules.filter(({ name }) => name.startsWith("zerotrustdns Filter Lists"));
  for (const rule of rulesToDelete) {
    console.log(`Deleting rule: ${rule.name}`);
    await deleteRule(rule.id);
  }

  const { result: lists } = await getLists();
  const listsToDelete = lists.filter(({ name }) => name.startsWith("zerotrustdns List"));
  if (listsToDelete.length) {
    console.log(`Deleting ${listsToDelete.length} lists...`);
    await deleteAllLists(listsToDelete);
  }

  console.log("Done.");
  process.exit(0);
}

// Step 1: Download
console.log("Downloading filter lists...");
const { allowlistRaw, blocklistRaw } = await downloadLists(ALLOWLIST_URLS, BLOCKLIST_URLS);

// Step 2: Parse & deduplicate
console.log("Parsing domains...");
const domains = parseDomains(blocklistRaw, allowlistRaw, LIST_ITEM_LIMIT);
console.log(`→ ${domains.length} unique domains to block`);

if (isDryRun) {
  console.log("Dry run — no changes made to Cloudflare.");
  process.exit(0);
}

// Step 3: Sync lists
console.log("Syncing to Cloudflare Gateway...");
await syncLists(domains);

// Step 4: Upsert the block rule
const { result: lists } = await getLists();
await upsertRule(lists.filter(({ name }) => name.startsWith("zerotrustdns List")));

console.log("Done.");
