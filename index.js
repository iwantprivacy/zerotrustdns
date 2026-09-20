/**
 * Zero Trust DNS — Cloudflare Gateway Ad Blocker
 * Downloads filter lists and syncs them to Cloudflare Zero Trust Gateway.
 *
 * Usage:
 *   node index.js          → download lists + sync to Cloudflare
 *   node index.js --dry    → download lists + preview changes (no API calls, no creds needed)
 *   node index.js --delete → delete all zerotrustdns lists and rules from Cloudflare
 */

import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { downloadLists, parseDomains } from "./lib/lists.js";
import {
  syncLists,
  deleteAllLists,
  upsertRule,
  deleteRule,
  getLists,
  getRules,
  isManagedList,
  isManagedRule,
} from "./lib/cloudflare.js";
import { BLOCKLIST_URLS, ALLOWLIST_URLS, LIST_ITEM_LIMIT, assertCloudflareEnv } from "./lib/config.js";
import { parseArgs } from "./lib/cli.js";

export async function main(args = process.argv.slice(2)) {
  const { isDryRun, isDelete } = parseArgs(args);

  // Dry-run downloads and parses only. Every Cloudflare mutation path requires credentials.
  if (!isDryRun) assertCloudflareEnv();

  if (isDelete) {
    console.log("Deleting all zerotrustdns lists and rules from Cloudflare...");

    const { result: rules } = await getRules();
    const rulesToDelete = rules.filter(isManagedRule);
    for (const rule of rulesToDelete) {
      console.log(`Deleting rule: ${rule.name}`);
      await deleteRule(rule.id);
    }

    const { result: lists } = await getLists();
    const listsToDelete = lists.filter(isManagedList);
    if (listsToDelete.length) {
      console.log(`Deleting ${listsToDelete.length} lists...`);
      await deleteAllLists(listsToDelete);
    }

    const { result: remainingRules } = await getRules();
    const { result: remainingLists } = await getLists();
    if (remainingRules.some(isManagedRule) || remainingLists.some(isManagedList)) {
      throw new Error("Delete verification failed: managed Cloudflare resources remain");
    }

    console.log("Done.");
    return;
  }

  // Step 1: Download sequentially — a source failure aborts the run before API access.
  console.log("Downloading filter lists...");
  const { allowlistRaw, blocklistRaw } = await downloadLists(ALLOWLIST_URLS, BLOCKLIST_URLS);

  // Step 2: Parse & deduplicate
  console.log("Parsing domains...");
  const domains = parseDomains(blocklistRaw, allowlistRaw, LIST_ITEM_LIMIT);
  console.log(`→ ${domains.length} unique domains to block`);
  if (domains.truncated) {
    console.warn(
      `WARNING: item limit ${LIST_ITEM_LIMIT} reached; ${domains.rawCandidatesNotProcessed} raw candidates were beyond the limit; estimated uncovered candidates: ${domains.omittedUncoveredCount}`
    );
  }

  if (domains.length === 0) {
    throw new Error("0 domains after parsing — refusing to sync an empty list (would wipe existing blocks)");
  }

  if (isDryRun) {
    console.log("Dry run — no changes made to Cloudflare.");
    return;
  }

  // Step 3: Sync lists. Obsolete empty lists are held until the rule stops referencing them.
  console.log("Syncing to Cloudflare Gateway...");
  const { obsoleteLists, createdLists, rollback } = await syncLists(domains);

  // Step 4: Upsert the rule before deleting obsolete lists.
  const obsoleteIds = new Set(obsoleteLists.map(({ id }) => id));
  try {
    const { result: lists } = await getLists();
    const listsById = new Map(
      [...lists, ...createdLists].filter(isManagedList).map((list) => [list.id, list])
    );
    const activeLists = [...listsById.values()].filter(({ id }) => !obsoleteIds.has(id));
    await upsertRule(activeLists);
  } catch (error) {
    if (!error.ruleMutationAmbiguous) await rollback();
    else console.error("  Rule mutation outcome is ambiguous; leaving staged list state for the next reconciliation run.");
    throw error;
  }

  if (obsoleteLists.length) await deleteAllLists(obsoleteLists);
  const { result: verifiedLists } = await getLists();
  const remainingObsolete = verifiedLists.filter(({ id }) => obsoleteIds.has(id));
  if (remainingObsolete.length > 0) {
    throw new Error("Cloudflare list deletion verification failed");
  }
  console.log("Done.");
}

const isDirectExecution = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isDirectExecution) {
  try {
    await main();
  } catch (err) {
    // Never print credentials; provider details are bounded and sanitized by the API client.
    console.error(`ERROR: ${err.message}`);
    process.exitCode = 1;
  }
}
