const SUPPORTED_OPTIONS = new Set(["--dry", "--delete"]);

export function parseArgs(args) {
  const unknown = args.filter((arg) => !SUPPORTED_OPTIONS.has(arg));
  if (unknown.length > 0) {
    throw new Error(`Unknown option: ${unknown[0]}`);
  }

  const isDryRun = args.includes("--dry");
  const isDelete = args.includes("--delete");
  if (isDryRun && isDelete) {
    throw new Error("--dry and --delete cannot be used together");
  }

  return { isDryRun, isDelete };
}
