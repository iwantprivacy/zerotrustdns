use anyhow::{Result, anyhow, bail};
use std::process::ExitCode;
use url::Url;
use zerotrustdns::cloudflare::{SyncOptions, sync_to_cloudflare};
use zerotrustdns::config::Config;
use zerotrustdns::parser::parse_domains;
use zerotrustdns::sources::{DownloadedLists, download_lists};

trait Operations {
    fn download(
        &mut self,
        allowlist_urls: &[Url],
        blocklist_urls: &[Url],
    ) -> Result<DownloadedLists>;
    fn sync(
        &mut self,
        token: &str,
        account_id: &str,
        domains: &[String],
        options: SyncOptions,
    ) -> Result<()>;
}

struct RealOperations;

impl Operations for RealOperations {
    fn download(
        &mut self,
        allowlist_urls: &[Url],
        blocklist_urls: &[Url],
    ) -> Result<DownloadedLists> {
        download_lists(allowlist_urls, blocklist_urls)
    }

    fn sync(
        &mut self,
        token: &str,
        account_id: &str,
        domains: &[String],
        options: SyncOptions,
    ) -> Result<()> {
        sync_to_cloudflare(token, account_id, domains, options)
    }
}

fn main() -> ExitCode {
    match run_from_environment() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_from_environment() -> Result<()> {
    let config = Config::from_env()?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    run(&config, &args, &mut RealOperations)
}

fn parse_args(args: &[String]) -> Result<bool> {
    if let Some(unknown) = args.iter().find(|argument| argument.as_str() != "--dry") {
        bail!("Unknown option: {unknown}");
    }
    Ok(args.iter().any(|argument| argument == "--dry"))
}

fn run(config: &Config, args: &[String], operations: &mut impl Operations) -> Result<()> {
    let is_dry_run = parse_args(args)?;
    let credentials = if is_dry_run {
        None
    } else {
        Some(config.validate_cloudflare_env()?)
    };

    println!("Downloading filter lists...");
    let downloaded = operations.download(&config.allowlist_urls, &config.blocklist_urls)?;
    println!("Parsing domains...");
    let parsed = parse_domains(
        &downloaded.blocklist_raw,
        &downloaded.allowlist_raw,
        config.list_item_limit,
    );
    println!("→ {} unique domains to block", parsed.domains.len());
    if parsed.truncated {
        eprintln!(
            "WARNING: item limit {} reached; {} raw candidates were beyond the limit; estimated uncovered candidates: {}",
            config.list_item_limit,
            parsed.raw_candidates_not_processed,
            parsed.omitted_uncovered_count
        );
    }
    if parsed.domains.is_empty() {
        bail!(
            "0 domains after parsing — refusing to sync an empty list (would wipe existing blocks)"
        );
    }

    if is_dry_run {
        println!("Dry run — no changes made to Cloudflare.");
        return Ok(());
    }

    let (token, account_id) =
        credentials.ok_or_else(|| anyhow!("Cloudflare credentials are required"))?;
    let options = SyncOptions {
        list_account_limit: config.list_account_limit,
        min_domain_retention_ratio: config.min_domain_retention_ratio,
        allow_large_shrink: config.allow_large_shrink,
    };
    println!("Syncing to Cloudflare Gateway...");
    operations.sync(token, account_id, &parsed.domains, options)?;
    println!("Done.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Operations, parse_args, run};
    use anyhow::{Result, anyhow};
    use url::Url;
    use zerotrustdns::cloudflare::SyncOptions;
    use zerotrustdns::config::Config;
    use zerotrustdns::sources::DownloadedLists;

    #[derive(Default)]
    struct FakeOperations {
        downloads: usize,
        syncs: usize,
        download_result: Option<DownloadedLists>,
        download_fails: bool,
        synced_domains: Vec<String>,
        synced_token: Option<String>,
        synced_account_id: Option<String>,
        synced_options: Option<SyncOptions>,
    }

    impl Operations for FakeOperations {
        fn download(
            &mut self,
            _allowlist_urls: &[Url],
            _blocklist_urls: &[Url],
        ) -> Result<DownloadedLists> {
            self.downloads += 1;
            if self.download_fails {
                return Err(anyhow!("source failed"));
            }
            self.download_result
                .take()
                .ok_or_else(|| anyhow!("test download result not configured"))
        }

        fn sync(
            &mut self,
            token: &str,
            account_id: &str,
            domains: &[String],
            options: SyncOptions,
        ) -> Result<()> {
            self.syncs += 1;
            self.synced_token = Some(token.to_owned());
            self.synced_account_id = Some(account_id.to_owned());
            self.synced_domains = domains.to_vec();
            self.synced_options = Some(options);
            Ok(())
        }
    }

    fn config(token: Option<&str>, account_id: Option<&str>) -> Config {
        Config {
            cloudflare_api_token: token.map(str::to_owned),
            cloudflare_account_id: account_id.map(str::to_owned),
            blocklist_urls: vec![Url::parse("https://block.example/list").unwrap()],
            allowlist_urls: vec![Url::parse("https://allow.example/list").unwrap()],
            list_item_limit: 300_000,
            list_account_limit: 300,
            min_domain_retention_ratio: 0.5,
            allow_large_shrink: false,
        }
    }

    fn successful_download(blocklist_raw: &str, allowlist_raw: &str) -> DownloadedLists {
        DownloadedLists {
            blocklist_raw: blocklist_raw.to_owned(),
            allowlist_raw: allowlist_raw.to_owned(),
        }
    }

    #[test]
    fn parse_args_accepts_only_dry_and_allows_repetition() {
        assert!(!parse_args(&[]).unwrap());
        assert!(parse_args(&["--dry".into(), "--dry".into()]).unwrap());
        assert!(
            parse_args(&["--unknown".into()])
                .unwrap_err()
                .to_string()
                .contains("Unknown option: --unknown")
        );
    }

    #[test]
    fn real_run_validates_credentials_before_downloading_any_source() {
        let mut operations = FakeOperations::default();
        let error = run(&config(None, Some("account")), &[], &mut operations).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Cloudflare credentials are required")
        );
        assert_eq!(operations.downloads, 0);
        assert_eq!(operations.syncs, 0);
    }

    #[test]
    fn dry_run_needs_no_cloudflare_credentials_and_never_syncs() {
        let mut operations = FakeOperations {
            download_result: Some(successful_download("||ads.example.com^", "")),
            ..FakeOperations::default()
        };
        run(&config(None, None), &["--dry".into()], &mut operations).unwrap();
        assert_eq!(operations.downloads, 1);
        assert_eq!(operations.syncs, 0);
    }

    #[test]
    fn source_failure_and_empty_parse_never_call_cloudflare() {
        let mut failing = FakeOperations {
            download_fails: true,
            ..FakeOperations::default()
        };
        assert!(run(&config(Some("token"), Some("account")), &[], &mut failing).is_err());
        assert_eq!(failing.syncs, 0);

        let mut empty = FakeOperations {
            download_result: Some(successful_download("# no domains", "")),
            ..FakeOperations::default()
        };
        let error = run(&config(Some("token"), Some("account")), &[], &mut empty).unwrap_err();
        assert!(error.to_string().contains("0 domains after parsing"));
        assert_eq!(empty.syncs, 0);
    }

    #[test]
    fn live_run_sends_only_parsed_domains_and_explicit_sync_settings() {
        let mut config = config(Some("secret-token"), Some("account-id"));
        config.list_account_limit = 17;
        config.min_domain_retention_ratio = 0.25;
        config.allow_large_shrink = true;
        let mut operations = FakeOperations {
            download_result: Some(successful_download(
                "||ads.example.com^\n||ads.example.com^\n||safe.example.com^",
                "safe.example.com",
            )),
            ..FakeOperations::default()
        };

        run(&config, &[], &mut operations).unwrap();

        assert_eq!(operations.syncs, 1);
        assert_eq!(operations.synced_token.as_deref(), Some("secret-token"));
        assert_eq!(operations.synced_account_id.as_deref(), Some("account-id"));
        assert_eq!(operations.synced_domains, ["ads.example.com"]);
        assert_eq!(
            operations.synced_options,
            Some(SyncOptions {
                list_account_limit: 17,
                min_domain_retention_ratio: 0.25,
                allow_large_shrink: true,
            })
        );
    }
}
