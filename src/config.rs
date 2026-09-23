//! Environment and runtime configuration.

use anyhow::{Result, anyhow};
use url::Url;

const DEFAULT_BLOCKLIST_URLS: &[&str] = &[
    "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
    "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
];

const DEFAULT_ALLOWLIST_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/banks.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/android.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/windows.txt",
    "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/mac.txt",
];

const DEFAULT_LIST_ITEM_LIMIT: usize = 300_000;
const DEFAULT_LIST_ACCOUNT_LIMIT: usize = 300;
const DEFAULT_MIN_DOMAIN_RETENTION_RATIO: f64 = 0.5;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, PartialEq)]
pub struct Config {
    pub cloudflare_api_token: Option<String>,
    pub cloudflare_account_id: Option<String>,
    pub blocklist_urls: Vec<Url>,
    pub allowlist_urls: Vec<Url>,
    pub list_item_limit: usize,
    pub list_account_limit: usize,
    pub min_domain_retention_ratio: f64,
    pub allow_large_shrink: bool,
}

impl Config {
    /// Loads optional dotenv configuration, then reads the effective process environment.
    /// Existing process variables take precedence over values in `.env`.
    pub fn from_env() -> Result<Self> {
        if let Err(error) = dotenvy::dotenv() {
            if !error.not_found() {
                return Err(anyhow!("Unable to load .env configuration"));
            }
        }

        config_from_lookup(|name| std::env::var(name).ok())
    }

    /// Returns Cloudflare credentials or a generic error that never includes their values.
    pub fn validate_cloudflare_env(&self) -> Result<(&str, &str)> {
        match (
            self.cloudflare_api_token.as_deref(),
            self.cloudflare_account_id.as_deref(),
        ) {
            (Some(token), Some(account_id)) if !token.is_empty() && !account_id.is_empty() => {
                Ok((token, account_id))
            }
            _ => Err(anyhow!("Cloudflare credentials are required")),
        }
    }
}

fn config_from_lookup(mut get: impl FnMut(&str) -> Option<String>) -> Result<Config> {
    let default_blocklist_urls = parse_default_urls(DEFAULT_BLOCKLIST_URLS)?;
    let default_allowlist_urls = parse_default_urls(DEFAULT_ALLOWLIST_URLS)?;
    let blocklist_urls = parse_url_list(get("BLOCKLIST_URLS").as_deref(), &default_blocklist_urls)?;
    let allowlist_urls = parse_url_list(get("ALLOWLIST_URLS").as_deref(), &default_allowlist_urls)?;

    Ok(Config {
        cloudflare_api_token: get("CLOUDFLARE_API_TOKEN"),
        cloudflare_account_id: get("CLOUDFLARE_ACCOUNT_ID"),
        blocklist_urls,
        allowlist_urls,
        list_item_limit: parse_positive_limit(
            get("CLOUDFLARE_LIST_ITEM_LIMIT").as_deref(),
            DEFAULT_LIST_ITEM_LIMIT,
        ),
        list_account_limit: parse_positive_limit(
            get("CLOUDFLARE_LIST_ACCOUNT_LIMIT").as_deref(),
            DEFAULT_LIST_ACCOUNT_LIMIT,
        ),
        min_domain_retention_ratio: parse_ratio(
            get("CLOUDFLARE_MIN_DOMAIN_RETENTION_RATIO").as_deref(),
            DEFAULT_MIN_DOMAIN_RETENTION_RATIO,
        ),
        allow_large_shrink: get("CLOUDFLARE_ALLOW_LARGE_SHRINK").as_deref() == Some("1"),
    })
}

fn parse_positive_limit(raw: Option<&str>, fallback: usize) -> usize {
    let Some(text) = raw.map(str::trim) else {
        return fallback;
    };
    let bytes = text.as_bytes();
    if bytes.is_empty()
        || !(b'1'..=b'9').contains(&bytes[0])
        || !bytes[1..].iter().all(u8::is_ascii_digit)
    {
        return fallback;
    }

    match text.parse::<u64>() {
        Ok(value) if value > 0 && value <= MAX_SAFE_INTEGER => {
            usize::try_from(value).unwrap_or(fallback)
        }
        _ => fallback,
    }
}

fn parse_ratio(raw: Option<&str>, fallback: f64) -> f64 {
    let Some(text) = raw.map(str::trim).filter(|text| !text.is_empty()) else {
        return fallback;
    };

    match text.parse::<f64>() {
        Ok(value) if value.is_finite() && (0.0..=1.0).contains(&value) => value,
        _ => fallback,
    }
}

fn parse_default_urls(entries: &[&str]) -> Result<Vec<Url>> {
    entries
        .iter()
        .map(|entry| Url::parse(entry).map_err(|_| anyhow!("Invalid default source URL")))
        .collect()
}

fn parse_url_list(raw: Option<&str>, fallback: &[Url]) -> Result<Vec<Url>> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(fallback.to_vec());
    };

    let mut urls = Vec::new();
    for entry in raw.lines().map(str::trim).filter(|entry| !entry.is_empty()) {
        let url =
            Url::parse(entry).map_err(|_| anyhow!("Invalid URL in source list configuration"))?;
        if url.scheme() != "https"
            || url.host_str().is_none_or(str::is_empty)
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(anyhow!("Invalid URL in source list configuration"));
        }
        urls.push(url);
    }

    if urls.is_empty() {
        return Err(anyhow!("Source list configuration contains no URLs"));
    }
    Ok(urls)
}

#[cfg(test)]
mod tests {
    use super::{Config, config_from_lookup, parse_positive_limit, parse_ratio, parse_url_list};
    use std::collections::HashMap;

    fn config_from(entries: &[(&str, &str)]) -> Config {
        let values: HashMap<_, _> = entries.iter().copied().collect();
        config_from_lookup(|key| values.get(key).map(|value| (*value).to_owned()))
            .expect("test configuration should be valid")
    }

    fn url_strings(urls: &[url::Url]) -> Vec<String> {
        urls.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn defaults_match_the_project_configuration() {
        let config = config_from(&[]);

        assert_eq!(config.cloudflare_api_token, None);
        assert_eq!(config.cloudflare_account_id, None);
        assert_eq!(
            url_strings(&config.blocklist_urls),
            vec![
                "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
                "https://raw.githubusercontent.com/bigdargon/hostsVN/master/hosts",
            ]
        );
        assert_eq!(
            url_strings(&config.allowlist_urls),
            vec![
                "https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
                "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/banks.txt",
                "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/android.txt",
                "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/windows.txt",
                "https://raw.githubusercontent.com/AdguardTeam/HttpsExclusions/master/exclusions/mac.txt",
            ]
        );
        assert_eq!(config.list_item_limit, 300_000);
        assert_eq!(config.list_account_limit, 300);
        assert_eq!(config.min_domain_retention_ratio, 0.5);
        assert!(!config.allow_large_shrink);
    }

    #[test]
    fn environment_overrides_are_parsed_without_normalizing_the_shrink_flag() {
        let config = config_from(&[
            ("CLOUDFLARE_API_TOKEN", "token-value"),
            ("CLOUDFLARE_ACCOUNT_ID", "account-value"),
            ("CLOUDFLARE_LIST_ITEM_LIMIT", "42"),
            ("CLOUDFLARE_LIST_ACCOUNT_LIMIT", "7"),
            ("CLOUDFLARE_MIN_DOMAIN_RETENTION_RATIO", "0.25"),
            ("CLOUDFLARE_ALLOW_LARGE_SHRINK", "1"),
            (
                "BLOCKLIST_URLS",
                "  https://example.com/a  \n\nhttps://example.org/b\n",
            ),
            ("ALLOWLIST_URLS", "https://allow.example/list"),
        ]);

        assert_eq!(config.cloudflare_api_token.as_deref(), Some("token-value"));
        assert_eq!(
            config.cloudflare_account_id.as_deref(),
            Some("account-value")
        );
        assert_eq!(config.list_item_limit, 42);
        assert_eq!(config.list_account_limit, 7);
        assert_eq!(config.min_domain_retention_ratio, 0.25);
        assert!(config.allow_large_shrink);
        assert_eq!(
            url_strings(&config.blocklist_urls),
            vec!["https://example.com/a", "https://example.org/b",]
        );
        assert_eq!(
            url_strings(&config.allowlist_urls),
            vec!["https://allow.example/list"]
        );

        assert!(!config_from(&[("CLOUDFLARE_ALLOW_LARGE_SHRINK", "true")]).allow_large_shrink);
        assert!(!config_from(&[("CLOUDFLARE_ALLOW_LARGE_SHRINK", " 1")]).allow_large_shrink);
    }

    #[test]
    fn positive_limits_reject_invalid_nonpositive_and_unsafe_values() {
        for raw in [
            "",
            "0",
            "-1",
            "+1",
            "01",
            "1.5",
            "9007199254740992",
            "999999999999999999999999",
        ] {
            assert_eq!(
                parse_positive_limit(Some(raw), 17),
                17,
                "raw value: {raw:?}"
            );
        }
        assert_eq!(parse_positive_limit(None, 17), 17);
        assert_eq!(parse_positive_limit(Some(" 23 "), 17), 23);
        assert_eq!(
            parse_positive_limit(Some("9007199254740991"), 17),
            9_007_199_254_740_991usize
        );
    }

    #[test]
    fn ratios_accept_only_finite_values_in_the_inclusive_unit_interval() {
        for raw in ["", "NaN", "inf", "-0.01", "1.01", "not-a-number"] {
            assert_eq!(parse_ratio(Some(raw), 0.5), 0.5, "raw value: {raw:?}");
        }
        assert_eq!(parse_ratio(None, 0.5), 0.5);
        assert_eq!(parse_ratio(Some("0"), 0.5), 0.0);
        assert_eq!(parse_ratio(Some("1"), 0.5), 1.0);
        assert_eq!(parse_ratio(Some(" 0.25 "), 0.5), 0.25);
    }

    #[test]
    fn url_lists_use_defaults_when_unset_or_blank_and_trim_valid_https_entries() {
        let fallback = vec![url::Url::parse("https://default.example/list").unwrap()];

        assert_eq!(parse_url_list(None, &fallback).unwrap(), fallback);
        assert_eq!(parse_url_list(Some(" \n\t "), &fallback).unwrap(), fallback);
        let parsed = parse_url_list(
            Some(" \nhttps://example.com/a\r\n  https://example.org/b  \n"),
            &fallback,
        )
        .unwrap();
        assert_eq!(
            url_strings(&parsed),
            vec!["https://example.com/a", "https://example.org/b",]
        );
    }

    #[test]
    fn url_lists_reject_every_invalid_explicit_entry() {
        let fallback = vec![url::Url::parse("https://default.example/list").unwrap()];

        for raw in [
            "http://example.com/list",
            "https://",
            "https://user:password@example.com/list",
            "https://example.com/list\nnot a URL",
        ] {
            assert!(
                parse_url_list(Some(raw), &fallback).is_err(),
                "raw value: {raw:?}"
            );
        }
    }

    #[test]
    fn cloudflare_validation_returns_credentials_or_a_safe_generic_error() {
        let config = config_from(&[
            ("CLOUDFLARE_API_TOKEN", "secret-token-value"),
            ("CLOUDFLARE_ACCOUNT_ID", "secret-account-value"),
        ]);
        assert_eq!(
            config.validate_cloudflare_env().unwrap(),
            ("secret-token-value", "secret-account-value")
        );

        let missing = config_from(&[("CLOUDFLARE_API_TOKEN", "secret-token-value")]);
        let error = missing.validate_cloudflare_env().unwrap_err().to_string();
        assert!(!error.contains("secret-token-value"));
        assert!(!error.contains("secret-account-value"));
        assert!(!error.is_empty());
    }

    #[test]
    fn config_parsing_rejects_any_invalid_explicit_list_entry() {
        let result = super::config_from_lookup(|key| match key {
            "BLOCKLIST_URLS" => {
                Some("https://valid.example/list\nhttp://invalid.example/list".to_owned())
            }
            _ => None,
        });

        assert!(result.is_err());
    }
}
