//! Filter-list parsing and domain normalization.

/// Converts a filter-list candidate into its canonical ASCII domain form.
pub fn normalize_domain(line: &str, is_allowlist: bool) -> String {
    let mut value = line;
    if is_allowlist {
        value = value.strip_prefix("@@||").unwrap_or(value);
    }

    for prefix in ["0.0.0.0", "127.0.0.1", "::1", "::"] {
        if let Some(rest) = value.strip_prefix(prefix) {
            if let Some(first) = rest.chars().next() {
                if first.is_whitespace() {
                    value = rest.trim_start_matches(char::is_whitespace);
                    break;
                }
            }
        }
    }

    value = value.strip_prefix("||").unwrap_or(value);
    if let Some(index) = value.find(['^', '$']) {
        value = &value[..index];
    }
    value = value.strip_prefix("*.").unwrap_or(value);
    canonical_domain(value)
}

/// Returns whether `value` is a valid canonicalizable multi-label domain.
pub fn is_valid_domain(value: &str) -> bool {
    let domain = canonical_domain(value);
    let labels: Vec<&str> = domain.split('.').collect();
    domain.parse::<std::net::IpAddr>().is_err()
        && (3..=253).contains(&domain.len())
        && labels.len() >= 2
        && labels.last().is_some_and(|label| label.len() >= 2)
        && labels.iter().all(|label| {
            label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

/// Returns whether a line starts with one of the supported comment markers.
pub fn is_comment(line: &str) -> bool {
    line.starts_with('#')
        || line.starts_with('!')
        || line.starts_with("//")
        || line.starts_with("/*")
}

fn canonical_domain(value: &str) -> String {
    let trimmed = value.trim();
    let without_final_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_final_dot.is_empty()
        || without_final_dot.chars().any(|ch| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    '/' | '?' | '#' | '\\' | ',' | ':' | ';' | '$' | '^' | '|' | '*'
                )
        })
    {
        return String::new();
    }
    idna::domain_to_ascii(without_final_dot)
        .map(|domain| domain.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Parsed, canonical blocklist domains and truncation statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDomains {
    pub domains: Vec<String>,
    pub truncated: bool,
    pub raw_candidates_not_processed: usize,
    pub omitted_uncovered_count: usize,
}

/// Parses blocklist and allowlist text, filtering and collapsing covered domains.
pub fn parse_domains(blocklist_raw: &str, allowlist_raw: &str, limit: usize) -> ParsedDomains {
    let mut allowlist = std::collections::HashSet::new();
    for line in allowlist_raw.lines() {
        for domain in domains_from_line(line, true) {
            if is_valid_domain(&domain) {
                allowlist.insert(domain);
            }
        }
    }

    let mut allowlisted_ancestors = std::collections::HashSet::new();
    for domain in &allowlist {
        let labels: Vec<&str> = domain.split('.').collect();
        for index in 1..labels.len() - 1 {
            allowlisted_ancestors.insert(labels[index..].join("."));
        }
    }

    let mut candidates = std::collections::HashSet::new();
    for line in blocklist_raw.lines() {
        for domain in domains_from_line(line, false) {
            if !is_valid_domain(&domain)
                || allowlist.contains(&domain)
                || allowlisted_ancestors.contains(&domain)
            {
                continue;
            }
            if has_parent_in(&domain, &allowlist) {
                continue;
            }
            candidates.insert(domain);
        }
    }

    let mut ordered: Vec<String> = candidates.into_iter().collect();
    ordered.sort_by(|left, right| {
        domain_depth(left)
            .cmp(&domain_depth(right))
            .then_with(|| left.cmp(right))
    });

    let mut domains = Vec::new();
    let mut blocked = std::collections::HashSet::new();
    let mut processed_candidates = 0;
    for domain in &ordered {
        if domains.len() >= limit {
            break;
        }
        processed_candidates += 1;
        if has_parent_in(domain, &blocked) {
            continue;
        }
        blocked.insert(domain.clone());
        domains.push(domain.clone());
    }

    let truncated = processed_candidates < ordered.len();
    let raw_candidates_not_processed = ordered.len() - processed_candidates;
    let omitted_uncovered_count = if truncated {
        let emitted: std::collections::HashSet<String> = domains.iter().cloned().collect();
        ordered
            .iter()
            .filter(|domain| !emitted.contains(*domain) && !has_parent_in(domain, &emitted))
            .count()
    } else {
        0
    };

    ParsedDomains {
        domains,
        truncated,
        raw_candidates_not_processed,
        omitted_uncovered_count,
    }
}

fn domains_from_line(line: &str, is_allowlist: bool) -> Vec<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || is_comment(trimmed) {
        return Vec::new();
    }

    let without_inline_comment = trimmed.split('#').next().unwrap_or_default().trim();
    if without_inline_comment.is_empty() {
        return Vec::new();
    }

    let mut tokens = without_inline_comment.split_whitespace();
    if let Some(first) = tokens.next() {
        if first.parse::<std::net::IpAddr>().is_ok() {
            return tokens
                .map(|token| normalize_domain(token, false))
                .filter(|domain| !domain.is_empty())
                .collect();
        }
    }

    let domain = normalize_domain(without_inline_comment, is_allowlist);
    if domain.is_empty() {
        Vec::new()
    } else {
        vec![domain]
    }
}

fn domain_depth(domain: &str) -> usize {
    domain.bytes().filter(|byte| *byte == b'.').count() + 1
}

fn has_parent_in<S: std::hash::BuildHasher>(
    domain: &str,
    domains: &std::collections::HashSet<String, S>,
) -> bool {
    let labels: Vec<&str> = domain.split('.').collect();
    (1..labels.len() - 1).any(|index| domains.contains(&labels[index..].join(".")))
}

#[cfg(test)]
mod tests {
    use super::{ParsedDomains, is_comment, is_valid_domain, normalize_domain, parse_domains};

    #[test]
    fn normalizes_hosts_adblock_wildcard_and_allowlist_syntax() {
        assert_eq!(
            normalize_domain("0.0.0.0 ads.example.com", false),
            "ads.example.com"
        );
        assert_eq!(
            normalize_domain("127.0.0.1 ads.example.com", false),
            "ads.example.com"
        );
        assert_eq!(
            normalize_domain("::1 ads.example.com", false),
            "ads.example.com"
        );
        assert_eq!(
            normalize_domain(":: ads.example.com", false),
            "ads.example.com"
        );
        assert_eq!(
            normalize_domain("||ads.example.com^$third-party", false),
            "ads.example.com"
        );
        assert_eq!(
            normalize_domain("||ads.example.com$important", false),
            "ads.example.com"
        );
        assert_eq!(
            normalize_domain("*.ads.example.com", false),
            "ads.example.com"
        );
        assert_eq!(
            normalize_domain("@@||good.example.com^", true),
            "good.example.com"
        );
    }

    #[test]
    fn canonicalizes_case_final_dot_and_unicode_idns() {
        assert_eq!(
            normalize_domain(" ADS.Example.COM. ", false),
            "ads.example.com"
        );
        assert_eq!(
            normalize_domain("пример.рф", false),
            "xn--e1afmkfd.xn--p1ai"
        );
        assert_eq!(normalize_domain("bad domain.com", false), "");
        assert_eq!(normalize_domain("a.example.com/path", false), "");
    }

    #[test]
    fn validates_canonical_domain_shape_and_rejects_ips() {
        assert!(is_valid_domain("UPPER.COM"));
        assert!(is_valid_domain("sub.example.co.uk"));
        assert!(is_valid_domain("example.xn--p1ai"));
        for invalid in [
            "",
            "localhost",
            "127.0.0.1",
            "::1",
            "-bad.com",
            "bad-.com",
            "bad..com",
            "has space.com",
            "example.c",
            "a..com",
            "a_b.com",
            "a.example.com/path",
        ] {
            assert!(!is_valid_domain(invalid), "should reject {invalid:?}");
        }
    }

    #[test]
    fn recognizes_only_comment_prefixes() {
        for comment in [
            "# hosts file",
            "! adblock title",
            "// comment",
            "/* block */",
        ] {
            assert!(is_comment(comment), "should recognize {comment:?}");
        }
        assert!(!is_comment("example.com"));
        assert!(!is_comment(" # not a prefix"));
    }

    #[test]
    fn parses_hosts_and_filter_syntax_while_skipping_comments_and_invalid_lines() {
        let parsed = parse_domains(
            "# title\n! comment\n103.179.189.35 a.example.com b.example.com # inline\n||c.example.com$important\n*.d.example.com\nnot a domain\n",
            "",
            100,
        );
        assert_eq!(
            parsed,
            ParsedDomains {
                domains: vec![
                    "a.example.com".into(),
                    "b.example.com".into(),
                    "c.example.com".into(),
                    "d.example.com".into(),
                ],
                truncated: false,
                raw_candidates_not_processed: 0,
                omitted_uncovered_count: 0,
            }
        );
    }

    #[test]
    fn allowlists_filter_exact_domains_parents_and_protected_ancestors() {
        let parsed = parse_domains(
            "example.com\ngood.example.com\nbad.example.com\nsafe.net\nsub.safe.net\nother.safe.net\n",
            "good.example.com\nsafe.net\n",
            100,
        );
        assert_eq!(parsed.domains, ["bad.example.com"]);
    }

    #[test]
    fn deduplicates_and_collapses_blocked_parents_independent_of_input_order() {
        let parent_first = parse_domains(
            "example.com\nsub.example.com\na.example.net\nb.example.net\na.example.net\n",
            "",
            100,
        );
        let child_first = parse_domains(
            "b.example.net\na.example.net\nsub.example.com\nexample.com\na.example.net\n",
            "",
            100,
        );
        assert_eq!(
            parent_first.domains,
            ["example.com", "a.example.net", "b.example.net"]
        );
        assert_eq!(child_first.domains, parent_first.domains);
    }

    #[test]
    fn reports_limit_metadata_and_excludes_candidates_covered_by_emitted_parents() {
        let parsed = parse_domains("a.com\nsub.a.com\nb.test\nc.test\n", "", 1);
        assert_eq!(
            parsed,
            ParsedDomains {
                domains: vec!["a.com".into()],
                truncated: true,
                raw_candidates_not_processed: 3,
                omitted_uncovered_count: 2,
            }
        );
    }

    #[test]
    fn zero_limit_marks_all_candidates_unprocessed() {
        let parsed = parse_domains("a.example.com\nb.example.com\n", "", 0);
        assert_eq!(
            parsed,
            ParsedDomains {
                domains: Vec::new(),
                truncated: true,
                raw_candidates_not_processed: 2,
                omitted_uncovered_count: 2,
            }
        );
    }
}
