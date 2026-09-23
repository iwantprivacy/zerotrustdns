use anyhow::Result;
use serde_json::{Value, json};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(30);
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
const MAX_GET_ATTEMPTS: usize = 3;
const LIST_CHUNK_SIZE: usize = 1000;
const RULE_NAME: &str = "zerotrustdns Filter Lists";
const RULE_DESCRIPTION: &str = "Managed by zerotrustdns. Do not rename this rule.";
const LIST_DESCRIPTION: &str = "Managed by zerotrustdns. Do not rename this list.";

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429) || (500..=599).contains(&status)
}

fn retry_after_delay(value: Option<&str>, now: SystemTime) -> Option<Duration> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    if let Ok(seconds) = value.parse::<f64>() {
        if seconds.is_finite() && seconds >= 0.0 {
            return Some(Duration::from_secs_f64(seconds.min(60.0)));
        }
    }
    let target = parse_http_date(value, now)?;
    let now = match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i128,
        Err(error) => -(error.duration().as_secs() as i128),
    };
    let seconds = (target as i128 - now).clamp(0, MAX_RETRY_AFTER.as_secs() as i128) as u64;
    Some(Duration::from_secs(seconds))
}

fn parse_http_date(value: &str, now: SystemTime) -> Option<i64> {
    let fields: Vec<&str> = value.split_whitespace().collect();
    let (day, month, year, time) = if fields.len() == 6 && fields[5] == "GMT" {
        // IMF-fixdate: Sun, 06 Nov 1994 08:49:37 GMT
        let day = fields[1].parse::<u32>().ok()?;
        let month = month_number(fields[2])?;
        let year = fields[3].parse::<i32>().ok()?;
        (day, month, year, fields[4])
    } else if fields.len() == 5 {
        // asctime: Sun Nov  6 08:49:37 1994
        let month = month_number(fields[1])?;
        let day = fields[2].parse::<u32>().ok()?;
        let year = fields[4].parse::<i32>().ok()?;
        (day, month, year, fields[3])
    } else if fields.len() == 4 && fields[3] == "GMT" {
        // RFC 850: Sunday, 06-Nov-94 08:49:37 GMT
        return parse_rfc850_date(value, now);
    } else {
        return None;
    };
    let (hour, minute, second) = parse_clock(time)?;
    civil_timestamp(year, month, day, hour, minute, second)
}

fn parse_rfc850_date(value: &str, now: SystemTime) -> Option<i64> {
    let (_, rest) = value.split_once(", ")?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() != 3 || fields[2] != "GMT" {
        return None;
    }
    let mut date = fields[0].split('-');
    let day = date.next()?.parse::<u32>().ok()?;
    let month = month_number(date.next()?)?;
    let short_year = date.next()?.parse::<i32>().ok()?;
    if date.next().is_some() || short_year > 99 {
        return None;
    }
    let now_year = year_from_timestamp(match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(error) => -(error.duration().as_secs() as i64),
    })?;
    let mut year = (now_year / 100) * 100 + short_year;
    if year > now_year + 50 {
        year -= 100;
    }
    let (hour, minute, second) = parse_clock(fields[1])?;
    civil_timestamp(year, month, day, hour, minute, second)
}

fn month_number(month: &str) -> Option<u32> {
    match month {
        "Jan" => Some(1),
        "Feb" => Some(2),
        "Mar" => Some(3),
        "Apr" => Some(4),
        "May" => Some(5),
        "Jun" => Some(6),
        "Jul" => Some(7),
        "Aug" => Some(8),
        "Sep" => Some(9),
        "Oct" => Some(10),
        "Nov" => Some(11),
        "Dec" => Some(12),
        _ => None,
    }
}

fn parse_clock(value: &str) -> Option<(u32, u32, u32)> {
    let mut fields = value.split(':');
    let hour = fields.next()?.parse::<u32>().ok()?;
    let minute = fields.next()?.parse::<u32>().ok()?;
    let second = fields.next()?.parse::<u32>().ok()?;
    if fields.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second.min(59)))
}

fn civil_timestamp(
    year: i32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Option<i64> {
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    let year = year as i64 - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let adjusted_month = month as i64 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(days * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn year_from_timestamp(timestamp: i64) -> Option<i32> {
    let days = timestamp.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    i32::try_from(year).ok()
}

fn has_foreign_description(resource: &serde_json::Value, expected: &str) -> bool {
    match resource.get("description") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::String(description)) => {
            !description.trim().is_empty() && description != expected
        }
        Some(_) => true,
    }
}

fn chunk_number(name: &str) -> Option<u64> {
    let number = name.strip_prefix("zerotrustdns List - Chunk ")?;
    if number.is_empty() || number.starts_with('0') || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let number = number.parse::<u64>().ok()?;
    (number > 0).then_some(number)
}

#[cfg(test)]
fn is_managed_list(list: &serde_json::Value) -> bool {
    list.get("type").and_then(serde_json::Value::as_str) == Some("DOMAIN")
        && list
            .get("name")
            .and_then(serde_json::Value::as_str)
            .and_then(chunk_number)
            .is_some()
        && !has_foreign_description(list, LIST_DESCRIPTION)
}

fn is_managed_rule(rule: &serde_json::Value) -> bool {
    rule.get("name").and_then(serde_json::Value::as_str) == Some(RULE_NAME)
        && !has_foreign_description(rule, RULE_DESCRIPTION)
}

fn same_values<T: Eq + std::hash::Hash>(left: &[T], right: &[T]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut counts = std::collections::HashMap::new();
    for value in left {
        *counts.entry(value).or_insert(0usize) += 1;
    }
    for value in right {
        let Some(count) = counts.get_mut(value) else {
            return false;
        };
        if *count == 0 {
            return false;
        }
        *count -= 1;
    }
    true
}

fn next_chunk_names(existing_lists: &[serde_json::Value], count: usize) -> Vec<String> {
    let mut used = std::collections::HashSet::new();
    for list in existing_lists {
        if let Some(number) = list
            .get("name")
            .and_then(serde_json::Value::as_str)
            .and_then(chunk_number)
        {
            used.insert(number);
        }
    }
    let mut names = Vec::with_capacity(count);
    let mut candidate = 1u64;
    while names.len() < count {
        if used.insert(candidate) {
            names.push(format!("zerotrustdns List - Chunk {candidate}"));
        }
        candidate = candidate.saturating_add(1);
        if candidate == u64::MAX && names.len() < count {
            break;
        }
    }
    names
}

fn normalize_traffic(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '(' && *character != ')')
        .collect()
}

fn traffic_list_ids(value: &str) -> Vec<String> {
    let bytes = value.as_bytes();
    let mut ids = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'$' {
            let start = index + 1;
            let mut end = start;
            while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'-') {
                end += 1;
            }
            if end > start {
                ids.push(value[start..end].to_owned());
            }
            index = end.max(index + 1);
        } else {
            index += 1;
        }
    }
    ids.sort();
    ids
}

fn is_verified_rule(rule: &serde_json::Value, traffic: &str) -> bool {
    let rule_description_valid = match rule.get("description") {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::String(description)) => description == RULE_DESCRIPTION,
        Some(_) => false,
    };
    let settings_valid = match rule.get("rule_settings") {
        None | Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::Object(settings)) => {
            let block_page_valid = settings
                .get("block_page_enabled")
                .is_none_or(|value| value.is_null() || value == false);
            let block_reason_valid = settings
                .get("block_reason")
                .is_none_or(|value| value.is_null() || value == "Blocked by zerotrustdns.");
            block_page_valid && block_reason_valid
        }
        Some(_) => false,
    };
    let actual_traffic = rule
        .get("traffic")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let normalized = normalize_traffic(actual_traffic);
    let traffic_shape_valid = normalized.split("or").all(|clause| {
        let Some(id) = clause.strip_prefix("anydns.domains[*]in$") else {
            return false;
        };
        !id.is_empty()
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    let expected_ids = traffic_list_ids(traffic);
    let filters_valid = rule
        .get("filters")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|filters| filters.len() == 1 && filters[0] == "dns");
    rule_description_valid
        && rule.get("enabled").and_then(serde_json::Value::as_bool) == Some(true)
        && rule.get("action").and_then(serde_json::Value::as_str) == Some("block")
        && filters_valid
        && traffic_list_ids(actual_traffic) == expected_ids
        && traffic_shape_valid
        && settings_valid
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpMethod {
    Get,
    Post,
    Patch,
    Put,
    Delete,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }

    fn is_retry_safe(self) -> bool {
        self == Self::Get
    }
}

struct HttpRequest {
    url: Url,
    method: HttpMethod,
    token: String,
    body: Option<Value>,
}

struct HttpResponse {
    status: u16,
    retry_after: Option<String>,
    body: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct TransportFailure {
    retryable: bool,
    timed_out: bool,
}

impl TransportFailure {
    #[cfg(test)]
    fn connection_reset() -> Self {
        Self {
            retryable: true,
            timed_out: false,
        }
    }
}

trait Transport: Send + Sync {
    fn send(&self, request: &HttpRequest) -> std::result::Result<HttpResponse, TransportFailure>;
}

trait Sleeper: Send + Sync {
    fn sleep(&self, duration: Duration);
}

trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self { client })
    }
}

impl Transport for ReqwestTransport {
    fn send(&self, request: &HttpRequest) -> std::result::Result<HttpResponse, TransportFailure> {
        let mut builder = self
            .client
            .request(
                reqwest::Method::from_bytes(request.method.as_str().as_bytes())
                    .expect("static HTTP method"),
                request.url.clone(),
            )
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", request.token),
            );
        if let Some(body) = &request.body {
            builder = builder.json(body);
        }
        let mut response = builder.send().map_err(classify_reqwest_failure)?;
        let status = response.status().as_u16();
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|header| header.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        response
            .copy_to(&mut body)
            .map_err(classify_reqwest_failure)?;
        Ok(HttpResponse {
            status,
            retry_after,
            body,
        })
    }
}

fn classify_reqwest_failure(error: reqwest::Error) -> TransportFailure {
    let timed_out = error.is_timeout();
    let mut retryable = timed_out || error.is_connect();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            retryable |= matches!(
                io_error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::NotConnected
            );
        }
        source = cause.source();
    }
    TransportFailure {
        retryable,
        timed_out,
    }
}

#[derive(Clone, Debug)]
struct CloudflareError {
    message: String,
    status: Option<u16>,
    provider_details: String,
    ambiguous_mutation: bool,
    rule_mutation_ambiguous: bool,
}

impl fmt::Display for CloudflareError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for CloudflareError {}

impl CloudflareError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            status: None,
            provider_details: String::new(),
            ambiguous_mutation: false,
            rule_mutation_ambiguous: false,
        }
    }
}

struct ApiClient {
    base: Url,
    token: String,
    transport: Arc<dyn Transport>,
    sleeper: Arc<dyn Sleeper>,
    clock: Arc<dyn Clock>,
}

impl ApiClient {
    fn new(token: &str, account_id: &str) -> Result<Self> {
        Self::with_parts(
            token,
            account_id,
            Arc::new(ReqwestTransport::new()?),
            Arc::new(ThreadSleeper),
            Arc::new(SystemClock),
        )
    }

    fn with_parts(
        token: &str,
        account_id: &str,
        transport: Arc<dyn Transport>,
        sleeper: Arc<dyn Sleeper>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self> {
        if token.is_empty() {
            return Err(anyhow::Error::new(CloudflareError::new(
                "Cloudflare API token is empty",
            )));
        }
        if account_id.is_empty() {
            return Err(anyhow::Error::new(CloudflareError::new(
                "Cloudflare account ID is empty",
            )));
        }
        let mut base = Url::parse("https://api.cloudflare.com/client/v4/accounts/")?;
        base.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("invalid Cloudflare API base URL"))?
            .pop_if_empty()
            .push(account_id)
            .push("gateway")
            .push("");
        Ok(Self {
            base,
            token: token.to_owned(),
            transport,
            sleeper,
            clock,
        })
    }

    fn request_json(&self, path: &str, method: HttpMethod, body: Option<&Value>) -> Result<Value> {
        let safe_path = format!("/{}", path.trim_start_matches('/'));
        let url = self.base.join(path.trim_start_matches('/'))?;
        for attempt in 1..=MAX_GET_ATTEMPTS {
            let request = HttpRequest {
                url: url.clone(),
                method,
                token: self.token.clone(),
                body: body.cloned(),
            };
            let response = match self.transport.send(&request) {
                Ok(response) => response,
                Err(failure) => {
                    let can_retry =
                        method.is_retry_safe() && failure.retryable && attempt < MAX_GET_ATTEMPTS;
                    if can_retry {
                        self.sleeper.sleep(Duration::from_secs(2 * attempt as u64));
                        continue;
                    }
                    let note = if failure.timed_out {
                        format!("Cloudflare API timeout on {safe_path}")
                    } else {
                        format!("Cloudflare API network error on {safe_path}")
                    };
                    let mut error = CloudflareError::new(note);
                    error.ambiguous_mutation = !method.is_retry_safe();
                    return Err(anyhow::Error::new(error));
                }
            };
            if response.status == 204 {
                return Ok(json!({"success": true, "result": null}));
            }
            if (200..300).contains(&response.status) {
                let payload: Value = serde_json::from_slice(&response.body).map_err(|_| {
                    let mut error = CloudflareError::new(format!(
                        "Cloudflare API returned invalid JSON on {safe_path}"
                    ));
                    error.ambiguous_mutation = !method.is_retry_safe();
                    anyhow::Error::new(error)
                })?;
                if payload.get("success") == Some(&Value::Bool(false)) {
                    let details = provider_error_details(&response.body, &self.token);
                    let suffix = if details.is_empty() {
                        String::new()
                    } else {
                        format!(": {details}")
                    };
                    let mut error = CloudflareError::new(format!(
                        "Cloudflare API rejected {safe_path}{suffix}"
                    ));
                    error.provider_details = details;
                    return Err(anyhow::Error::new(error));
                }
                return Ok(payload);
            }

            let details = provider_error_details(&response.body, &self.token);
            if method.is_retry_safe()
                && is_retryable_status(response.status)
                && attempt < MAX_GET_ATTEMPTS
            {
                let delay = if response.status == 429 {
                    retry_after_delay(response.retry_after.as_deref(), self.clock.now())
                        .unwrap_or(RATE_LIMIT_COOLDOWN)
                } else {
                    Duration::from_secs(2 * attempt as u64)
                };
                self.sleeper.sleep(delay);
                continue;
            }
            let mut message = format!("Cloudflare API error {} on {safe_path}", response.status);
            if !details.is_empty() {
                message.push_str(": ");
                message.push_str(&details);
            }
            if !method.is_retry_safe() && is_retryable_status(response.status) {
                message.push_str(" (mutation not retried after ambiguous outcome)");
            }
            if method.is_retry_safe()
                && is_retryable_status(response.status)
                && attempt == MAX_GET_ATTEMPTS
            {
                message.push_str(" (gave up after 3 attempts)");
            }
            let mut error = CloudflareError::new(message);
            error.status = Some(response.status);
            error.provider_details = details;
            error.ambiguous_mutation =
                !method.is_retry_safe() && is_retryable_status(response.status);
            return Err(anyhow::Error::new(error));
        }
        unreachable!("request attempts always return or retry")
    }
}

fn provider_error_details(body: &[u8], token: &str) -> String {
    let Ok(payload) = serde_json::from_slice::<Value>(body) else {
        return String::new();
    };
    let Some(errors) = payload.get("errors").and_then(Value::as_array) else {
        return String::new();
    };
    let mut details = errors
        .iter()
        .filter_map(|entry| {
            let value = entry
                .get("message")
                .filter(|value| !value.is_null())
                .or_else(|| entry.get("code"))?;
            match value {
                Value::String(text) => Some(text.clone()),
                Value::Number(number) => Some(number.to_string()),
                Value::Bool(boolean) => Some(boolean.to_string()),
                _ => None,
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    details = details.split_whitespace().collect::<Vec<_>>().join(" ");
    if !token.is_empty() {
        details = details.replace(token, "[REDACTED]");
    }
    details.chars().take(500).collect()
}

fn cloudflare_error(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(CloudflareError::new(message))
}

fn json_integer(value: &Value) -> Option<i128> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
    let number = match value {
        Value::Number(number) => number.as_f64()?,
        Value::String(text) => text.parse::<f64>().ok()?,
        _ => return None,
    };
    if !number.is_finite() || number.fract() != 0.0 || number.abs() > MAX_SAFE_INTEGER {
        return None;
    }
    Some(number as i128)
}

fn validate_identity_items(
    items: &[Value],
    path: &str,
    identity_key: Option<&str>,
    seen: &mut std::collections::HashSet<String>,
) -> Result<()> {
    let Some(identity_key) = identity_key else {
        return Ok(());
    };
    for item in items {
        let identity = item
            .get(identity_key)
            .and_then(Value::as_str)
            .filter(|identity| !identity.is_empty())
            .ok_or_else(|| {
                cloudflare_error(format!(
                    "Cloudflare response item missing {identity_key} for {path}"
                ))
            })?;
        if !seen.insert(identity.to_owned()) {
            return Err(cloudflare_error(format!(
                "Cloudflare response contains duplicate {identity_key} for {path}"
            )));
        }
    }
    Ok(())
}

fn fetch_all_pages(
    api: &ApiClient,
    path: &str,
    per_page: usize,
    identity_key: Option<&str>,
) -> Result<Vec<Value>> {
    let mut results = Vec::new();
    let mut page = 1u64;
    let mut expected_total_count = None;
    let mut expected_per_page = None;
    let mut expected_total_pages = None;
    let mut seen_identity_values = std::collections::HashSet::new();

    loop {
        let separator = if path.contains('?') { '&' } else { '?' };
        let request_path = format!("{path}{separator}page={page}&per_page={per_page}");
        let payload = api.request_json(&request_path, HttpMethod::Get, None)?;
        let page_results = payload
            .get("result")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                cloudflare_error(format!(
                    "Cloudflare API returned an invalid result for {path}"
                ))
            })?;
        let result_info = payload.get("result_info");
        if result_info.is_none() || result_info == Some(&Value::Null) {
            if page != 1 || page_results.len() >= per_page {
                return Err(cloudflare_error(format!(
                    "Cloudflare pagination metadata missing for {path}"
                )));
            }
            validate_identity_items(page_results, path, identity_key, &mut seen_identity_values)?;
            return Ok(page_results.clone());
        }
        let Some(result_info) = result_info.and_then(Value::as_object) else {
            return Err(cloudflare_error(format!(
                "Cloudflare pagination metadata invalid for {path}"
            )));
        };

        let reported_page = result_info.get("page").and_then(json_integer);
        let reported_total_count = result_info.get("total_count").and_then(json_integer);
        let reported_per_page = result_info
            .get("per_page")
            .and_then(json_integer)
            .filter(|value| *value != 0)
            .unwrap_or(per_page as i128);
        let has_total_pages = result_info
            .get("total_pages")
            .is_some_and(|value| !value.is_null());
        let reported_total_pages = result_info
            .get("total_pages")
            .filter(|value| !value.is_null())
            .and_then(json_integer);
        let has_count = result_info
            .get("count")
            .is_some_and(|value| !value.is_null());
        let reported_count = result_info
            .get("count")
            .filter(|value| !value.is_null())
            .and_then(json_integer);

        if !reported_page.is_some_and(|value| value > 0)
            || !reported_total_count.is_some_and(|value| value >= 0)
            || reported_per_page <= 0
            || (has_total_pages && reported_total_pages.is_none())
            || reported_total_pages.is_some_and(|value| value <= 0)
            || (has_count && reported_count.is_none())
            || reported_count.is_some_and(|value| value != page_results.len() as i128)
        {
            return Err(cloudflare_error(format!(
                "Cloudflare pagination metadata invalid for {path}"
            )));
        }
        if reported_page != Some(page as i128) {
            return Err(cloudflare_error(format!(
                "Cloudflare pagination metadata mismatch for {path}: expected page {page}, got {}",
                reported_page.unwrap_or_default()
            )));
        }
        let total_count = reported_total_count.expect("validated above") as u64;
        let response_per_page = reported_per_page as u64;
        let total_pages = reported_total_pages
            .map(|value| value as u64)
            .unwrap_or_else(|| total_count.div_ceil(response_per_page).max(1));
        if let (Some(expected_count), Some(expected_per_page), Some(expected_pages)) = (
            expected_total_count,
            expected_per_page,
            expected_total_pages,
        ) {
            if total_count != expected_count
                || response_per_page != expected_per_page
                || total_pages != expected_pages
            {
                return Err(cloudflare_error(format!(
                    "Cloudflare pagination metadata mismatch for {path}"
                )));
            }
        } else {
            expected_total_count = Some(total_count);
            expected_per_page = Some(response_per_page);
            expected_total_pages = Some(total_pages);
        }

        validate_identity_items(page_results, path, identity_key, &mut seen_identity_values)?;
        results.extend(page_results.iter().cloned());
        if page >= total_pages {
            if results.len() as u64 != expected_total_count.expect("metadata set on first page") {
                return Err(cloudflare_error(format!(
                    "Cloudflare pagination incomplete for {path}: got {}, expected {}",
                    results.len(),
                    expected_total_count.unwrap_or_default()
                )));
            }
            return Ok(results);
        }
        page += 1;
        if page > 1000 {
            return Err(cloudflare_error(format!(
                "Cloudflare pagination exceeded safety limit for {path}"
            )));
        }
    }
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

fn get_list_items(api: &ApiClient, id: &str) -> Result<Vec<Value>> {
    fetch_all_pages(
        api,
        &format!("lists/{}/items", encode_path_segment(id)),
        LIST_CHUNK_SIZE,
        None,
    )
}

fn read_list_item_values(items: &[Value], list_id: &str) -> Result<Vec<String>> {
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let value = item
                .get("value")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    cloudflare_error(format!(
                        "Malformed list item for {list_id} at index {index}"
                    ))
                })?;
            Ok(value.to_owned())
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SyncOptions {
    pub list_account_limit: usize,
    pub min_domain_retention_ratio: f64,
    pub allow_large_shrink: bool,
}

#[derive(Clone, Debug)]
struct ManagedList {
    id: String,
    name: String,
}

#[derive(Clone, Debug, Default)]
struct ListPatch {
    remove: Vec<String>,
    append: Vec<Value>,
}

#[derive(Clone, Debug)]
struct CreateSpec {
    name: String,
    items: Vec<Value>,
    values: Vec<String>,
}

struct ListPlan {
    existing: Vec<ManagedList>,
    original_items: std::collections::HashMap<String, Vec<String>>,
    patches: std::collections::HashMap<String, ListPatch>,
    create_specs: Vec<CreateSpec>,
    obsolete: Vec<ManagedList>,
    active_existing: Vec<ManagedList>,
}

#[derive(Clone, Debug)]
struct CreatedList {
    id: String,
    name: String,
}

fn list_item(value: &str, description: &str) -> Value {
    json!({"value": value, "description": description})
}

fn build_list_patch(current: &[String], target: &[String], description: &str) -> ListPatch {
    let mut target_counts = std::collections::HashMap::new();
    for value in target {
        *target_counts.entry(value.as_str()).or_insert(0usize) += 1;
    }
    let mut remove = Vec::new();
    for value in current {
        let remaining = target_counts.entry(value.as_str()).or_insert(0);
        if *remaining > 0 {
            *remaining -= 1;
        } else {
            remove.push(value.clone());
        }
    }
    let mut current_counts = std::collections::HashMap::new();
    for value in current {
        *current_counts.entry(value.as_str()).or_insert(0usize) += 1;
    }
    let mut append = Vec::new();
    for value in target {
        let remaining = current_counts.entry(value.as_str()).or_insert(0);
        if *remaining > 0 {
            *remaining -= 1;
        } else {
            append.push(list_item(value, description));
        }
    }
    ListPatch { remove, append }
}

fn patch_is_empty(patch: &ListPatch) -> bool {
    patch.remove.is_empty() && patch.append.is_empty()
}

fn patch_body(patch: &ListPatch) -> Value {
    let mut body = serde_json::Map::new();
    if !patch.remove.is_empty() {
        body.insert("remove".to_owned(), json!(patch.remove));
    }
    if !patch.append.is_empty() {
        body.insert("append".to_owned(), json!(patch.append));
    }
    Value::Object(body)
}

fn list_name_and_id_order(left: &ManagedList, right: &ManagedList) -> std::cmp::Ordering {
    chunk_number(&left.name)
        .cmp(&chunk_number(&right.name))
        .then_with(|| left.id.cmp(&right.id))
}

fn plan_lists(
    api: &ApiClient,
    all_lists: Vec<Value>,
    desired_domains: &[String],
    options: SyncOptions,
    now_description: &str,
) -> Result<ListPlan> {
    let mut seen_desired = std::collections::HashSet::new();
    let unique_domains = desired_domains
        .iter()
        .filter(|domain| seen_desired.insert(domain.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if unique_domains.is_empty() {
        return Err(cloudflare_error("Refusing to sync zero desired domains"));
    }
    if !options.min_domain_retention_ratio.is_finite() || options.min_domain_retention_ratio < 0.0 {
        return Err(cloudflare_error("Invalid minimum domain retention ratio"));
    }

    let mut named_lists = all_lists
        .iter()
        .filter(|list| {
            list.get("type").and_then(Value::as_str) == Some("DOMAIN")
                && list
                    .get("name")
                    .and_then(Value::as_str)
                    .and_then(chunk_number)
                    .is_some()
        })
        .cloned()
        .collect::<Vec<_>>();
    let foreign_named_lists = named_lists
        .iter()
        .filter(|list| has_foreign_description(list, LIST_DESCRIPTION))
        .filter_map(|list| list.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    if !foreign_named_lists.is_empty() {
        return Err(cloudflare_error(format!(
            "Cloudflare list ownership collision: {}",
            foreign_named_lists.join(", ")
        )));
    }
    let mut name_counts = std::collections::HashMap::new();
    for list in &named_lists {
        if let Some(name) = list.get("name").and_then(Value::as_str) {
            *name_counts.entry(name.to_owned()).or_insert(0usize) += 1;
        }
    }
    let duplicate_names = name_counts
        .into_iter()
        .filter_map(|(name, count)| (count > 1).then_some(name))
        .collect::<Vec<_>>();
    if !duplicate_names.is_empty() {
        return Err(cloudflare_error(format!(
            "Duplicate managed Cloudflare list names: {}",
            duplicate_names.join(", ")
        )));
    }

    let mut existing = named_lists
        .drain(..)
        .map(|list| {
            let id = list
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| cloudflare_error("Managed Cloudflare list is missing its ID"))?;
            let name = list
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| cloudflare_error("Managed Cloudflare list is missing its name"))?;
            Ok(ManagedList {
                id: id.to_owned(),
                name: name.to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    existing.sort_by(list_name_and_id_order);

    let mut original_items = std::collections::HashMap::new();
    for list in &existing {
        let values = read_list_item_values(&get_list_items(api, &list.id)?, &list.id)?;
        original_items.insert(list.id.clone(), values);
    }
    let mut owner_by_domain = std::collections::HashMap::<String, String>::new();
    for list in &existing {
        for domain in original_items.get(&list.id).into_iter().flatten() {
            owner_by_domain
                .entry(domain.clone())
                .or_insert_with(|| list.id.clone());
        }
    }
    if !options.allow_large_shrink
        && !owner_by_domain.is_empty()
        && (unique_domains.len() as f64)
            < (owner_by_domain.len() as f64) * options.min_domain_retention_ratio
    {
        return Err(cloudflare_error(format!(
            "Refusing suspicious domain shrink: {} existing domains -> {} desired domains; set CLOUDFLARE_ALLOW_LARGE_SHRINK=1 to approve",
            owner_by_domain.len(),
            unique_domains.len()
        )));
    }

    let wanted = unique_domains
        .iter()
        .map(String::as_str)
        .collect::<std::collections::HashSet<_>>();
    let mut removals_by_list = std::collections::HashMap::<String, Vec<String>>::new();
    for list in &existing {
        let mut seen = std::collections::HashSet::new();
        let removals = original_items
            .get(&list.id)
            .into_iter()
            .flatten()
            .filter(|domain| {
                let duplicate = !seen.insert(domain.as_str())
                    || owner_by_domain
                        .get(*domain)
                        .is_some_and(|owner| owner != &list.id);
                !wanted.contains(domain.as_str()) || duplicate
            })
            .cloned()
            .collect::<Vec<_>>();
        if !removals.is_empty() {
            removals_by_list.insert(list.id.clone(), removals);
        }
    }
    let mut to_add = unique_domains
        .iter()
        .filter(|domain| !owner_by_domain.contains_key(*domain))
        .cloned()
        .collect::<Vec<_>>();
    let mut patches = std::collections::HashMap::new();
    let mut add_index = 0usize;
    for list in &existing {
        let Some(removals) = removals_by_list.get(&list.id) else {
            continue;
        };
        let current_count = original_items.get(&list.id).map_or(0, Vec::len);
        let capacity = LIST_CHUNK_SIZE.saturating_sub(current_count.saturating_sub(removals.len()));
        let end = (add_index + capacity).min(to_add.len());
        let append = to_add[add_index..end]
            .iter()
            .map(|value| list_item(value, now_description))
            .collect();
        add_index = end;
        patches.insert(
            list.id.clone(),
            ListPatch {
                remove: removals.clone(),
                append,
            },
        );
    }
    for list in &existing {
        if patches.contains_key(&list.id) || add_index >= to_add.len() {
            continue;
        }
        let current_count = original_items.get(&list.id).map_or(0, Vec::len);
        let capacity = LIST_CHUNK_SIZE.saturating_sub(current_count);
        if capacity > 0 {
            let end = (add_index + capacity).min(to_add.len());
            patches.insert(
                list.id.clone(),
                ListPatch {
                    remove: Vec::new(),
                    append: to_add[add_index..end]
                        .iter()
                        .map(|value| list_item(value, now_description))
                        .collect(),
                },
            );
            add_index = end;
        }
    }
    let remaining_additions = to_add.split_off(add_index);
    let mut final_count_by_list = std::collections::HashMap::new();
    for list in &existing {
        let current_count = original_items.get(&list.id).map_or(0, Vec::len);
        let patch = patches.get(&list.id);
        final_count_by_list.insert(
            list.id.clone(),
            current_count
                .saturating_sub(patch.map_or(0, |patch| patch.remove.len()))
                .saturating_add(patch.map_or(0, |patch| patch.append.len())),
        );
    }
    let mut obsolete = existing
        .iter()
        .filter(|list| final_count_by_list.get(&list.id) == Some(&0))
        .cloned()
        .collect::<Vec<_>>();
    for list in &obsolete {
        patches.remove(&list.id);
    }

    let managed_values = named_list_values(&existing);
    let create_names = next_chunk_names(
        &managed_values,
        remaining_additions.len().div_ceil(LIST_CHUNK_SIZE),
    );
    let mut create_specs = create_names
        .into_iter()
        .zip(remaining_additions.chunks(LIST_CHUNK_SIZE))
        .map(|(name, values)| CreateSpec {
            name,
            items: values
                .iter()
                .map(|value| list_item(value, now_description))
                .collect(),
            values: values.to_vec(),
        })
        .collect::<Vec<_>>();
    let unmanaged_count = all_lists.len().saturating_sub(existing.len());
    let initial_managed_count = final_count_by_list
        .values()
        .filter(|count| **count > 0)
        .count()
        + create_specs.len();
    let mut projected_count = unmanaged_count + initial_managed_count;
    let mut active_existing = existing
        .iter()
        .filter(|list| {
            final_count_by_list
                .get(&list.id)
                .is_some_and(|count| *count > 0)
        })
        .cloned()
        .collect::<Vec<_>>();

    if projected_count > options.list_account_limit {
        let required_count = unique_domains.len().div_ceil(LIST_CHUNK_SIZE);
        active_existing = existing.iter().take(required_count).cloned().collect();
        patches.clear();
        for (index, list) in active_existing.iter().enumerate() {
            let start = index * LIST_CHUNK_SIZE;
            let end = (start + LIST_CHUNK_SIZE).min(unique_domains.len());
            let target = &unique_domains[start..end];
            let current = original_items
                .get(&list.id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            if !same_values(current, target) {
                patches.insert(
                    list.id.clone(),
                    build_list_patch(current, target, now_description),
                );
            }
        }
        obsolete = existing.iter().skip(required_count).cloned().collect();
        let missing_lists = required_count.saturating_sub(existing.len());
        let create_names = next_chunk_names(&managed_values, missing_lists);
        create_specs = create_names
            .into_iter()
            .enumerate()
            .map(|(index, name)| {
                let start = (existing.len() + index) * LIST_CHUNK_SIZE;
                let end = (start + LIST_CHUNK_SIZE).min(unique_domains.len());
                let values = unique_domains[start..end].to_vec();
                CreateSpec {
                    name,
                    items: values
                        .iter()
                        .map(|value| list_item(value, now_description))
                        .collect(),
                    values,
                }
            })
            .collect();
        projected_count = unmanaged_count + required_count;
    }
    if projected_count > options.list_account_limit {
        return Err(cloudflare_error(format!(
            "Cloudflare list quota would be exceeded: {projected_count} projected lists > {} allowed",
            options.list_account_limit
        )));
    }
    Ok(ListPlan {
        existing,
        original_items,
        patches,
        create_specs,
        obsolete,
        active_existing,
    })
}

fn named_list_values(lists: &[ManagedList]) -> Vec<Value> {
    lists
        .iter()
        .map(|list| json!({"id":list.id,"name":list.name,"type":"DOMAIN"}))
        .collect()
}

fn civil_from_timestamp(timestamp: i64) -> (i32, u32, u32) {
    let days = timestamp.div_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year as i32, month as u32, day as u32)
}

fn iso_timestamp(time: SystemTime) -> String {
    let millis = time
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0);
    let seconds = millis.div_euclid(1000);
    let sub_millis = millis.rem_euclid(1000);
    let (year, month, day) = civil_from_timestamp(seconds);
    let day_seconds = seconds.rem_euclid(86_400);
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{sub_millis:03}Z")
}

fn get_lists(api: &ApiClient) -> Result<Vec<Value>> {
    fetch_all_pages(api, "lists", LIST_CHUNK_SIZE, Some("id"))
}

fn get_rules(api: &ApiClient) -> Result<Vec<Value>> {
    fetch_all_pages(api, "rules", LIST_CHUNK_SIZE, Some("id"))
}

fn patch_list(api: &ApiClient, list_id: &str, patch: &ListPatch) -> Result<()> {
    api.request_json(
        &format!("lists/{}", encode_path_segment(list_id)),
        HttpMethod::Patch,
        Some(&patch_body(patch)),
    )?;
    Ok(())
}

fn delete_list(api: &ApiClient, list_id: &str) -> Result<()> {
    match api.request_json(
        &format!("lists/{}", encode_path_segment(list_id)),
        HttpMethod::Delete,
        None,
    ) {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<CloudflareError>()
                .and_then(|error| error.status)
                == Some(404) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn delete_rule(api: &ApiClient, rule_id: &str) -> Result<()> {
    match api.request_json(
        &format!("rules/{}", encode_path_segment(rule_id)),
        HttpMethod::Delete,
        None,
    ) {
        Ok(_) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<CloudflareError>()
                .and_then(|error| error.status)
                == Some(404) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn list_expected_after_patch(current: &[String], patch: &ListPatch) -> Vec<String> {
    let mut expected = current.to_vec();
    for removed in &patch.remove {
        if let Some(index) = expected.iter().position(|value| value == removed) {
            expected.remove(index);
        }
    }
    expected.extend(
        patch
            .append
            .iter()
            .filter_map(|item| item.get("value").and_then(Value::as_str).map(str::to_owned)),
    );
    expected
}

fn append_rollback_errors(error: anyhow::Error, failures: &[String]) -> anyhow::Error {
    if failures.is_empty() {
        return error;
    }
    let mut cloudflare_error = match error.downcast::<CloudflareError>() {
        Ok(error) => error,
        Err(error) => CloudflareError::new(error.to_string()),
    };
    cloudflare_error.message.push_str("; rollback incomplete: ");
    cloudflare_error.message.push_str(&failures.join("; "));
    anyhow::Error::new(cloudflare_error)
}

fn rollback_list_mutations(
    api: &ApiClient,
    plan: &ListPlan,
    created: &[CreatedList],
) -> Vec<String> {
    let mut failures = Vec::new();
    for list in &plan.existing {
        if !plan.patches.contains_key(&list.id) {
            continue;
        }
        let original = plan
            .original_items
            .get(&list.id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let result = (|| -> Result<()> {
            let current = read_list_item_values(&get_list_items(api, &list.id)?, &list.id)?;
            if same_values(&current, original) {
                return Ok(());
            }
            let rollback_patch = build_list_patch(&current, original, "rollback");
            let patch_error = if patch_is_empty(&rollback_patch) {
                None
            } else {
                patch_list(api, &list.id, &rollback_patch).err()
            };
            let verification = get_list_items(api, &list.id)
                .and_then(|items| read_list_item_values(&items, &list.id));
            match verification {
                Ok(verified) if same_values(&verified, original) => Ok(()),
                Ok(_) => {
                    let patch_context = patch_error
                        .as_ref()
                        .map(|error| format!("rollback PATCH failed ({error}); "))
                        .unwrap_or_default();
                    Err(cloudflare_error(format!(
                        "{patch_context}rollback verification failed for {}",
                        list.id
                    )))
                }
                Err(verification_error) => {
                    let patch_context = patch_error
                        .as_ref()
                        .map(|error| format!("rollback PATCH failed ({error}); "))
                        .unwrap_or_default();
                    Err(cloudflare_error(format!(
                        "{patch_context}rollback read-back failed for {}: {verification_error}",
                        list.id
                    )))
                }
            }
        })();
        if let Err(error) = result {
            failures.push(format!("{}: {error}", list.id));
        }
    }
    for list in created.iter().rev() {
        if let Err(error) = delete_list(api, &list.id) {
            failures.push(format!("{}: {error}", list.id));
        }
    }
    if !created.is_empty() {
        match get_lists(api) {
            Ok(lists) => {
                let present = lists
                    .iter()
                    .filter_map(|list| list.get("id").and_then(Value::as_str))
                    .collect::<std::collections::HashSet<_>>();
                for list in created {
                    if present.contains(list.id.as_str()) {
                        failures.push(format!("{}: created list remains after rollback", list.id));
                    }
                }
            }
            Err(error) => failures.push(format!("created list absence verification: {error}")),
        }
    }
    failures
}

fn stage_list_changes(api: &ApiClient, plan: &ListPlan) -> Result<Vec<CreatedList>> {
    let mut created: Vec<CreatedList> = Vec::new();
    let stage_result = (|| -> Result<()> {
        let mut expected_by_id = Vec::<(String, Vec<String>)>::new();
        for spec in &plan.create_specs {
            let payload = api.request_json(
                "lists",
                HttpMethod::Post,
                Some(&json!({
                    "name": spec.name,
                    "description": LIST_DESCRIPTION,
                    "type": "DOMAIN",
                    "items": spec.items,
                })),
            )?;
            let result = payload.get("result").unwrap_or(&Value::Null);
            let returned_id = result
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_owned);
            if let Some(id) = &returned_id {
                if plan.existing.iter().any(|list| list.id == *id) {
                    return Err(cloudflare_error(format!(
                        "Cloudflare returned a created list ID that collides with an existing list: {id}"
                    )));
                }
                if created.iter().any(|list| list.id == *id) {
                    return Err(cloudflare_error(format!(
                        "Cloudflare returned duplicate created Cloudflare list ID: {id}"
                    )));
                }
                created.push(CreatedList {
                    id: id.clone(),
                    name: spec.name.clone(),
                });
                expected_by_id.push((id.clone(), spec.values.clone()));
            }
            if returned_id.is_none()
                || result.get("name").and_then(Value::as_str) != Some(spec.name.as_str())
                || result.get("type").and_then(Value::as_str) != Some("DOMAIN")
                || has_foreign_description(result, LIST_DESCRIPTION)
            {
                return Err(cloudflare_error(format!(
                    "Cloudflare returned an invalid identity for created list {}",
                    spec.name
                )));
            }
        }

        for list in &plan.existing {
            let Some(patch) = plan.patches.get(&list.id) else {
                continue;
            };
            if patch_is_empty(patch) {
                continue;
            }
            patch_list(api, &list.id, patch)?;
            let current = plan
                .original_items
                .get(&list.id)
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            expected_by_id.push((list.id.clone(), list_expected_after_patch(current, patch)));
        }

        for (list_id, expected) in expected_by_id {
            let actual = read_list_item_values(&get_list_items(api, &list_id)?, &list_id)?;
            if !same_values(&actual, &expected) {
                return Err(cloudflare_error(format!(
                    "Cloudflare list verification failed for {list_id}"
                )));
            }
        }
        Ok(())
    })();

    if let Err(error) = stage_result {
        let failures = rollback_list_mutations(api, plan, &created);
        return Err(append_rollback_errors(error, &failures));
    }
    Ok(created)
}

fn rule_body(list_ids: &[String]) -> (Value, String) {
    let traffic = list_ids
        .iter()
        .map(|id| format!("any(dns.domains[*] in ${id})"))
        .collect::<Vec<_>>()
        .join(" or ");
    let body = json!({
        "name": RULE_NAME,
        "description": RULE_DESCRIPTION,
        "enabled": true,
        "action": "block",
        "filters": ["dns"],
        "traffic": traffic,
        "rule_settings": {
            "block_page_enabled": false,
            "block_reason": "Blocked by zerotrustdns."
        }
    });
    (body, traffic)
}

fn verify_rule_readback(
    api: &ApiClient,
    expected_id: Option<&str>,
    traffic: &str,
    require_single: bool,
) -> Result<String> {
    let rules = get_rules(api)?;
    if rules.iter().any(|rule| {
        rule.get("name").and_then(Value::as_str) == Some(RULE_NAME)
            && has_foreign_description(rule, RULE_DESCRIPTION)
    }) {
        return Err(cloudflare_error(
            "Cloudflare rule ownership collision during verification",
        ));
    }
    let managed = rules
        .iter()
        .filter(|rule| is_managed_rule(rule))
        .collect::<Vec<_>>();
    if require_single && managed.len() != 1 {
        return Err(cloudflare_error(
            "Cloudflare block rule verification failed",
        ));
    }
    let verified = match expected_id {
        Some(id) => managed
            .iter()
            .find(|rule| rule.get("id").and_then(Value::as_str) == Some(id))
            .copied(),
        None if managed.len() == 1 => managed.first().copied(),
        None => None,
    }
    .filter(|rule| is_verified_rule(rule, traffic))
    .ok_or_else(|| cloudflare_error("Cloudflare block rule verification failed"))?;
    verified
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| cloudflare_error("Verified Cloudflare rule is missing its ID"))
}

fn upsert_rule(api: &ApiClient, lists: &[ManagedList]) -> Result<()> {
    let mut list_ids = lists.iter().map(|list| list.id.clone()).collect::<Vec<_>>();
    list_ids.sort();
    list_ids.dedup();
    list_ids.retain(|id| !id.is_empty());
    if list_ids.is_empty() {
        return Err(cloudflare_error(
            "Cannot create a block rule without managed lists",
        ));
    }

    let mut write_committed = false;
    let result = (|| -> Result<()> {
        let (body, traffic) = rule_body(&list_ids);
        let existing_rules = get_rules(api)?;
        let same_name_rules = existing_rules
            .iter()
            .filter(|rule| rule.get("name").and_then(Value::as_str) == Some(RULE_NAME))
            .cloned()
            .collect::<Vec<_>>();
        if same_name_rules
            .iter()
            .any(|rule| has_foreign_description(rule, RULE_DESCRIPTION))
        {
            return Err(cloudflare_error(
                "Cloudflare rule ownership collision: a different rule already uses the managed name",
            ));
        }
        let mut managed_rules = same_name_rules;
        managed_rules.sort_by(|left, right| {
            left.get("id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .cmp(right.get("id").and_then(Value::as_str).unwrap_or(""))
        });
        let canonical = managed_rules.first().cloned();
        let duplicates = managed_rules.iter().skip(1).cloned().collect::<Vec<_>>();
        let canonical_id = if let Some(canonical) = &canonical {
            let id = canonical
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| cloudflare_error("Managed Cloudflare rule is missing its ID"))?;
            api.request_json(
                &format!("rules/{}", encode_path_segment(id)),
                HttpMethod::Put,
                Some(&body),
            )?;
            write_committed = true;
            Some(id.to_owned())
        } else {
            api.request_json("rules", HttpMethod::Post, Some(&body))?;
            write_committed = true;
            None
        };

        // Keep duplicate rules until the canonical rule is confirmed active.
        let verified_id = verify_rule_readback(
            api,
            canonical_id.as_deref(),
            &traffic,
            canonical_id.is_none(),
        )?;
        if canonical_id.is_some() {
            for duplicate in &duplicates {
                let id = duplicate.get("id").and_then(Value::as_str).ok_or_else(|| {
                    cloudflare_error("Duplicate managed Cloudflare rule is missing its ID")
                })?;
                delete_rule(api, id)?;
            }
        }

        verify_rule_readback(api, Some(&verified_id), &traffic, true)?;
        Ok(())
    })();

    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            let mut error = match error.downcast::<CloudflareError>() {
                Ok(error) => error,
                Err(error) => CloudflareError::new(error.to_string()),
            };
            error.rule_mutation_ambiguous = write_committed || error.ambiguous_mutation;
            Err(anyhow::Error::new(error))
        }
    }
}

fn sync_with_api(api: &ApiClient, desired_domains: &[String], options: SyncOptions) -> Result<()> {
    if desired_domains.is_empty() {
        return Err(cloudflare_error("Refusing to sync zero desired domains"));
    }
    if !options.min_domain_retention_ratio.is_finite() || options.min_domain_retention_ratio < 0.0 {
        return Err(cloudflare_error("Invalid minimum domain retention ratio"));
    }
    let now_description = iso_timestamp(api.clock.now());
    let all_lists = get_lists(api)?;
    let plan = plan_lists(api, all_lists, desired_domains, options, &now_description)?;
    let created = stage_list_changes(api, &plan)?;
    let mut active_lists = plan.active_existing.clone();
    active_lists.extend(created.iter().map(|list| ManagedList {
        id: list.id.clone(),
        name: list.name.clone(),
    }));
    active_lists.sort_by(list_name_and_id_order);

    if let Err(error) = upsert_rule(api, &active_lists) {
        let ambiguous = error
            .downcast_ref::<CloudflareError>()
            .is_some_and(|error| error.rule_mutation_ambiguous);
        if ambiguous {
            return Err(error);
        }
        let failures = rollback_list_mutations(api, &plan, &created);
        return Err(append_rollback_errors(error, &failures));
    }

    for list in &plan.obsolete {
        delete_list(api, &list.id)?;
    }
    if !plan.obsolete.is_empty() {
        let obsolete_ids = plan
            .obsolete
            .iter()
            .map(|list| list.id.as_str())
            .collect::<std::collections::HashSet<_>>();
        let current_lists = get_lists(api)?;
        let remaining = current_lists
            .iter()
            .filter_map(|list| list.get("id").and_then(Value::as_str))
            .filter(|id| obsolete_ids.contains(id))
            .collect::<Vec<_>>();
        if !remaining.is_empty() {
            return Err(cloudflare_error(
                "Cloudflare list deletion verification failed",
            ));
        }
    }
    Ok(())
}

pub fn sync_to_cloudflare(
    token: &str,
    account_id: &str,
    desired_domains: &[String],
    options: SyncOptions,
) -> Result<()> {
    if desired_domains.is_empty() {
        return Err(cloudflare_error("Refusing to sync zero desired domains"));
    }
    let api = ApiClient::new(token, account_id)?;
    sync_with_api(&api, desired_domains, options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, UNIX_EPOCH};

    enum MockOutcome {
        Response(HttpResponse),
        Failure(TransportFailure),
    }

    #[derive(Default)]
    struct MockTransport {
        outcomes: Mutex<VecDeque<MockOutcome>>,
        requests: Mutex<Vec<RecordedRequest>>,
    }

    #[derive(Clone)]
    struct RecordedRequest {
        url: String,
        method: HttpMethod,
        token: String,
        body: Option<serde_json::Value>,
    }

    impl MockTransport {
        fn with_outcomes(outcomes: Vec<MockOutcome>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes.into()),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Transport for MockTransport {
        fn send(
            &self,
            request: &HttpRequest,
        ) -> std::result::Result<HttpResponse, TransportFailure> {
            self.requests.lock().unwrap().push(RecordedRequest {
                url: request.url.as_str().to_owned(),
                method: request.method,
                token: request.token.to_owned(),
                body: request.body.clone(),
            });
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected transport request")
                .into_result()
        }
    }

    impl MockOutcome {
        fn into_result(self) -> std::result::Result<HttpResponse, TransportFailure> {
            match self {
                Self::Response(response) => Ok(response),
                Self::Failure(error) => Err(error),
            }
        }
    }

    #[derive(Default)]
    struct RecordingSleeper(Mutex<Vec<Duration>>);

    impl Sleeper for RecordingSleeper {
        fn sleep(&self, duration: Duration) {
            self.0.lock().unwrap().push(duration);
        }
    }

    struct FixedClock(SystemTime);

    impl Clock for FixedClock {
        fn now(&self) -> SystemTime {
            self.0
        }
    }

    fn response(status: u16, body: serde_json::Value, retry_after: Option<&str>) -> MockOutcome {
        MockOutcome::Response(HttpResponse {
            status,
            retry_after: retry_after.map(str::to_owned),
            body: serde_json::to_vec(&body).unwrap(),
        })
    }

    fn paged(result: serde_json::Value) -> serde_json::Value {
        let count = result.as_array().map_or(0, Vec::len);
        serde_json::json!({
            "success": true,
            "result": result,
            "result_info": {"page": 1, "per_page": 1000, "total_count": count, "total_pages": 1, "count": count}
        })
    }

    fn sync_options() -> SyncOptions {
        SyncOptions {
            list_account_limit: 300,
            min_domain_retention_ratio: 0.9,
            allow_large_shrink: false,
        }
    }

    fn created_list_result(id: &str, name: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "description": LIST_DESCRIPTION,
            "type": "DOMAIN"
        })
    }

    fn valid_rule(id: &str, traffic: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "name": RULE_NAME,
            "description": RULE_DESCRIPTION,
            "enabled": true,
            "action": "block",
            "filters": ["dns"],
            "traffic": traffic,
            "rule_settings": {"block_page_enabled": false, "block_reason": "Blocked by zerotrustdns."}
        })
    }

    fn test_api(
        outcomes: Vec<MockOutcome>,
        token: &str,
    ) -> (ApiClient, Arc<MockTransport>, Arc<RecordingSleeper>) {
        let transport = Arc::new(MockTransport::with_outcomes(outcomes));
        let sleeper = Arc::new(RecordingSleeper::default());
        let api = ApiClient::with_parts(
            token,
            "acct-id",
            transport.clone(),
            sleeper.clone(),
            Arc::new(FixedClock(UNIX_EPOCH)),
        )
        .unwrap();
        (api, transport, sleeper)
    }

    #[test]
    fn get_retries_only_transient_responses_and_uses_retry_after() {
        let (api, transport, sleeper) = test_api(
            vec![
                response(429, serde_json::json!({"success":false}), Some("7")),
                response(200, serde_json::json!({"success":true,"result":[]}), None),
            ],
            "test-token",
        );
        assert_eq!(
            api.request_json("lists", HttpMethod::Get, None).unwrap()["result"],
            serde_json::json!([])
        );
        assert_eq!(transport.requests().len(), 2);
        assert_eq!(
            sleeper.0.lock().unwrap().as_slice(),
            &[Duration::from_secs(7)]
        );
        assert_eq!(transport.requests()[0].token, "test-token");
        assert!(
            transport.requests()[0]
                .url
                .contains("/accounts/acct-id/gateway/lists")
        );
    }

    #[test]
    fn get_retries_at_most_three_times_with_attempt_scaled_backoff() {
        let (api, transport, sleeper) = test_api(
            vec![
                response(503, serde_json::json!({"errors":[]}), None),
                response(500, serde_json::json!({"errors":[]}), None),
                response(502, serde_json::json!({"errors":[]}), None),
            ],
            "test-token",
        );
        assert!(api.request_json("lists", HttpMethod::Get, None).is_err());
        assert_eq!(transport.requests().len(), 3);
        assert_eq!(
            sleeper.0.lock().unwrap().as_slice(),
            &[Duration::from_secs(2), Duration::from_secs(4)]
        );
    }

    #[test]
    fn mutations_are_never_retried_and_transient_outcomes_are_ambiguous() {
        let (api, transport, _) = test_api(
            vec![response(503, serde_json::json!({"errors":[]}), None)],
            "test-token",
        );
        let error = api
            .request_json(
                "lists",
                HttpMethod::Post,
                Some(&serde_json::json!({"name":"new"})),
            )
            .unwrap_err();
        assert_eq!(transport.requests().len(), 1);
        assert!(
            error
                .downcast_ref::<CloudflareError>()
                .unwrap()
                .ambiguous_mutation
        );

        let (api, transport, _) = test_api(
            vec![MockOutcome::Failure(TransportFailure::connection_reset())],
            "test-token",
        );
        let error = api
            .request_json("rules", HttpMethod::Put, Some(&serde_json::json!({})))
            .unwrap_err();
        assert_eq!(transport.requests().len(), 1);
        assert!(
            error
                .downcast_ref::<CloudflareError>()
                .unwrap()
                .ambiguous_mutation
        );
    }

    #[test]
    fn provider_errors_are_bounded_and_never_echo_the_api_token() {
        let token = "secret-api-token";
        let (api, _, _) = test_api(
            vec![response(
                400,
                serde_json::json!({"errors":[{"message":format!("invalid {token}") }]}),
                None,
            )],
            token,
        );
        let error = api
            .request_json("lists", HttpMethod::Get, None)
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("invalid [REDACTED]"));
        assert!(!text.contains(token));
    }

    #[test]
    fn pagination_collects_all_pages_and_checks_resource_identities() {
        let (api, transport, _) = test_api(
            vec![
                response(
                    200,
                    serde_json::json!({"success":true,"result":[{"id":"l1"}],"result_info":{"page":1,"per_page":1,"total_count":2,"total_pages":2,"count":1}}),
                    None,
                ),
                response(
                    200,
                    serde_json::json!({"success":true,"result":[{"id":"l2"}],"result_info":{"page":2,"per_page":1,"total_count":2,"total_pages":2,"count":1}}),
                    None,
                ),
            ],
            "token",
        );
        let items = fetch_all_pages(&api, "lists", 1, Some("id")).unwrap();
        assert_eq!(
            items,
            vec![
                serde_json::json!({"id":"l1"}),
                serde_json::json!({"id":"l2"})
            ]
        );
        let requests = transport.requests();
        assert!(requests[0].url.ends_with("lists?page=1&per_page=1"));
        assert!(requests[1].url.ends_with("lists?page=2&per_page=1"));
    }

    #[test]
    fn pagination_allows_only_short_single_page_metadata_omission() {
        let (api, _, _) = test_api(
            vec![response(
                200,
                serde_json::json!({"success":true,"result":[{"id":"l1"}]}),
                None,
            )],
            "token",
        );
        assert_eq!(
            fetch_all_pages(&api, "lists", 2, Some("id")).unwrap().len(),
            1
        );

        let (api, _, _) = test_api(
            vec![response(
                200,
                serde_json::json!({"success":true,"result":[{"id":"l1"}]}),
                None,
            )],
            "token",
        );
        let error = fetch_all_pages(&api, "lists", 1, Some("id")).unwrap_err();
        assert!(error.to_string().contains("pagination metadata missing"));
    }

    #[test]
    fn pagination_fails_closed_on_metadata_changes_and_duplicate_ids() {
        let (api, _, _) = test_api(
            vec![
                response(
                    200,
                    serde_json::json!({"success":true,"result":[{"id":"l1"}],"result_info":{"page":1,"per_page":1,"total_count":2,"total_pages":2}}),
                    None,
                ),
                response(
                    200,
                    serde_json::json!({"success":true,"result":[{"id":"l2"}],"result_info":{"page":2,"per_page":1,"total_count":3,"total_pages":3}}),
                    None,
                ),
            ],
            "token",
        );
        assert!(
            fetch_all_pages(&api, "lists", 1, Some("id"))
                .unwrap_err()
                .to_string()
                .contains("pagination metadata mismatch")
        );

        let (api, _, _) = test_api(
            vec![
                response(
                    200,
                    serde_json::json!({"success":true,"result":[{"id":"same"}],"result_info":{"page":1,"per_page":1,"total_count":2,"total_pages":2}}),
                    None,
                ),
                response(
                    200,
                    serde_json::json!({"success":true,"result":[{"id":"same"}],"result_info":{"page":2,"per_page":1,"total_count":2,"total_pages":2}}),
                    None,
                ),
            ],
            "token",
        );
        assert!(
            fetch_all_pages(&api, "lists", 1, Some("id"))
                .unwrap_err()
                .to_string()
                .contains("duplicate id")
        );
    }

    #[test]
    fn pagination_rejects_present_but_invalid_count_and_total_pages_fields() {
        let (api, _, _) = test_api(
            vec![response(
                200,
                serde_json::json!({
                    "success":true,
                    "result":[{"id":"l1"}],
                    "result_info":{"page":1,"per_page":1,"total_count":1,"total_pages":1,"count":"bad"}
                }),
                None,
            )],
            "token",
        );
        assert!(fetch_all_pages(&api, "lists", 1, Some("id")).is_err());

        let (api, _, _) = test_api(
            vec![response(
                200,
                serde_json::json!({
                    "success":true,
                    "result":[{"id":"l1"}],
                    "result_info":{"page":1,"per_page":1,"total_count":1,"total_pages":"bad"}
                }),
                None,
            )],
            "token",
        );
        assert!(fetch_all_pages(&api, "lists", 1, Some("id")).is_err());
    }

    #[test]
    fn non_retryable_get_status_fails_fast() {
        let (api, transport, sleeper) = test_api(
            vec![response(401, serde_json::json!({"errors":[]}), None)],
            "token",
        );
        let error = api
            .request_json("lists", HttpMethod::Get, None)
            .unwrap_err();
        assert!(error.to_string().contains("Cloudflare API error 401"));
        assert_eq!(transport.requests().len(), 1);
        assert!(sleeper.0.lock().unwrap().is_empty());
    }

    #[test]
    fn retries_only_transient_cloudflare_statuses() {
        for status in [408, 425, 429, 500, 502, 503, 504] {
            assert!(is_retryable_status(status), "{status}");
        }
        for status in [400, 401, 403, 404, 422, 600] {
            assert!(!is_retryable_status(status), "{status}");
        }
    }

    #[test]
    fn retry_after_supports_seconds_dates_and_caps() {
        assert_eq!(
            retry_after_delay(Some("0"), UNIX_EPOCH),
            Some(Duration::ZERO)
        );
        assert_eq!(
            retry_after_delay(Some("2"), UNIX_EPOCH),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            retry_after_delay(Some("999"), UNIX_EPOCH),
            Some(Duration::from_secs(60))
        );
        assert_eq!(retry_after_delay(Some("invalid"), UNIX_EPOCH), None);
        assert_eq!(
            retry_after_delay(Some("Thu, 01 Jan 1970 00:00:05 GMT"), UNIX_EPOCH),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            retry_after_delay(Some("Thu Jan  1 00:00:05 1970"), UNIX_EPOCH),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            retry_after_delay(Some("Thursday, 01-Jan-70 00:00:05 GMT"), UNIX_EPOCH),
            Some(Duration::from_secs(5))
        );
        assert_eq!(
            retry_after_delay(Some("Wed, 21 Oct 2015 07:28:00 GMT"), UNIX_EPOCH),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn managed_resource_ownership_requires_exact_identity_and_safe_description() {
        assert!(is_managed_list(&serde_json::json!({
            "type": "DOMAIN", "name": "zerotrustdns List - Chunk 1"
        })));
        assert!(is_managed_list(&serde_json::json!({
            "type": "DOMAIN", "name": "zerotrustdns List - Chunk 1", "description": ""
        })));
        assert!(is_managed_list(&serde_json::json!({
            "type": "DOMAIN", "name": "zerotrustdns List - Chunk 1", "description": LIST_DESCRIPTION
        })));
        for resource in [
            serde_json::json!({"type":"EMAIL", "name":"zerotrustdns List - Chunk 1"}),
            serde_json::json!({"type":"DOMAIN", "name":"zerotrustdns List - Chunk 01"}),
            serde_json::json!({"type":"DOMAIN", "name":"zerotrustdns List - Chunk 1", "description":"foreign"}),
            serde_json::json!({"type":"DOMAIN", "name":"zerotrustdns List - Chunk 1", "description":{"owner":"foreign"}}),
        ] {
            assert!(!is_managed_list(&resource), "{resource}");
        }
        assert!(is_managed_rule(&serde_json::json!({"name": RULE_NAME})));
        assert!(!is_managed_rule(
            &serde_json::json!({"name": RULE_NAME, "description": "foreign"})
        ));
    }

    #[test]
    fn list_equality_is_a_multiset_comparison() {
        assert!(same_values(&["a", "b", "a"], &["b", "a", "a"]));
        assert!(!same_values(&["a", "a"], &["a"]));
        assert!(!same_values(&["a", "b"], &["a", "c"]));
    }

    #[test]
    fn new_chunk_names_use_the_lowest_unused_positive_number() {
        let lists = vec![
            serde_json::json!({"name":"zerotrustdns List - Chunk 1"}),
            serde_json::json!({"name":"zerotrustdns List - Chunk 3"}),
            serde_json::json!({"name":"zerotrustdns List - Chunk 8"}),
        ];
        assert_eq!(
            next_chunk_names(&lists, 4),
            vec![
                "zerotrustdns List - Chunk 2",
                "zerotrustdns List - Chunk 4",
                "zerotrustdns List - Chunk 5",
                "zerotrustdns List - Chunk 6",
            ]
        );
    }

    #[test]
    fn rule_readback_requires_a_single_blocking_dns_clause_for_each_target_id() {
        let valid = serde_json::json!({
            "description": RULE_DESCRIPTION,
            "enabled": true,
            "action": "block",
            "filters": ["dns"],
            "traffic": "( any ( dns.domains[*] in $list-b ) ) or any(dns.domains[*] in $list-a)",
            "rule_settings": {"block_page_enabled": false, "block_reason": "Blocked by zerotrustdns."}
        });
        assert!(is_verified_rule(
            &valid,
            "any(dns.domains[*] in $list-a) or any(dns.domains[*] in $list-b)"
        ));
        for invalid in [
            serde_json::json!({"enabled":false,"action":"block","filters":["dns"],"traffic":"any(dns.domains[*] in $list-a)"}),
            serde_json::json!({"enabled":true,"action":"allow","filters":["dns"],"traffic":"any(dns.domains[*] in $list-a)"}),
            serde_json::json!({"enabled":true,"action":"block","filters":["http"],"traffic":"any(dns.domains[*] in $list-a)"}),
            serde_json::json!({"enabled":true,"action":"block","filters":["dns"],"traffic":"any(dns.domains[*] in $list-a) or ip.src in $list-b"}),
            serde_json::json!({"enabled":true,"action":"block","filters":["dns"],"traffic":"any(dns.domains[*] in $list-a)","rule_settings":{"block_page_enabled":true}}),
        ] {
            assert!(
                !is_verified_rule(&invalid, "any(dns.domains[*] in $list-a)"),
                "{invalid}"
            );
        }
    }

    #[test]
    fn empty_desired_domains_fail_before_any_cloudflare_request() {
        let (api, transport, _) = test_api(Vec::new(), "token");
        assert!(sync_with_api(&api, &[], sync_options()).is_err());
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn full_sync_authenticates_creates_verifies_and_upserts_exact_block_rule() {
        let name = "zerotrustdns List - Chunk 1";
        let traffic = "any(dns.domains[*] in $list-1)";
        let (api, transport, sleeper) = test_api(
            vec![
                response(200, paged(serde_json::json!([])), None),
                response(
                    200,
                    serde_json::json!({"success":true,"result":created_list_result("list-1", name)}),
                    None,
                ),
                response(
                    200,
                    paged(serde_json::json!([{"value":"a.example"},{"value":"b.example"}])),
                    None,
                ),
                response(200, paged(serde_json::json!([])), None),
                response(200, serde_json::json!({"success":true,"result":{}}), None),
                response(
                    200,
                    paged(serde_json::json!([valid_rule("rule-1", traffic)])),
                    None,
                ),
                response(
                    200,
                    paged(serde_json::json!([valid_rule("rule-1", traffic)])),
                    None,
                ),
            ],
            "test-token",
        );
        sync_with_api(
            &api,
            &["a.example".into(), "b.example".into()],
            sync_options(),
        )
        .unwrap();
        let requests = transport.requests();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.method)
                .collect::<Vec<_>>(),
            [
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Get,
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Get,
                HttpMethod::Get
            ]
        );
        assert!(requests.iter().all(|request| request.token == "test-token"));
        assert!(
            requests[0]
                .url
                .starts_with("https://api.cloudflare.com/client/v4/accounts/acct-id/gateway/")
        );
        assert_eq!(requests[1].body.as_ref().unwrap()["name"], name);
        assert_eq!(requests[1].body.as_ref().unwrap()["type"], "DOMAIN");
        assert_eq!(requests[4].body.as_ref().unwrap()["traffic"], traffic);
        assert_eq!(requests[4].body.as_ref().unwrap()["action"], "block");
        assert!(sleeper.0.lock().unwrap().is_empty());
    }

    #[test]
    fn duplicate_created_list_ids_fail_closed_before_rule_write() {
        let first_name = "zerotrustdns List - Chunk 1";
        let second_name = "zerotrustdns List - Chunk 2";
        let (api, transport, _) = test_api(
            vec![
                response(200, paged(serde_json::json!([])), None),
                response(
                    200,
                    serde_json::json!({"success":true,"result":created_list_result("duplicate-id", first_name)}),
                    None,
                ),
                response(
                    200,
                    serde_json::json!({"success":true,"result":created_list_result("duplicate-id", second_name)}),
                    None,
                ),
                response(204, serde_json::Value::Null, None),
                response(200, paged(serde_json::json!([])), None),
                response(204, serde_json::Value::Null, None),
                response(200, paged(serde_json::json!([])), None),
            ],
            "token",
        );
        let domains = (0..1001)
            .map(|index| format!("domain-{index}.example"))
            .collect::<Vec<_>>();

        let error = sync_with_api(&api, &domains, sync_options()).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("duplicate created Cloudflare list ID")
        );
        let requests = transport.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == HttpMethod::Post)
                .count(),
            2
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == HttpMethod::Delete)
                .count(),
            1
        );
        assert!(
            requests
                .iter()
                .all(|request| !request.url.contains("/rules"))
        );
    }

    #[test]
    fn created_list_id_collision_with_existing_resource_never_deletes_it() {
        let existing_domains = (0..1000)
            .map(|index| format!("existing-{index}.example"))
            .collect::<Vec<_>>();
        let existing_items = paged(serde_json::Value::Array(
            existing_domains
                .iter()
                .map(|value| serde_json::json!({"value":value}))
                .collect(),
        ));
        let (api, transport, _) = test_api(
            vec![
                response(
                    200,
                    paged(serde_json::json!([{
                        "id":"existing-id",
                        "name":"zerotrustdns List - Chunk 1",
                        "type":"DOMAIN"
                    }])),
                    None,
                ),
                response(200, existing_items.clone(), None),
                response(
                    200,
                    serde_json::json!({
                        "success":true,
                        "result":created_list_result("existing-id", "zerotrustdns List - Chunk 2")
                    }),
                    None,
                ),
                response(200, existing_items, None),
                response(204, serde_json::Value::Null, None),
                response(200, paged(serde_json::json!([])), None),
            ],
            "token",
        );
        let mut desired = existing_domains;
        desired.push("new.example".to_owned());

        let error = sync_with_api(&api, &desired, sync_options()).unwrap_err();

        assert!(error.to_string().contains("collides with an existing list"));
        assert!(
            transport
                .requests()
                .iter()
                .all(|request| request.method != HttpMethod::Delete)
        );
    }

    #[test]
    fn definitive_rule_write_failure_rolls_back_created_lists() {
        let name = "zerotrustdns List - Chunk 1";
        let (api, transport, _) = test_api(
            vec![
                response(200, paged(serde_json::json!([])), None),
                response(
                    200,
                    serde_json::json!({"success":true,"result":created_list_result("list-1", name)}),
                    None,
                ),
                response(
                    200,
                    paged(serde_json::json!([{"value":"new.example"}])),
                    None,
                ),
                response(200, paged(serde_json::json!([])), None),
                response(
                    403,
                    serde_json::json!({"errors":[{"message":"forbidden"}]}),
                    None,
                ),
                response(204, serde_json::Value::Null, None),
                response(200, paged(serde_json::json!([])), None),
            ],
            "token",
        );
        let error = sync_with_api(&api, &["new.example".into()], sync_options()).unwrap_err();
        assert!(
            !error
                .downcast_ref::<CloudflareError>()
                .unwrap()
                .rule_mutation_ambiguous
        );
        let requests = transport.requests();
        let rule_write = requests
            .iter()
            .position(|request| {
                request.url.ends_with("/rules") && request.method == HttpMethod::Post
            })
            .unwrap();
        let created_delete = requests
            .iter()
            .position(|request| {
                request.url.ends_with("/lists/list-1") && request.method == HttpMethod::Delete
            })
            .unwrap();
        assert!(created_delete > rule_write);
        assert_eq!(requests.last().unwrap().method, HttpMethod::Get);
    }

    #[test]
    fn ambiguous_rule_write_keeps_staged_lists_without_rollback() {
        let name = "zerotrustdns List - Chunk 1";
        let (api, transport, _) = test_api(
            vec![
                response(200, paged(serde_json::json!([])), None),
                response(
                    200,
                    serde_json::json!({"success":true,"result":created_list_result("list-1", name)}),
                    None,
                ),
                response(
                    200,
                    paged(serde_json::json!([{"value":"new.example"}])),
                    None,
                ),
                response(200, paged(serde_json::json!([])), None),
                response(503, serde_json::json!({"errors":[]}), None),
            ],
            "token",
        );
        let error = sync_with_api(&api, &["new.example".into()], sync_options()).unwrap_err();
        assert!(
            error
                .downcast_ref::<CloudflareError>()
                .unwrap()
                .rule_mutation_ambiguous
        );
        assert!(
            transport
                .requests()
                .iter()
                .all(|request| request.method != HttpMethod::Delete)
        );
        assert_eq!(
            transport.requests().last().unwrap().method,
            HttpMethod::Post
        );
    }

    #[test]
    fn obsolete_list_delete_waits_for_rule_verification_and_404_is_idempotent() {
        let lists = serde_json::json!([
            {"id":"list-1","name":"zerotrustdns List - Chunk 1","type":"DOMAIN"},
            {"id":"list-2","name":"zerotrustdns List - Chunk 2","type":"DOMAIN"}
        ]);
        let traffic = "any(dns.domains[*] in $list-1)";
        let (api, transport, _) = test_api(
            vec![
                response(200, paged(lists), None),
                response(
                    200,
                    paged(serde_json::json!([{"value":"keep.example"}])),
                    None,
                ),
                response(
                    200,
                    paged(serde_json::json!([{"value":"remove.example"}])),
                    None,
                ),
                response(200, paged(serde_json::json!([])), None),
                response(200, serde_json::json!({"success":true,"result":{}}), None),
                response(
                    200,
                    paged(serde_json::json!([valid_rule("rule-1", traffic)])),
                    None,
                ),
                response(
                    200,
                    paged(serde_json::json!([valid_rule("rule-1", traffic)])),
                    None,
                ),
                response(404, serde_json::json!({"errors":[]}), None),
                response(
                    200,
                    paged(
                        serde_json::json!([{"id":"list-1","name":"zerotrustdns List - Chunk 1","type":"DOMAIN"}]),
                    ),
                    None,
                ),
            ],
            "token",
        );
        let mut options = sync_options();
        options.min_domain_retention_ratio = 0.0;
        sync_with_api(&api, &["keep.example".into()], options).unwrap();
        let requests = transport.requests();
        let rule_verify = requests
            .iter()
            .rposition(|request| {
                request.url.ends_with("/rules?page=1&per_page=1000")
                    && request.method == HttpMethod::Get
                    && request.url.contains("gateway/rules")
            })
            .unwrap();
        let obsolete_delete = requests
            .iter()
            .position(|request| {
                request.url.ends_with("/lists/list-2") && request.method == HttpMethod::Delete
            })
            .unwrap();
        assert!(obsolete_delete > rule_verify);
        assert_eq!(requests.last().unwrap().method, HttpMethod::Get);
        assert!(
            requests
                .last()
                .unwrap()
                .url
                .ends_with("/lists?page=1&per_page=1000")
        );
    }

    #[test]
    fn account_quota_counts_unmanaged_resources_before_any_mutation() {
        let (api, transport, _) = test_api(
            vec![response(
                200,
                paged(serde_json::json!([{"id":"unmanaged","name":"other","type":"DOMAIN"}])),
                None,
            )],
            "token",
        );
        let mut options = sync_options();
        options.list_account_limit = 1;
        let error = sync_with_api(&api, &["new.example".into()], options).unwrap_err();
        assert!(error.to_string().contains("quota would be exceeded"));
        assert_eq!(transport.requests().len(), 1);
        assert_eq!(transport.requests()[0].method, HttpMethod::Get);
    }

    #[test]
    fn suspicious_shrink_and_ownership_collisions_fail_before_mutations() {
        let existing_domains = (0..10)
            .map(|index| format!("existing-{index}.example"))
            .collect::<Vec<_>>();
        let item_response = paged(serde_json::Value::Array(
            existing_domains
                .iter()
                .map(|value| serde_json::json!({"value":value}))
                .collect(),
        ));
        let (api, transport, _) = test_api(
            vec![
                response(
                    200,
                    paged(
                        serde_json::json!([{"id":"list-1","name":"zerotrustdns List - Chunk 1","type":"DOMAIN"}]),
                    ),
                    None,
                ),
                response(200, item_response, None),
            ],
            "token",
        );
        let error =
            sync_with_api(&api, &[existing_domains[0].clone()], sync_options()).unwrap_err();
        assert!(error.to_string().contains("suspicious domain shrink"));
        assert!(
            transport
                .requests()
                .iter()
                .all(|request| request.method == HttpMethod::Get)
        );

        let (api, transport, _) = test_api(
            vec![response(
                200,
                paged(
                    serde_json::json!([{"id":"foreign","name":"zerotrustdns List - Chunk 1","description":"foreign owner","type":"DOMAIN"}]),
                ),
                None,
            )],
            "token",
        );
        let error = sync_with_api(&api, &["desired.example".into()], sync_options()).unwrap_err();
        assert!(error.to_string().contains("ownership collision"));
        assert_eq!(transport.requests().len(), 1);
    }

    #[test]
    fn domain_inputs_are_deduplicated_and_split_into_1000_item_chunks() {
        let mut domains = (0..1000)
            .map(|index| format!("domain-{index}.example"))
            .collect::<Vec<_>>();
        domains.push("domain-0.example".to_owned());
        domains.push("domain-1000.example".to_owned());
        let (api, _, _) = test_api(Vec::new(), "token");
        let plan = plan_lists(
            &api,
            Vec::new(),
            &domains,
            sync_options(),
            "1970-01-01T00:00:00.000Z",
        )
        .unwrap();
        assert_eq!(plan.create_specs.len(), 2);
        assert_eq!(plan.create_specs[0].name, "zerotrustdns List - Chunk 1");
        assert_eq!(plan.create_specs[0].items.len(), 1000);
        assert_eq!(plan.create_specs[1].name, "zerotrustdns List - Chunk 2");
        assert_eq!(plan.create_specs[1].items.len(), 1);
        assert_eq!(plan.create_specs[0].values[0], "domain-0.example");
    }

    #[test]
    fn quota_pressure_compacts_scattered_domains_into_required_chunks() {
        let count = 301usize;
        let lists = (0..count)
            .map(|index| {
                serde_json::json!({
                    "id": format!("list-{}", index + 1),
                    "name": format!("zerotrustdns List - Chunk {}", index + 1),
                    "type": "DOMAIN"
                })
            })
            .collect::<Vec<_>>();
        let domains = (0..count)
            .map(|index| format!("domain-{index}.example"))
            .collect::<Vec<_>>();
        let item_responses = domains
            .iter()
            .map(|domain| response(200, paged(serde_json::json!([{"value":domain}])), None))
            .collect();
        let (api, _, _) = test_api(item_responses, "token");
        let mut options = sync_options();
        options.list_account_limit = 300;
        let plan = plan_lists(&api, lists, &domains, options, "1970-01-01T00:00:00.000Z").unwrap();
        assert_eq!(plan.active_existing.len(), 1);
        assert_eq!(plan.active_existing[0].id, "list-1");
        assert_eq!(plan.obsolete.len(), 300);
        assert_eq!(plan.create_specs.len(), 0);
        assert_eq!(plan.patches.len(), 1);
        let patch = plan.patches.get("list-1").unwrap();
        assert!(patch.remove.is_empty());
        assert_eq!(patch.append.len(), 300);
    }

    #[test]
    fn rule_upsert_updates_one_canonical_rule_then_removes_duplicates() {
        let traffic = "any(dns.domains[*] in $list-1)";
        let existing_rules = serde_json::json!([
            {"id":"r2","name":RULE_NAME},
            {"id":"r1","name":RULE_NAME}
        ]);
        let (api, transport, _) = test_api(
            vec![
                response(
                    200,
                    paged(
                        serde_json::json!([{"id":"list-1","name":"zerotrustdns List - Chunk 1","type":"DOMAIN"}]),
                    ),
                    None,
                ),
                response(
                    200,
                    paged(serde_json::json!([{"value":"keep.example"}])),
                    None,
                ),
                response(200, paged(existing_rules), None),
                response(200, serde_json::json!({"success":true,"result":{}}), None),
                response(
                    200,
                    paged(serde_json::json!([
                        valid_rule("r1", traffic),
                        valid_rule("r2", traffic)
                    ])),
                    None,
                ),
                response(404, serde_json::json!({"errors":[]}), None),
                response(
                    200,
                    paged(serde_json::json!([valid_rule("r1", traffic)])),
                    None,
                ),
            ],
            "token",
        );
        sync_with_api(&api, &["keep.example".into()], sync_options()).unwrap();
        let requests = transport.requests();
        let put = requests
            .iter()
            .position(|request| request.method == HttpMethod::Put)
            .unwrap();
        let delete = requests
            .iter()
            .position(|request| request.method == HttpMethod::Delete)
            .unwrap();
        let verifications = requests
            .iter()
            .enumerate()
            .filter_map(|(index, request)| {
                (request.method == HttpMethod::Get && request.url.contains("/rules?"))
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        assert_eq!(verifications.len(), 3);
        assert!(put < verifications[1] && verifications[1] < delete && delete < verifications[2]);
        assert!(requests[put].url.ends_with("/rules/r1"));
        assert!(requests[delete].url.ends_with("/rules/r2"));
    }

    #[test]
    fn failed_canonical_rule_readback_preserves_duplicate_rules() {
        let expected_traffic = "any(dns.domains[*] in $list-1)";
        let wrong_traffic = "any(dns.domains[*] in $old-list)";
        let invalid_readback = paged(serde_json::json!([
            valid_rule("r1", wrong_traffic),
            valid_rule("r2", expected_traffic)
        ]));
        let (api, transport, _) = test_api(
            vec![
                response(
                    200,
                    paged(serde_json::json!([
                        {"id":"r1","name":RULE_NAME},
                        {"id":"r2","name":RULE_NAME}
                    ])),
                    None,
                ),
                response(200, serde_json::json!({"success":true,"result":{}}), None),
                response(200, invalid_readback.clone(), None),
                response(200, invalid_readback, None),
            ],
            "token",
        );

        let error = upsert_rule(
            &api,
            &[ManagedList {
                id: "list-1".to_owned(),
                name: "zerotrustdns List - Chunk 1".to_owned(),
            }],
        )
        .unwrap_err();

        assert!(error.to_string().contains("block rule verification failed"));
        assert!(
            transport
                .requests()
                .iter()
                .all(|request| request.method != HttpMethod::Delete)
        );
    }

    #[test]
    fn rule_upsert_rejects_an_empty_managed_list_set_without_api_calls() {
        let (api, transport, _) = test_api(Vec::new(), "token");
        let error = upsert_rule(&api, &[]).unwrap_err();
        assert!(error.to_string().contains("without managed lists"));
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn later_patch_failure_restores_earlier_list_mutations_and_verifies_multisets() {
        let left_original = (0..1000)
            .map(|index| format!("left-{index}.example"))
            .collect::<Vec<_>>();
        let right_original = (0..1000)
            .map(|index| format!("right-{index}.example"))
            .collect::<Vec<_>>();
        let mut left_after_patch = left_original[..999].to_vec();
        left_after_patch.push("new-left.example".to_owned());
        let desired = left_original[..999]
            .iter()
            .chain(right_original[..999].iter())
            .cloned()
            .chain([
                "new-left.example".to_owned(),
                "new-right.example".to_owned(),
            ])
            .collect::<Vec<_>>();
        let values_payload = |values: &[String]| {
            paged(serde_json::Value::Array(
                values
                    .iter()
                    .map(|value| serde_json::json!({"value":value}))
                    .collect(),
            ))
        };
        let (api, transport, _) = test_api(
            vec![
                response(
                    200,
                    paged(serde_json::json!([
                        {"id":"l1","name":"zerotrustdns List - Chunk 1","type":"DOMAIN"},
                        {"id":"l2","name":"zerotrustdns List - Chunk 2","type":"DOMAIN"}
                    ])),
                    None,
                ),
                response(200, values_payload(&left_original), None),
                response(200, values_payload(&right_original), None),
                response(200, serde_json::json!({"success":true,"result":{}}), None),
                response(
                    400,
                    serde_json::json!({"errors":[{"message":"patch rejected"}]}),
                    None,
                ),
                response(200, values_payload(&left_after_patch), None),
                response(200, serde_json::json!({"success":true,"result":{}}), None),
                response(200, values_payload(&left_original), None),
                response(200, values_payload(&right_original), None),
            ],
            "token",
        );
        let error = sync_with_api(&api, &desired, sync_options()).unwrap_err();
        assert_eq!(
            error.downcast_ref::<CloudflareError>().unwrap().status,
            Some(400)
        );
        let requests = transport.requests();
        assert_eq!(requests[3].method, HttpMethod::Patch);
        assert_eq!(requests[4].method, HttpMethod::Patch);
        assert_eq!(requests[6].method, HttpMethod::Patch);
        assert_eq!(
            requests[6].body.as_ref().unwrap()["remove"],
            serde_json::json!(["new-left.example"])
        );
        assert_eq!(
            requests[6].body.as_ref().unwrap()["append"][0]["value"],
            "left-999.example"
        );
        assert_eq!(
            requests[6].body.as_ref().unwrap()["append"][0]["description"],
            "rollback"
        );
        assert!(requests.last().unwrap().url.contains("/lists/l2/items"));
    }

    #[test]
    fn changed_list_readback_mismatch_triggers_compensation_before_rule_write() {
        let original = vec!["old.example".to_owned()];
        let wrong = vec!["wrong.example".to_owned()];
        let item_page = |values: &[String]| {
            paged(serde_json::Value::Array(
                values
                    .iter()
                    .map(|value| serde_json::json!({"value":value}))
                    .collect(),
            ))
        };
        let (api, transport, _) = test_api(
            vec![
                response(
                    200,
                    paged(
                        serde_json::json!([{"id":"l1","name":"zerotrustdns List - Chunk 1","type":"DOMAIN"}]),
                    ),
                    None,
                ),
                response(200, item_page(&original), None),
                response(200, serde_json::json!({"success":true,"result":{}}), None),
                response(200, item_page(&wrong), None),
                response(200, item_page(&wrong), None),
                response(200, serde_json::json!({"success":true,"result":{}}), None),
                response(200, item_page(&original), None),
            ],
            "token",
        );
        let error = sync_with_api(&api, &["new.example".into()], sync_options()).unwrap_err();
        assert!(error.to_string().contains("list verification failed"));
        let requests = transport.requests();
        assert_eq!(requests[5].method, HttpMethod::Patch);
        assert_eq!(
            requests[5].body.as_ref().unwrap()["remove"],
            serde_json::json!(["wrong.example"])
        );
        assert_eq!(
            requests[5].body.as_ref().unwrap()["append"][0]["value"],
            "old.example"
        );
        assert!(
            requests
                .iter()
                .all(|request| !request.url.contains("/rules"))
        );
    }

    #[test]
    fn ambiguous_rollback_patch_is_read_back_before_reporting_failure() {
        let original = vec!["old.example".to_owned()];
        let current = vec!["new.example".to_owned()];
        let page = |values: &[String]| {
            paged(serde_json::Value::Array(
                values
                    .iter()
                    .map(|value| serde_json::json!({"value":value}))
                    .collect(),
            ))
        };
        let plan = ListPlan {
            existing: vec![ManagedList {
                id: "list-1".to_owned(),
                name: "zerotrustdns List - Chunk 1".to_owned(),
            }],
            original_items: std::collections::HashMap::from([(
                "list-1".to_owned(),
                original.clone(),
            )]),
            patches: std::collections::HashMap::from([(
                "list-1".to_owned(),
                ListPatch {
                    remove: vec!["old.example".to_owned()],
                    append: vec![list_item("new.example", "forward")],
                },
            )]),
            create_specs: Vec::new(),
            obsolete: Vec::new(),
            active_existing: Vec::new(),
        };
        let (api, transport, _) = test_api(
            vec![
                response(200, page(&current), None),
                response(
                    503,
                    serde_json::json!({"errors":[{"message":"temporary failure"}]}),
                    None,
                ),
                response(200, page(&original), None),
            ],
            "token",
        );

        let failures = rollback_list_mutations(&api, &plan, &[]);

        assert!(failures.is_empty(), "{failures:?}");
        let requests = transport.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, HttpMethod::Get);
        assert_eq!(requests[1].method, HttpMethod::Patch);
        assert_eq!(requests[2].method, HttpMethod::Get);
    }
}
