//! Safe, bounded downloads for configured filter sources.

use std::io::Read;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow};
use reqwest::blocking::{Client, Response};
use url::Url;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct DownloadedLists {
    pub allowlist_raw: String,
    pub blocklist_raw: String,
}

#[derive(Clone, Default)]
struct ResponseHeaders {
    content_length: Option<String>,
    content_encoding: Option<String>,
    content_type: Option<String>,
    retry_after: Option<String>,
}

struct TransportResponse {
    status: u16,
    headers: ResponseHeaders,
    body: Box<dyn Read + Send>,
}

#[derive(Clone, Copy, Debug)]
enum TransportError {
    Network,
    Timeout,
    Fatal,
}

trait Transport: Send + Sync {
    fn get(
        &self,
        source: &Url,
        timeout: Duration,
    ) -> std::result::Result<TransportResponse, TransportError>;
}

trait Sleeper: Send + Sync {
    fn sleep(&self, duration: Duration);
}

struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

struct ReqwestTransport {
    client: Client,
}

impl Transport for ReqwestTransport {
    fn get(
        &self,
        source: &Url,
        timeout: Duration,
    ) -> std::result::Result<TransportResponse, TransportError> {
        let response = self
            .client
            .get(source.clone())
            .timeout(timeout)
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    TransportError::Timeout
                } else if error.is_connect() {
                    TransportError::Network
                } else {
                    TransportError::Fatal
                }
            })?;
        Ok(transport_response(response))
    }
}

fn transport_response(response: Response) -> TransportResponse {
    let headers = response.headers();
    let value = |name: reqwest::header::HeaderName| {
        headers
            .get(name)
            .map(|value| value.to_str().unwrap_or("<invalid>").to_owned())
    };
    let response_headers = ResponseHeaders {
        content_length: value(reqwest::header::CONTENT_LENGTH),
        content_encoding: value(reqwest::header::CONTENT_ENCODING),
        content_type: value(reqwest::header::CONTENT_TYPE),
        retry_after: value(reqwest::header::RETRY_AFTER),
    };
    TransportResponse {
        status: response.status().as_u16(),
        headers: response_headers,
        body: Box::new(response),
    }
}

#[derive(Clone, Copy)]
struct DownloadLimits {
    max_sources: usize,
    max_per_source: usize,
    max_total: usize,
}

impl Default for DownloadLimits {
    fn default() -> Self {
        Self {
            max_sources: 32,
            max_per_source: 50 * 1024 * 1024,
            max_total: 200 * 1024 * 1024,
        }
    }
}

pub fn download_lists(allowlist_urls: &[Url], blocklist_urls: &[Url]) -> Result<DownloadedLists> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to initialize HTTP client")?;
    let transport = ReqwestTransport { client };
    download_lists_with_clock(
        allowlist_urls,
        blocklist_urls,
        &transport,
        &ThreadSleeper,
        SystemTime::now,
        DownloadLimits::default(),
    )
}

#[cfg(test)]
fn download_lists_with<T: Transport, S: Sleeper>(
    allowlist_urls: &[Url],
    blocklist_urls: &[Url],
    transport: &T,
    sleeper: &S,
    now: SystemTime,
    limits: DownloadLimits,
) -> Result<DownloadedLists> {
    download_lists_with_clock(
        allowlist_urls,
        blocklist_urls,
        transport,
        sleeper,
        move || now,
        limits,
    )
}

fn download_lists_with_clock<T: Transport, S: Sleeper, N: Fn() -> SystemTime>(
    allowlist_urls: &[Url],
    blocklist_urls: &[Url],
    transport: &T,
    sleeper: &S,
    now: N,
    limits: DownloadLimits,
) -> Result<DownloadedLists> {
    let source_count = allowlist_urls.len().saturating_add(blocklist_urls.len());
    if source_count > limits.max_sources {
        return Err(anyhow!(
            "source count exceeds maximum of {}",
            limits.max_sources
        ));
    }
    validate_sources(allowlist_urls, "allowlist")?;
    validate_sources(blocklist_urls, "blocklist")?;
    let mut total_bytes = 0;
    let allowlist_raw = fetch_sources(
        allowlist_urls,
        "allowlist",
        transport,
        sleeper,
        &now,
        limits,
        &mut total_bytes,
    )?;
    let blocklist_raw = fetch_sources(
        blocklist_urls,
        "blocklist",
        transport,
        sleeper,
        &now,
        limits,
        &mut total_bytes,
    )?;
    Ok(DownloadedLists {
        allowlist_raw,
        blocklist_raw,
    })
}

fn validate_sources(urls: &[Url], kind: &str) -> Result<()> {
    for (index, source) in urls.iter().enumerate() {
        let authority = source
            .as_str()
            .split_once("://")
            .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default());
        let has_credentials = !source.username().is_empty()
            || source.password().is_some()
            || authority.is_some_and(|value| value.contains('@'));
        if source.scheme() != "https" || has_credentials {
            return Err(anyhow!("Invalid {kind} source {}", index + 1));
        }
    }
    Ok(())
}

fn fetch_sources<T: Transport, S: Sleeper, N: Fn() -> SystemTime>(
    urls: &[Url],
    kind: &str,
    transport: &T,
    sleeper: &S,
    now: &N,
    limits: DownloadLimits,
    total_bytes: &mut usize,
) -> Result<String> {
    let mut combined = String::new();
    for (index, source) in urls.iter().enumerate() {
        let remaining = limits.max_total.saturating_sub(*total_bytes);
        if remaining == 0 {
            return Err(source_error(
                kind,
                index,
                source,
                "aggregate source size exceeds maximum",
            ));
        }
        let max_bytes = limits.max_per_source.min(remaining);
        let body = fetch_one(source, max_bytes, transport, sleeper, now)
            .map_err(|failure| source_error(kind, index, source, &failure.reason))?;
        *total_bytes = total_bytes.saturating_add(body.len());
        if index > 0 {
            combined.push('\n');
        }
        combined.push_str(&String::from_utf8_lossy(&body));
    }
    Ok(combined)
}

const MAX_ATTEMPTS: usize = 3;

#[derive(Debug)]
struct AttemptFailure {
    reason: String,
    retryable: bool,
    retry_after: Duration,
}

impl AttemptFailure {
    fn fatal(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            retryable: false,
            retry_after: Duration::ZERO,
        }
    }

    fn retryable(reason: impl Into<String>, retry_after: Duration) -> Self {
        Self {
            reason: reason.into(),
            retryable: true,
            retry_after,
        }
    }
}

fn fetch_one<T: Transport, S: Sleeper, N: Fn() -> SystemTime>(
    source: &Url,
    max_bytes: usize,
    transport: &T,
    sleeper: &S,
    now: &N,
) -> std::result::Result<Vec<u8>, AttemptFailure> {
    for attempt in 1..=MAX_ATTEMPTS {
        match fetch_attempt(source, max_bytes, transport, now) {
            Ok(body) => return Ok(body),
            Err(failure) if failure.retryable && attempt < MAX_ATTEMPTS => {
                let backoff = Duration::from_secs(1_u64 << (attempt - 1));
                sleeper.sleep(failure.retry_after.max(backoff));
            }
            Err(failure) => return Err(failure),
        }
    }
    unreachable!("the bounded retry loop always returns")
}

fn fetch_attempt<T: Transport, N: Fn() -> SystemTime>(
    source: &Url,
    max_bytes: usize,
    transport: &T,
    now: &N,
) -> std::result::Result<Vec<u8>, AttemptFailure> {
    let mut response = transport
        .get(source, REQUEST_TIMEOUT)
        .map_err(|error| match error {
            TransportError::Timeout => AttemptFailure::retryable("timeout", Duration::ZERO),
            TransportError::Network => AttemptFailure::retryable("network error", Duration::ZERO),
            TransportError::Fatal => AttemptFailure::fatal("request failed"),
        })?;

    if (300..400).contains(&response.status) {
        return Err(AttemptFailure::fatal(format!(
            "HTTP {} redirect rejected",
            response.status
        )));
    }
    if response.status != 200 {
        let retry_after = parse_retry_after(response.headers.retry_after.as_deref(), now());
        let reason = format!("HTTP {}", response.status);
        return if is_retryable_status(response.status) {
            Err(AttemptFailure::retryable(reason, retry_after))
        } else {
            Err(AttemptFailure::fatal(reason))
        };
    }

    let body = read_bounded_body(&mut response, max_bytes)?;
    let text = String::from_utf8_lossy(&body);
    if text.trim().is_empty() {
        return Err(AttemptFailure::fatal("empty response body"));
    }
    if looks_like_error_document(&text, response.headers.content_type.as_deref()) {
        return Err(AttemptFailure::fatal("unexpected error-document response"));
    }
    Ok(body)
}

fn is_retryable_status(status: u16) -> bool {
    matches!(status, 408 | 425 | 429) || (500..=599).contains(&status)
}

fn read_bounded_body(
    response: &mut TransportResponse,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, AttemptFailure> {
    let declared_length = response
        .headers
        .content_length
        .as_deref()
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| AttemptFailure::fatal("invalid content-length header"))
        })
        .transpose()?;
    if declared_length.is_some_and(|length| length > max_bytes) {
        return Err(AttemptFailure::fatal("response exceeds maximum size"));
    }

    let mut body = Vec::with_capacity(declared_length.unwrap_or(0).min(max_bytes));
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes_left = max_bytes.saturating_sub(body.len());
        let read_size = bytes_left.saturating_add(1).min(buffer.len());
        let read = response
            .body
            .read(&mut buffer[..read_size])
            .map_err(|error| {
                let reason = if error.kind() == std::io::ErrorKind::TimedOut {
                    "timeout"
                } else {
                    "network error"
                };
                if is_retryable_io_error(error.kind()) {
                    AttemptFailure::retryable(reason, Duration::ZERO)
                } else {
                    AttemptFailure::fatal("source response could not be read")
                }
            })?;
        if read == 0 {
            break;
        }
        if read > bytes_left {
            return Err(AttemptFailure::fatal("response exceeds maximum size"));
        }
        body.extend_from_slice(&buffer[..read]);
    }

    if response
        .headers
        .content_encoding
        .as_deref()
        .is_none_or(str::is_empty)
        && declared_length.is_some_and(|length| length != body.len())
    {
        return Err(AttemptFailure::fatal("response body length mismatch"));
    }
    Ok(body)
}

fn is_retryable_io_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::BrokenPipe
    )
}

fn looks_like_error_document(text: &str, content_type: Option<&str>) -> bool {
    let media_type = content_type
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let error_media_type = media_type == "text/html"
        || media_type == "text/xml"
        || media_type == "text/json"
        || media_type == "application/json"
        || media_type == "application/xml"
        || media_type
            .strip_prefix("application/")
            .is_some_and(|subtype| subtype.ends_with("+json") || subtype.ends_with("+xml"));
    if error_media_type {
        return true;
    }

    let sample = text
        .strip_prefix('\u{feff}')
        .unwrap_or(text)
        .trim_start()
        .to_ascii_lowercase();
    sample.starts_with("<?xml")
        || sample.starts_with("<!doctype html")
        || sample.starts_with("<html")
        || sample.starts_with("<error")
        || sample.starts_with('{')
        || sample.strip_prefix('[').is_some_and(|rest| {
            rest.trim_start().starts_with('"') || rest.trim_start().starts_with('{')
        })
}

fn parse_retry_after(value: Option<&str>, now: SystemTime) -> Duration {
    const CAP: Duration = Duration::from_secs(300);
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Duration::ZERO;
    };
    if let Ok(seconds) = value.parse::<f64>() {
        if seconds.is_finite() && seconds >= 0.0 {
            return Duration::from_secs_f64(seconds.min(300.0));
        }
    }
    parse_http_date(value, now)
        .and_then(|deadline| deadline.duration_since(now).ok())
        .unwrap_or(Duration::ZERO)
        .min(CAP)
}

fn parse_http_date(value: &str, now: SystemTime) -> Option<SystemTime> {
    let parts: Vec<_> = value.split_whitespace().collect();
    let (day, month, year, clock) = match parts.as_slice() {
        [weekday, day, month, year, clock, "GMT"] if weekday.ends_with(',') => (
            day.parse::<u32>().ok()?,
            parse_month(month)?,
            year.parse::<i64>().ok()?,
            *clock,
        ),
        [weekday, date, clock, "GMT"] if weekday.ends_with(',') => {
            let mut date_parts = date.split('-');
            let day = date_parts.next()?.parse::<u32>().ok()?;
            let month = parse_month(date_parts.next()?)?;
            let short_year = date_parts.next()?.parse::<i64>().ok()?;
            if date_parts.next().is_some() || short_year > 99 {
                return None;
            }
            let current_year = year_at(now)?;
            let mut year = 2000 + short_year;
            if year > current_year.checked_add(50)? {
                year -= 100;
            }
            (day, month, year, *clock)
        }
        [_, month, day, clock, year] => (
            day.parse::<u32>().ok()?,
            parse_month(month)?,
            year.parse::<i64>().ok()?,
            *clock,
        ),
        _ => return None,
    };
    let (hour, minute, second) = parse_clock(clock)?;
    let days = days_from_civil(year, month, day)?;
    let seconds = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour * 3600 + minute * 60 + second))?;
    if seconds >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds as u64))
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(seconds.unsigned_abs()))
    }
}

fn parse_month(month: &str) -> Option<u32> {
    match month {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    }
    .into()
}

fn parse_clock(clock: &str) -> Option<(u32, u32, u32)> {
    let mut clock = clock.split(':');
    let hour = clock.next()?.parse::<u32>().ok()?;
    let minute = clock.next()?.parse::<u32>().ok()?;
    let second = clock.next()?.parse::<u32>().ok()?;
    if clock.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    Some((hour, minute, second))
}

fn year_at(time: SystemTime) -> Option<i64> {
    let seconds = match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).ok()?,
        Err(error) => -i64::try_from(error.duration().as_secs()).ok()?,
    };
    let days = seconds.div_euclid(86_400);
    let shifted_days = days.checked_add(719_468)?;
    let era = shifted_days.div_euclid(146_097);
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era.checked_add(era.checked_mul(400)?)?;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year = year.checked_add(1)?;
    }
    Some(year)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(0..=9_999).contains(&year) || !(1..=12).contains(&month) {
        return None;
    }
    let leap_year =
        year.rem_euclid(4) == 0 && (year.rem_euclid(100) != 0 || year.rem_euclid(400) == 0);
    let max_day = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > max_day {
        return None;
    }
    let year = year.checked_sub(i64::from(month <= 2))?;
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

fn source_error(kind: &str, index: usize, source: &Url, reason: &str) -> anyhow::Error {
    anyhow!(
        "Failed to download {kind} source {} ({}): {reason}",
        index + 1,
        source.host_str().unwrap_or("configured source")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{self, Cursor, Read};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    fn url(host: &str) -> url::Url {
        url::Url::parse(&format!("{}://{host}", "https")).unwrap()
    }

    enum Reply {
        Response {
            status: u16,
            headers: ResponseHeaders,
            body: Vec<u8>,
        },
        Generated {
            status: u16,
            headers: ResponseHeaders,
            bytes: usize,
            delivered: Arc<AtomicUsize>,
        },
        Network,
        Timeout,
        Fatal,
    }

    struct FakeTransport {
        replies: Mutex<VecDeque<Reply>>,
        hosts: Mutex<Vec<String>>,
        timeouts: Mutex<Vec<Duration>>,
    }

    impl FakeTransport {
        fn new(replies: impl IntoIterator<Item = Reply>) -> Self {
            Self {
                replies: Mutex::new(replies.into_iter().collect()),
                hosts: Mutex::new(Vec::new()),
                timeouts: Mutex::new(Vec::new()),
            }
        }
    }

    impl Transport for FakeTransport {
        fn get(
            &self,
            source: &url::Url,
            timeout: Duration,
        ) -> Result<TransportResponse, TransportError> {
            self.hosts
                .lock()
                .unwrap()
                .push(source.host_str().unwrap_or_default().to_owned());
            self.timeouts.lock().unwrap().push(timeout);
            match self.replies.lock().unwrap().pop_front().unwrap() {
                Reply::Response {
                    status,
                    headers,
                    body,
                } => Ok(TransportResponse {
                    status,
                    headers,
                    body: Box::new(Cursor::new(body)),
                }),
                Reply::Generated {
                    status,
                    headers,
                    bytes,
                    delivered,
                } => Ok(TransportResponse {
                    status,
                    headers,
                    body: Box::new(GeneratedReader {
                        remaining: bytes,
                        delivered,
                    }),
                }),
                Reply::Network => Err(TransportError::Network),
                Reply::Timeout => Err(TransportError::Timeout),
                Reply::Fatal => Err(TransportError::Fatal),
            }
        }
    }

    struct GeneratedReader {
        remaining: usize,
        delivered: Arc<AtomicUsize>,
    }

    impl Read for GeneratedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.remaining.min(buffer.len());
            buffer[..count].fill(b'x');
            self.remaining -= count;
            self.delivered.fetch_add(count, Ordering::SeqCst);
            Ok(count)
        }
    }

    #[derive(Default)]
    struct FakeSleeper(Mutex<Vec<Duration>>);

    impl Sleeper for FakeSleeper {
        fn sleep(&self, duration: Duration) {
            self.0.lock().unwrap().push(duration);
        }
    }

    fn response(body: &str) -> Reply {
        Reply::Response {
            status: 200,
            headers: ResponseHeaders::default(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn response_with_status(status: u16, body: &str) -> Reply {
        Reply::Response {
            status,
            headers: ResponseHeaders::default(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn response_with_retry_after(status: u16, retry_after: &str) -> Reply {
        Reply::Response {
            status,
            headers: ResponseHeaders {
                retry_after: Some(retry_after.to_owned()),
                ..ResponseHeaders::default()
            },
            body: Vec::new(),
        }
    }

    fn response_with_headers(status: u16, headers: ResponseHeaders, body: &str) -> Reply {
        Reply::Response {
            status,
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn downloads_sources_sequentially_and_joins_each_list() {
        let transport = FakeTransport::new([
            response("allow-one.example\n"),
            response("allow-two.example\n"),
            response("block.example\n"),
        ]);
        let sleeper = FakeSleeper::default();
        let result = download_lists_with(
            &[url("allow-one.invalid"), url("allow-two.invalid")],
            &[url("block.invalid")],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            DownloadLimits::default(),
        )
        .unwrap();

        assert_eq!(
            result.allowlist_raw,
            "allow-one.example\n\nallow-two.example\n"
        );
        assert_eq!(result.blocklist_raw, "block.example\n");
        assert_eq!(
            *transport.hosts.lock().unwrap(),
            ["allow-one.invalid", "allow-two.invalid", "block.invalid"]
        );
        assert_eq!(
            *transport.timeouts.lock().unwrap(),
            [Duration::from_secs(30); 3]
        );
        assert!(sleeper.0.lock().unwrap().is_empty());
    }

    #[test]
    fn rejects_non_https_and_credentialed_sources_before_requesting_them() {
        let insecure = url::Url::parse(&format!("{}://private.invalid/path", "http")).unwrap();
        let credentialed = url::Url::parse(&format!(
            "{}://user:password@private.invalid/path?token=hidden",
            "https"
        ))
        .unwrap();
        let transport = FakeTransport::new([]);
        let sleeper = FakeSleeper::default();

        for source in [&insecure, &credentialed] {
            let error = match download_lists_with(
                std::slice::from_ref(source),
                &[],
                &transport,
                &sleeper,
                SystemTime::UNIX_EPOCH,
                DownloadLimits::default(),
            ) {
                Ok(_) => panic!("unsafe source unexpectedly accepted"),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(message.contains("allowlist source 1"));
            assert!(!message.contains("password"));
            assert!(!message.contains("hidden"));
            assert!(!message.contains("/path"));
        }

        assert!(transport.hosts.lock().unwrap().is_empty());
    }

    #[test]
    fn enforces_one_combined_source_count_before_fetching() {
        let transport = FakeTransport::new([]);
        let sleeper = FakeSleeper::default();
        let limits = DownloadLimits {
            max_sources: 2,
            ..DownloadLimits::default()
        };
        let error = match download_lists_with(
            &[url("allow.invalid")],
            &[url("block-one.invalid"), url("block-two.invalid")],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            limits,
        ) {
            Ok(_) => panic!("too many configured sources unexpectedly accepted"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("source count exceeds maximum of 2")
        );
        assert!(transport.hosts.lock().unwrap().is_empty());
    }

    #[test]
    fn requires_http_200_and_does_not_retry_redirects_or_other_statuses() {
        for status in [301, 302, 404, 206] {
            let source = url::Url::parse(&format!(
                "{}://source.invalid/private?secret=hidden",
                "https"
            ))
            .unwrap();
            let transport = FakeTransport::new([response_with_status(status, "not a list")]);
            let sleeper = FakeSleeper::default();
            let error = match download_lists_with(
                &[source],
                &[],
                &transport,
                &sleeper,
                SystemTime::UNIX_EPOCH,
                DownloadLimits::default(),
            ) {
                Ok(_) => panic!("non-200 response unexpectedly accepted"),
                Err(error) => error,
            };

            let message = error.to_string();
            assert!(message.contains(&format!("HTTP {status}")));
            assert!(message.contains("source.invalid"));
            assert!(!message.contains("/private"));
            assert!(!message.contains("hidden"));
            assert_eq!(transport.hosts.lock().unwrap().len(), 1);
            assert!(sleeper.0.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn retries_only_the_transient_http_statuses_with_exponential_backoff() {
        for status in [408, 425, 429, 500, 599] {
            let transport = FakeTransport::new([
                response_with_status(status, "busy"),
                response_with_status(status, "busy"),
                response("list.example\\n"),
            ]);
            let sleeper = FakeSleeper::default();
            let result = download_lists_with(
                &[url("retry.invalid")],
                &[],
                &transport,
                &sleeper,
                SystemTime::UNIX_EPOCH,
                DownloadLimits::default(),
            )
            .unwrap();

            assert_eq!(result.allowlist_raw, "list.example\\n");
            assert_eq!(transport.hosts.lock().unwrap().len(), 3);
            assert_eq!(
                *sleeper.0.lock().unwrap(),
                [Duration::from_secs(1), Duration::from_secs(2)]
            );
        }
    }

    #[test]
    fn honors_numeric_and_http_date_retry_after_with_a_five_minute_cap() {
        let cases = [
            ("60", Duration::from_secs(60)),
            ("Thu, 01 Jan 1970 00:01:00 GMT", Duration::from_secs(60)),
            ("Thu, 01 Jan 1970 00:10:00 GMT", Duration::from_secs(300)),
        ];
        for (retry_after, expected_delay) in cases {
            let transport = FakeTransport::new([
                response_with_retry_after(429, retry_after),
                response("list.example\n"),
            ]);
            let sleeper = FakeSleeper::default();
            let result = download_lists_with(
                &[url("retry-after.invalid")],
                &[],
                &transport,
                &sleeper,
                SystemTime::UNIX_EPOCH,
                DownloadLimits::default(),
            )
            .unwrap();

            assert_eq!(result.allowlist_raw, "list.example\n");
            assert_eq!(*sleeper.0.lock().unwrap(), [expected_delay]);
        }
    }

    #[test]
    fn retries_network_and_timeout_failures_at_most_three_times_without_url_leaks() {
        let source = url::Url::parse(&format!(
            "{}://transport.invalid/private?secret=hidden",
            "https"
        ))
        .unwrap();
        let transport = FakeTransport::new([Reply::Network, Reply::Timeout, Reply::Network]);
        let sleeper = FakeSleeper::default();
        let error = match download_lists_with(
            &[source],
            &[],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            DownloadLimits::default(),
        ) {
            Ok(_) => panic!("repeated transport failures unexpectedly succeeded"),
            Err(error) => error,
        };
        let message = error.to_string();

        assert_eq!(message.matches("Failed to download").count(), 1);
        assert!(message.contains("transport.invalid"));
        assert!(!message.contains("/private"));
        assert!(!message.contains("hidden"));
        assert_eq!(transport.hosts.lock().unwrap().len(), 3);
        assert_eq!(
            *sleeper.0.lock().unwrap(),
            [Duration::from_secs(1), Duration::from_secs(2)]
        );
    }

    #[test]
    fn rejects_empty_error_documents_invalid_lengths_and_unencoded_mismatches() {
        let cases = [
            (ResponseHeaders::default(), " \n", "empty response body"),
            (
                ResponseHeaders {
                    content_type: Some("text/html; charset=utf-8".to_owned()),
                    ..ResponseHeaders::default()
                },
                "good.example",
                "unexpected error-document response",
            ),
            (
                ResponseHeaders {
                    content_type: Some("application/problem+json".to_owned()),
                    ..ResponseHeaders::default()
                },
                "good.example",
                "unexpected error-document response",
            ),
            (
                ResponseHeaders::default(),
                "{\"error\":true}",
                "unexpected error-document response",
            ),
            (
                ResponseHeaders::default(),
                "\u{feff} <?xml version=\"1.0\"?><error/>",
                "unexpected error-document response",
            ),
            (
                ResponseHeaders {
                    content_length: Some("invalid".to_owned()),
                    ..ResponseHeaders::default()
                },
                "good.example",
                "invalid content-length header",
            ),
            (
                ResponseHeaders {
                    content_length: Some("1".to_owned()),
                    ..ResponseHeaders::default()
                },
                "good.example",
                "response body length mismatch",
            ),
        ];

        for (headers, body, expected_error) in cases {
            let transport = FakeTransport::new([response_with_headers(200, headers, body)]);
            let sleeper = FakeSleeper::default();
            let error = match download_lists_with(
                &[url("documents.invalid")],
                &[],
                &transport,
                &sleeper,
                SystemTime::UNIX_EPOCH,
                DownloadLimits::default(),
            ) {
                Ok(_) => panic!("invalid document unexpectedly accepted: {expected_error}"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(expected_error));
            assert!(sleeper.0.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn content_encoding_disables_content_length_body_comparison() {
        let transport = FakeTransport::new([response_with_headers(
            200,
            ResponseHeaders {
                content_length: Some("1".to_owned()),
                content_encoding: Some("gzip".to_owned()),
                ..ResponseHeaders::default()
            },
            "good.example",
        )]);
        let sleeper = FakeSleeper::default();
        let result = download_lists_with(
            &[url("encoded.invalid")],
            &[],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            DownloadLimits::default(),
        )
        .unwrap();

        assert_eq!(result.allowlist_raw, "good.example");
    }

    #[test]
    fn enforces_per_source_and_combined_byte_limits() {
        let limits = DownloadLimits {
            max_sources: 32,
            max_per_source: 4,
            max_total: 6,
        };
        let transport = FakeTransport::new([response("abcde")]);
        let sleeper = FakeSleeper::default();
        let error = match download_lists_with(
            &[url("single-size.invalid")],
            &[],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            limits,
        ) {
            Ok(_) => panic!("oversized individual source unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("response exceeds maximum size"));
        assert_eq!(transport.hosts.lock().unwrap().len(), 1);
        assert!(sleeper.0.lock().unwrap().is_empty());

        let transport = FakeTransport::new([response("aaaa"), response("bbb")]);
        let sleeper = FakeSleeper::default();
        let error = match download_lists_with(
            &[url("first-size.invalid")],
            &[url("second-size.invalid")],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            limits,
        ) {
            Ok(_) => panic!("aggregate source size limit was not enforced"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("response exceeds maximum size"));
        assert_eq!(transport.hosts.lock().unwrap().len(), 2);
    }

    #[test]
    fn stops_streaming_at_one_byte_past_the_limit() {
        let delivered = Arc::new(AtomicUsize::new(0));
        let transport = FakeTransport::new([Reply::Generated {
            status: 200,
            headers: ResponseHeaders::default(),
            bytes: 1_000_000,
            delivered: delivered.clone(),
        }]);
        let sleeper = FakeSleeper::default();
        let limits = DownloadLimits {
            max_sources: 32,
            max_per_source: 4,
            max_total: 100,
        };
        let error = match download_lists_with(
            &[url("stream.invalid")],
            &[],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            limits,
        ) {
            Ok(_) => panic!("unbounded response unexpectedly accepted"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("response exceeds maximum size"));
        assert_eq!(delivered.load(Ordering::SeqCst), 5);
        assert!(sleeper.0.lock().unwrap().is_empty());

        let declared_reader_bytes = Arc::new(AtomicUsize::new(0));
        let transport = FakeTransport::new([Reply::Generated {
            status: 200,
            headers: ResponseHeaders {
                content_length: Some("5".to_owned()),
                ..ResponseHeaders::default()
            },
            bytes: 1_000_000,
            delivered: declared_reader_bytes.clone(),
        }]);
        let error = match download_lists_with(
            &[url("declared-size.invalid")],
            &[],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            limits,
        ) {
            Ok(_) => panic!("oversized declared length unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("response exceeds maximum size"));
        assert_eq!(declared_reader_bytes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn accepts_obsolete_http_date_formats_for_retry_after() {
        let now = SystemTime::UNIX_EPOCH;
        assert_eq!(
            parse_retry_after(Some("Thursday, 01-Jan-70 00:01:00 GMT"), now),
            Duration::from_secs(60)
        );
        assert_eq!(
            parse_retry_after(Some("Thu Jan  1 00:01:00 1970"), now),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn default_limits_allow_exactly_thirty_two_combined_sources() {
        let defaults = DownloadLimits::default();
        assert_eq!(defaults.max_sources, 32);
        assert_eq!(defaults.max_per_source, 50 * 1024 * 1024);
        assert_eq!(defaults.max_total, 200 * 1024 * 1024);

        let sources: Vec<_> = (0..32)
            .map(|index| url(&format!("source-{index}.invalid")))
            .collect();
        let transport = FakeTransport::new((0..32).map(|_| response("x")));
        let sleeper = FakeSleeper::default();
        let result = download_lists_with(
            &sources[..16],
            &sources[16..],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            DownloadLimits::default(),
        )
        .unwrap();
        assert_eq!(result.allowlist_raw.matches('\n').count(), 15);
        assert_eq!(transport.hosts.lock().unwrap().len(), 32);

        let sources: Vec<_> = (0..33)
            .map(|index| url(&format!("source-{index}.invalid")))
            .collect();
        let transport = FakeTransport::new([]);
        let error = match download_lists_with(
            &sources[..16],
            &sources[16..],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            DownloadLimits::default(),
        ) {
            Ok(_) => panic!("33 configured sources unexpectedly accepted"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("source count exceeds maximum of 32")
        );
        assert!(transport.hosts.lock().unwrap().is_empty());
    }

    #[test]
    fn reevaluates_http_dates_against_the_clock_on_each_retry() {
        let clock_calls = AtomicUsize::new(0);
        let clock = || {
            if clock_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                SystemTime::UNIX_EPOCH
            } else {
                SystemTime::UNIX_EPOCH + Duration::from_secs(60)
            }
        };
        let transport = FakeTransport::new([
            response_with_retry_after(429, "Thu, 01 Jan 1970 00:02:00 GMT"),
            response_with_retry_after(429, "Thu, 01 Jan 1970 00:02:00 GMT"),
            response("list.example\n"),
        ]);
        let sleeper = FakeSleeper::default();
        let result = download_lists_with_clock(
            &[url("clock.invalid")],
            &[],
            &transport,
            &sleeper,
            clock,
            DownloadLimits::default(),
        )
        .unwrap();

        assert_eq!(result.allowlist_raw, "list.example\n");
        assert_eq!(clock_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            *sleeper.0.lock().unwrap(),
            [Duration::from_secs(120), Duration::from_secs(60)]
        );
    }

    #[test]
    fn does_not_retry_fatal_transport_errors() {
        let transport = FakeTransport::new([Reply::Fatal]);
        let sleeper = FakeSleeper::default();
        let error = match download_lists_with(
            &[url("fatal.invalid")],
            &[],
            &transport,
            &sleeper,
            SystemTime::UNIX_EPOCH,
            DownloadLimits::default(),
        ) {
            Ok(_) => panic!("fatal transport error unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("request failed"));
        assert_eq!(transport.hosts.lock().unwrap().len(), 1);
        assert!(sleeper.0.lock().unwrap().is_empty());
    }

    #[test]
    fn does_not_retry_incomplete_response_bodies() {
        assert!(!is_retryable_io_error(io::ErrorKind::UnexpectedEof));
    }
}
