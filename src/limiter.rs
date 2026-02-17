// TODO: deal with HTTP redirects - they should not circumvent the policy

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::time::Duration;

use moka::sync::Cache;
use reqwest::{Client, Response, StatusCode, Url};
use robotstxt::matcher::{LongestMatchRobotsMatchStrategy, RobotsMatcher};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::time::Instant;

use crate::error::{Error, ErrorKind, Result};

/// Rate-limiter for web crawlers.
///
/// See the crate-level documentation for an example.
///
/// This rate-limiter contains an LRU cache of Internet domains and their `robots.txt` policies (if
/// any). If the host has no `/robots.txt` file (it's a 404), then we permit crawling the host. If
/// fetching `/robots.txt` fails with any other network error, or times out, or the policy is huge
/// (over 500 KiB), we mark the host as having banned us. The limiter will retry when the
/// host falls out of the LRU cache, or after 24 hours.
pub struct Limiter {
    client: Client,
    user_agent: String,
    domains: Cache<String, Arc<Mutex<Domain>>>,
}

/// A single web domain (eTLD+1).
struct Domain {
    /// When to allow the next request. See `MIN_DELAY`.
    next_access: Instant,
    /// Stores robots.txt for each host we've encountered in this domain.
    hosts: HashMap<HostKey, Host>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HostKey {
    hostname: String,
    port: u16,
}

struct Host {
    /// Content of `/robots.txt` for this host, if any.
    /// (TODO - parse and keep only the parts relevant for our user_agent)
    robots_txt: Option<String>,
    /// When robots.txt was last fetched. See `ROBOTS_TXT_FRESHNESS`.
    robots_last_fetch: Instant,
}

/// Permit to fetch a URL, returned by [`Limiter::acquire`].
///
/// Dropping this frees up the permit, so that a permit can be issued to another async task for a
/// URL on the same host.
pub struct Permit {
    domain_guard: OwnedMutexGuard<Domain>,
}

/// Rather strict limit on policy length. Even Wikipedia's policy is nowhere near this long;
/// anything longer than that we will treat as a ban.
const ROBOTS_TXT_LIMIT_BYTES: usize = 500 * 1024;

const ROBOTS_TXT_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a fetched robots.txt file can be cached and reused. The balance to be struck here is
/// between pestering the server too often and noticing promptly if the server decides to ban us,
/// but in practice, updates to the file are extraordinarily rare. We refetch daily.
const ROBOTS_TXT_FRESHNESS: Duration = Duration::from_secs(24 * 60 * 60);

const DISALLOW_ALL: &str = "user-agent: *\ndisallow: /\n";

/// Minimum pause between the end of one request and the beginning of the next (not counting
/// requests for `/robots.txt`). We allow one request per second, on the theory that (1) most web
/// sites will consider that an acceptable pace, so we shouldn't get rate-limited; (2) any spider
/// typically crawls many web sites concurrently, so it's not like the spider needs to hammer any
/// one host at a high rate.
const MIN_DELAY: Duration = Duration::from_secs(1);

impl Domain {
    fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Domain {
            next_access: Instant::now(),
            hosts: HashMap::new(),
        }))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        // Work complete! Enforce the minimum delay between this request and the next.
        self.domain_guard.next_access = Instant::now() + MIN_DELAY;
        // Dropping self.domain_guard releases the mutex so that the next task can get a permit.
    }
}

impl Domain {
    async fn robots(
        &mut self,
        client: &Client,
        host_key: HostKey,
        url: &Url,
    ) -> Result<Option<&str>> {
        let host_entry = self.hosts.entry(host_key);

        if let Entry::Occupied(e) = &host_entry
            && e.get().robots_last_fetch.elapsed() <= ROBOTS_TXT_FRESHNESS
        {
            let Entry::Occupied(e) = host_entry else {
                panic!("just confirmed match");
            };
            return Ok(e.into_mut().robots_txt.as_deref());
        }

        let timeout_at = Instant::now() + ROBOTS_TXT_FETCH_TIMEOUT;
        let response = client
            .get(
                url.join("/robots.txt")
                    .expect("fixed string is a valid relative URL"),
            )
            .timeout(ROBOTS_TXT_FETCH_TIMEOUT)
            .send()
            .await?;
        let robots_txt = if response.status() == StatusCode::NOT_FOUND {
            // 404 Not Found is great; it means the site has no policy.
            None
        } else {
            // but treat any other error as a policy against all robots. Many different errors are
            // possible: the spider's network access is down; the server is permanently down or
            // gone; an HTTP 403 Forbidden or 429 Too Many Requests response; an HTTP 500 Server
            // Error. Most of these at least suggest we shouldn't try to crawl the host.
            match tokio::time::timeout_at(timeout_at, read_response(response)).await {
                Ok(Ok(text)) => Some(text),
                _ => Some(DISALLOW_ALL.to_string()),
            }
        };
        let now = Instant::now();

        let host = match host_entry {
            Entry::Vacant(e) => e.insert(Host {
                robots_last_fetch: now,
                robots_txt,
            }),
            Entry::Occupied(e) => {
                let host = e.into_mut();
                host.robots_last_fetch = now;
                host.robots_txt = robots_txt;
                host
            }
        };
        Ok(host.robots_txt.as_deref())
    }
}

struct AnyError;

impl From<reqwest::Error> for AnyError {
    fn from(_err: reqwest::Error) -> Self {
        AnyError
    }
}

impl From<std::string::FromUtf8Error> for AnyError {
    fn from(_err: std::string::FromUtf8Error) -> Self {
        AnyError
    }
}

async fn read_response(response: Response) -> Result<String, AnyError> {
    // Fetch the body of a GET /robots.txt response - rather carefully, to avoid wasting memory
    let mut response = response.error_for_status()?;
    let mut bytes = vec![];
    while let Some(chunk) = response.chunk().await? {
        if bytes.len() + chunk.len() > ROBOTS_TXT_LIMIT_BYTES {
            return Err(AnyError); // response too large
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8(bytes)?)
}

impl Limiter {
    /// Create a new rate limiter. `client` is used to fetch `robots.txt` from hosts. `user_agent`
    /// is this spider's `User-Agent` string, used to determine which rules in the file apply to
    /// us.
    ///
    /// To comply with RFC 9309, `client` SHOULD have a redirect policy that
    /// honors at least 5 levels of redirects. reqwest's default redirect policy is fine.
    ///
    /// (The caller is responsible for configuring `client` to use this user agent string,
    /// since it's not configurable once the client is created.)
    pub fn new(client: Client, user_agent: String) -> Self {
        let domains = Cache::builder().max_capacity(1_000_000).build();
        Limiter {
            client,
            user_agent,
            domains,
        }
    }

    /// Try to obtain a permit to fetch the specified `url`.
    ///
    /// If we do not already have a `robots.txt` from the host named in `url`, we first fetch it.
    ///
    /// If this returns an error, the caller must not try to fetch the URL. On success, this returns
    /// a `Permit`, which is an opaque token without any useful methods. The caller should hold on to the
    /// `Permit` while fetching the URL, then drop it. Holding the permit prevents other tasks from
    /// being given a permit for the same host; dropping it allows those tasks to proceed.
    ///
    /// # Errors
    ///
    /// This fails with an error if:
    /// - `url` is not an `http:` or `https:` URL
    /// - there's an error or timeout trying to fetch `robots.txt`
    /// - the site's `robots.txt` disallows crawling the path
    pub async fn acquire(&self, url: &Url) -> Result<Permit> {
        let scheme = url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(Error {
                kind: ErrorKind::NotHttp,
            });
        }
        let (Some(host_str), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
            return Err(Error {
                kind: ErrorKind::InvalidUrl,
            });
        };
        let Some(domain) = psl::domain_str(host_str) else {
            return Err(Error {
                kind: ErrorKind::InvalidUrl,
            });
        };
        let key = domain.to_lowercase();

        let domain_mutex = self.domains.get_with(key, Domain::new).clone();
        let mut domain_guard = domain_mutex.lock_owned().await;
        let hostname = host_str.to_lowercase();
        let host_key = HostKey { hostname, port };
        if let Some(robots_txt) = domain_guard.robots(&self.client, host_key, url).await? {
            let mut matcher = RobotsMatcher::<LongestMatchRobotsMatchStrategy>::default();
            if !matcher.one_agent_allowed_by_robots(robots_txt, &self.user_agent, url.as_str()) {
                return Err(Error {
                    kind: ErrorKind::Disallowed,
                });
            }
        }

        if Instant::now() < domain_guard.next_access {
            tokio::time::sleep_until(domain_guard.next_access).await;
        }

        Ok(Permit { domain_guard })
    }
}
