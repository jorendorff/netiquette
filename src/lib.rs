//! Polite behavior for web crawlers.
//!
//! A web crawler can use this crate's [`Limiter`] to honor `robots.txt` files on servers. This
//! helps your spider be a good Internet citizen and avoid making a nuisance of itself and getting
//! rate-limited.
//!
//! # Usage
//!
//! ```
//! # const MY_USER_AGENT: &str = "ExampleCodeSomeoneCopiedAndPasted/0.1";
//! # fn handle_web_page(_response: reqwest::Result<reqwest::Response>) {}
//! # async fn crawl_urls(urls: Vec<netiquette::Url>) {
//! use netiquette::Limiter;
//!
//! // Create a reqwest::Client to fetch web content.
//! let client = reqwest::Client::builder()
//!     .user_agent(MY_USER_AGENT)
//!     .build()
//!     .unwrap();
//!
//! let limiter = Limiter::new(client.clone(), MY_USER_AGENT.to_string());
//! for url in urls {
//!     match limiter.acquire(&url).await {
//!         Ok(_permit) => handle_web_page(client.get(url).send().await),
//!         Err(err) => eprintln!("can't crawl {url} - {err}"),
//!     }
//! }
//! # }
//! ```
//!
//! Of course, in a real spider, many tasks can fetch and process web pages concurrently. There can
//! be thousands of HTTP requests in flight at a time. The purpose of `Limiter` is to slow down
//! requests that would hit the same host concurrently or too frequently.
#![deny(missing_docs)]

mod error;
mod limiter;

pub use error::{Error, Result};
pub use limiter::{Limiter, Permit};
pub use reqwest::Url;
