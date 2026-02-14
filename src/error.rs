use std::error::Error as StdError;
use std::fmt::{self, Display, Formatter};

/// The error type used by [`Limiter::acquire`](crate::Limiter::acquire).
///
/// Most commonly, these are just network errors from `reqwest`. They can also indicate that the
/// `url` argument was invalid or the host's `robots.txt` policy disallows crawling that URL.
#[derive(Debug)]
pub struct Error {
    pub(crate) kind: ErrorKind,
}

#[derive(Debug)]
pub(crate) enum ErrorKind {
    Reqwest(reqwest::Error),
    NotHttp,
    InvalidUrl,
    Disallowed,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match &self.kind {
            ErrorKind::Reqwest(err) => err.fmt(f),
            ErrorKind::NotHttp => write!(f, "non-http url"),
            ErrorKind::InvalidUrl => write!(f, "invalid url"),
            ErrorKind::Disallowed => write!(f, "url disallowed by robots.txt"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.kind {
            ErrorKind::Reqwest(err) => err.source(),
            _ => None
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self {
            kind: ErrorKind::Reqwest(err),
        }
    }
}

/// A result alias where the error type is [`netiquette::Error`](Error).
pub type Result<T, E = Error> = std::result::Result<T, E>;
