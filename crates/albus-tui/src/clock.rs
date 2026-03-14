use time::OffsetDateTime;

/// Clock abstraction for deterministic tests and local runtime use.
pub trait Clock {
    /// Returns the current UTC time.
    fn now_utc(&self) -> OffsetDateTime;

    /// Returns the current Unix timestamp in seconds.
    #[must_use]
    fn now_unix_timestamp(&self) -> u64 {
        u64::try_from(self.now_utc().unix_timestamp()).unwrap_or_default()
    }
}

/// Production clock backed by the local system clock.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}
