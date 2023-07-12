use chrono::{DateTime, Utc};

/// This is the Win32 Epoch time for when Unix Epoch time started.
/// It is in hundreds of nanoseconds.
const EPOCH_AS_FILETIME: u64 = 116444736000000000; // January 1, 1970 as MS file time

pub fn filetime_now() -> u64 {
    Utc::now().timestamp_nanos() as u64 / 100 + EPOCH_AS_FILETIME
}

pub fn filetime_from_utc(dt: DateTime<Utc>) -> u64 {
    dt.timestamp_nanos() as u64 / 100 + EPOCH_AS_FILETIME
}
