//! Thread-safe in-process secret store.
//!
//! Replaces `unsafe { std::env::set_var() }` / `remove_var()` calls that are
//! unsound in multi-threaded Rust programs (UB since the 2024 edition, `unsafe`
//! since Rust 1.66).
//!
//! Secrets written at runtime (e.g. channel API keys configured via the UI) are
//! stored here.  Readers should call [`get_secret`] first and fall back to
//! [`std::env::var`] for values that were set at process startup.
//!
//! Internal storage uses `Zeroizing<String>` so secrets are zeroed from memory
//! when removed or overwritten. The public API returns plain `String` to avoid
//! forcing all callers to depend on the `zeroize` crate.

use dashmap::DashMap;
use std::sync::OnceLock;
use zeroize::Zeroizing;

fn store() -> &'static DashMap<String, Zeroizing<String>> {
    static STORE: OnceLock<DashMap<String, Zeroizing<String>>> = OnceLock::new();
    STORE.get_or_init(DashMap::new)
}

/// Insert or overwrite a secret.
///
/// The previous value (if any) is zeroed from memory on drop.
pub fn set_secret(key: &str, value: &str) {
    store().insert(key.to_string(), Zeroizing::new(value.to_string()));
}

/// Remove a secret. The stored value is zeroed from memory on drop.
pub fn remove_secret(key: &str) {
    store().remove(key);
}

/// Retrieve a secret.  Returns `None` if the key was never stored.
///
/// Returns a plain `String` (clone of the stored value) for API ergonomics.
pub fn get_secret(key: &str) -> Option<String> {
    store().get(key).map(|r| r.value().as_str().to_string())
}

/// Retrieve a secret, falling back to the process environment.
///
/// **Priority:** the in-process store is checked first; the OS environment is
/// only consulted when the key is absent from the store. This means a value set
/// via [`set_secret`] at runtime will shadow an identically named startup env
/// var. Callers that want only runtime-set values should use [`get_secret`].
///
/// Use this instead of `std::env::var()` when the value may have been set at
/// runtime via the channel-configuration UI.
pub fn get_secret_or_env(key: &str) -> Option<String> {
    get_secret(key).or_else(|| std::env::var(key).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_trip() {
        set_secret("TEST_SECRET_STORE_RT", "hello");
        assert_eq!(get_secret("TEST_SECRET_STORE_RT").as_deref(), Some("hello"));
        remove_secret("TEST_SECRET_STORE_RT");
        assert_eq!(get_secret("TEST_SECRET_STORE_RT"), None);
    }

    #[test]
    fn falls_back_to_env() {
        // get_secret_or_env should return None for an unset key
        assert_eq!(get_secret_or_env("NONEXISTENT_TEST_KEY_42"), None);
    }
}
