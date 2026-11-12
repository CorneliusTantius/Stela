//! The credential the stick's Wi-Fi settings give the mount network: the
//! key file's passphrase or PSK, or none for a network `stela.cfg` names as
//! open (`--wifi-open`). A missing or unusable key file without that setting
//! joins nothing, and the line saying so names the file but never its bytes.
use crate::options::{DEFAULT_WIFI_KEY, System};
use alloc::{format, string::String};
use stela_drivers::net::wifi::network::Secret;

/// The boot log's line for a network set as open.
pub const OPEN: &str = "HOST Wi-Fi network set as open (--wifi-open): joining it with no key, and no protected AP of its name\n";

/// The secret for `options`' `--wifi` network from `key`, the key file's
/// bytes (empty when the loader read none), or the line that says why the
/// network is not joined.
pub fn secret(options: &System, key: &[u8]) -> Result<Secret, String> {
    if options.wifi_open {
        return Ok(Secret::Open);
    }
    let path = options.wifi_key.as_deref().unwrap_or(DEFAULT_WIFI_KEY);
    if key.is_empty() {
        return Err(format!(
            "HOST Wi-Fi key {path} is missing, empty or unreadable: the network is not joined\n"
        ));
    }
    Secret::parse(key).map_err(|error| {
        format!("HOST Wi-Fi key {path} unusable ({error}): the network is not joined\n")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_open_setting_joins_without_a_key() {
        let open = System::parse("--system --wifi Cafe --wifi-open").unwrap();
        assert!(matches!(secret(&open, b""), Ok(Secret::Open)));
        let keyed = System::parse("--system --wifi Cafe").unwrap();
        assert_eq!(
            secret(&keyed, b"").err().as_deref(),
            Some(
                "HOST Wi-Fi key \\EFI\\stela\\wifi.key is missing, empty or unreadable: \
                 the network is not joined\n"
            )
        );
        let short = secret(&keyed, b"short").err().unwrap();
        assert!(short.starts_with("HOST Wi-Fi key \\EFI\\stela\\wifi.key unusable ("));
        assert!(short.ends_with("): the network is not joined\n"));
        assert!(matches!(
            secret(&keyed, b"correct horse"),
            Ok(Secret::Passphrase(_))
        ));
        assert!(OPEN.contains("--wifi-open") && OPEN.ends_with('\n'));
    }
}
