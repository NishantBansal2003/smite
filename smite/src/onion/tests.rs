//! BOLT 4 test vectors and round-trip properties.

use serde_json::Value;

use super::{KeyType, derive_key};

/// The `onion-error-test.json` vector from the BOLT repository, verbatim.
///
/// Only its key derivation is checked here; the return packet it builds is
/// covered once failure messages land.
const ONION_ERROR_TEST: &str = include_str!("vectors/onion-error-test.json");

fn hex_field(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("field is a hex string")).expect("field is valid hex")
}

#[test]
fn bolt4_vector_derives_error_keys() {
    let vector: Value = serde_json::from_str(ONION_ERROR_TEST).expect("vector is valid JSON");
    let hops = vector["generate"]["hops"]
        .as_array()
        .expect("hops is an array");

    for hop in hops {
        let secret: [u8; 32] = hex_field(&hop["hop_shared_secret"])
            .try_into()
            .expect("shared secret is 32 bytes");

        assert_eq!(
            derive_key(KeyType::Ammag, &secret)[..],
            hex_field(&hop["ammag_key"]),
        );
        // Only the erring node's `um` key is listed.
        if let Some(um_key) = hop.get("um_key") {
            assert_eq!(derive_key(KeyType::Um, &secret)[..], hex_field(um_key));
        }
    }
}
