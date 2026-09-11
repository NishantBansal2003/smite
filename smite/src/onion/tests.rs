//! BOLT 4 test vectors and round-trip properties.

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde_json::Value;

use super::{HopPayload, KeyType, OnionError, PaymentData, derive_key};
use crate::bolt::{BigSize, BoltError, ShortChannelId, WireFormat};

/// The `onion-test.json` vector from the BOLT repository, verbatim.
const ONION_TEST: &str = include_str!("vectors/onion-test.json");

/// The `onion-error-test.json` vector from the BOLT repository, verbatim.
///
/// Only its key derivation is checked here; the return packet it builds is
/// covered once failure messages land.
const ONION_ERROR_TEST: &str = include_str!("vectors/onion-error-test.json");

fn vector() -> Value {
    serde_json::from_str(ONION_TEST).expect("vector is valid JSON")
}

fn hex_field(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("field is a hex string")).expect("field is valid hex")
}

/// The vector's payloads carry their `bigsize` length prefix; strip it to get
/// the bare TLV stream.
fn strip_length_prefix(payload: &[u8]) -> Vec<u8> {
    let mut cursor = payload;
    let length = BigSize::read(&mut cursor).expect("length prefix is valid");
    assert_eq!(
        u64::try_from(cursor.len()).unwrap(),
        length.value(),
        "vector payload length prefix disagrees with its body"
    );
    cursor.to_vec()
}

/// Deterministic keys: hop `i` uses secret key `[i; 32]`.
fn route(hops: usize) -> (Vec<SecretKey>, Vec<PublicKey>) {
    let secp = Secp256k1::new();
    let secrets: Vec<SecretKey> = (1..=hops)
        .map(|i| SecretKey::from_slice(&[u8::try_from(i).unwrap(); 32]).unwrap())
        .collect();
    let publics = secrets
        .iter()
        .map(|sk| PublicKey::from_secret_key(&secp, sk))
        .collect();
    (secrets, publics)
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

#[test]
fn bolt4_vector_hop_payload_decodes() {
    let vector = vector();
    let payload = strip_length_prefix(&hex_field(&vector["generate"]["hops"][0]["payload"]));

    let decoded = HopPayload::decode(&payload).expect("vector payload decodes");

    assert_eq!(
        decoded,
        HopPayload::forward(ShortChannelId::from_u64(1), 15_000, 1_500)
    );
    assert_eq!(decoded.encode(), payload);
}

#[test]
fn hop_payload_roundtrips_every_field() {
    let (_, publics) = route(1);
    let payload = HopPayload {
        amt_to_forward: Some(1_000_000),
        outgoing_cltv_value: Some(700_000),
        short_channel_id: Some(ShortChannelId::new(700_000, 3, 1)),
        payment_data: Some(PaymentData {
            payment_secret: [0x11; 32],
            total_msat: 2_000_000,
        }),
        encrypted_recipient_data: Some(vec![0x22; 16]),
        current_path_key: Some(publics[0]),
        payment_metadata: Some(vec![0x33; 8]),
        total_amount_msat: Some(3_000_000),
    };

    assert_eq!(HopPayload::decode(&payload.encode()).unwrap(), payload);
}

#[test]
fn hop_payload_encodes_zero_amounts_as_empty_values() {
    let payload = HopPayload {
        amt_to_forward: Some(0),
        outgoing_cltv_value: Some(0),
        ..HopPayload::default()
    };

    // Two records, each with a zero-length truncated integer value.
    assert_eq!(payload.encode(), vec![2, 0, 4, 0]);
    assert_eq!(HopPayload::decode(&payload.encode()).unwrap(), payload);
}

#[test]
fn hop_payload_rejects_non_minimal_truncated_integers() {
    // amt_to_forward with a leading zero byte.
    let payload = [2u8, 2, 0, 1];

    assert_eq!(
        HopPayload::decode(&payload),
        Err(OnionError::Bolt(BoltError::TruncatedIntNotMinimal))
    );
}

#[test]
fn hop_payload_rejects_unknown_even_types() {
    let payload = [20u8, 1, 0];

    assert_eq!(
        HopPayload::decode(&payload),
        Err(OnionError::Bolt(BoltError::TlvUnknownEvenType(20)))
    );
}

#[test]
fn hop_payload_receive_roundtrips() {
    let payload = HopPayload::receive(1_000, 800_000, [0x77; 32], 5_000);

    assert_eq!(
        payload.payment_data,
        Some(PaymentData {
            payment_secret: [0x77; 32],
            total_msat: 5_000,
        })
    );
    assert_eq!(HopPayload::decode(&payload.encode()).unwrap(), payload);
}
