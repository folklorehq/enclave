use std::io::Cursor;

use dstack_verifier::{
    parse_json_strict, read_frame, write_frame, NativeInputV1, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES,
};

#[test]
fn length_prefixed_frames_round_trip_without_trailing_bytes() {
    let payload = br#"{"version":1}"#;
    let mut encoded = Vec::new();

    write_frame(&mut encoded, payload, MAX_OUTPUT_BYTES).expect("frame writes");

    let decoded = read_frame(Cursor::new(encoded), MAX_INPUT_BYTES).expect("frame reads");
    assert_eq!(decoded, payload);
}

#[test]
fn length_prefixed_reader_rejects_missing_and_trailing_bytes() {
    assert!(read_frame(Cursor::new(Vec::<u8>::new()), MAX_INPUT_BYTES).is_err());

    let mut encoded = Vec::new();
    write_frame(&mut encoded, b"{}", MAX_OUTPUT_BYTES).expect("frame writes");
    encoded.push(0);
    assert!(read_frame(Cursor::new(encoded), MAX_INPUT_BYTES).is_err());
}

#[test]
fn length_prefixed_reader_rejects_oversized_declared_payload() {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(MAX_INPUT_BYTES as u32 + 1).to_be_bytes());

    assert!(read_frame(Cursor::new(encoded), MAX_INPUT_BYTES).is_err());
}

#[test]
fn length_prefixed_writer_rejects_oversized_payload() {
    let payload = vec![0; MAX_OUTPUT_BYTES + 1];
    let mut encoded = Vec::new();

    assert!(write_frame(&mut encoded, &payload, MAX_OUTPUT_BYTES).is_err());
    assert!(encoded.is_empty());
}

#[test]
fn native_input_preserves_upstream_wire_fields_separately_from_local_expectations() {
    let payload = serde_json::json!({
        "version": 1,
        "quote": "cXVvdGU=",
        "collateral": "Y29sbGF0ZXJhbA==",
        "eventLog": "[{\"imr\":3,\"event_type\":134217729}]",
        "vmConfig": "{\"os_image_hash\":\"fixture-image\"}",
        "expected": {
            "rtmr": "a".repeat(96),
            "runtimeIdentityDigest": "b".repeat(64),
            "workloadArtifactDigest": "c".repeat(64),
            "routeIdentityDigest": "d".repeat(64),
            "tcbStatus": "UpToDate",
            "kmsRootDigests": ["e".repeat(64)],
            "channelPinDigests": ["f".repeat(64)],
            "upstream": {
                "quoteVerified": true,
                "eventLogVerified": true,
                "osImageHashVerified": true,
                "acpiTablesVerified": true,
                "teeVariant": "dstack-tdx",
                    "reportData": "0".repeat(128),
                "tcbStatus": "UpToDate",
                "advisoryIds": [],
                "appInfo": {
                    "appIdDigest": "1".repeat(64),
                    "composeHashDigest": "2".repeat(64),
                    "instanceIdDigest": "3".repeat(64),
                    "deviceIdDigest": "4".repeat(64),
                    "mrSystemDigest": "5".repeat(64),
                    "mrAggregatedDigest": "6".repeat(64),
                    "osImageHashDigest": "7".repeat(64),
                    "keyProviderInfoDigest": "8".repeat(64)
                }
            }
        }
    });

    let input: NativeInputV1 =
        parse_json_strict(&serde_json::to_vec(&payload).expect("fixture serializes"))
            .expect("wire input parses");

    assert_eq!(input.event_log, "[{\"imr\":3,\"event_type\":134217729}]");
    assert_eq!(input.vm_config, "{\"os_image_hash\":\"fixture-image\"}");
    assert_eq!(input.expected.rtmr, "a".repeat(96));
}
