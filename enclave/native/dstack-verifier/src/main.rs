mod protocol;
mod public_quote;

use std::io;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

#[cfg(target_os = "linux")]
use dstack_upstream_verifier::VerificationRequest;

use protocol::{
    parse_json_strict, read_frame, write_frame, ExpectedEvidenceV1, NativeInputV1, NativeOutputV1,
    UpstreamEvidenceV1, MAX_INPUT_BYTES, MAX_OUTPUT_BYTES, PROTOCOL_VERSION,
};

const DIGEST_LENGTH: usize = 64;
const RTMR_LENGTH: usize = 96;
const MAX_ARRAY_ITEMS: usize = 64;
const MAX_WIRE_BYTES: usize = 1_048_576;
const MAX_TCB_STATUS_LENGTH: usize = 64;
const MAX_ADVISORY_ID_LENGTH: usize = 128;
const EXPECTED_TCB_STATUS: &str = "UpToDate";

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(()) => std::process::ExitCode::FAILURE,
    }
}

fn run() -> Result<(), ()> {
    let mut stdin = io::stdin().lock();
    let input_bytes = read_frame(&mut stdin, MAX_INPUT_BYTES).map_err(|_| ())?;
    let envelope: serde_json::Value = parse_json_strict(&input_bytes).map_err(|_| ())?;
    let output_bytes = match envelope.get("version").and_then(|value| value.as_u64()) {
        Some(1) => {
            let input: NativeInputV1 = parse_json_strict(&input_bytes).map_err(|_| ())?;
            serde_json::to_vec(&verify(input).ok_or(())?).map_err(|_| ())?
        }
        Some(2) => match public_quote::verify(&input_bytes) {
            Ok(output) => serde_json::to_vec(&output).map_err(|_| ())?,
            Err(code) => serde_json::to_vec(&serde_json::json!({
                "version": 2, "verdict": "rejected", "failureCode": code
            }))
            .map_err(|_| ())?,
        },
        _ => return Err(()),
    };
    let mut stdout = io::stdout().lock();
    write_frame(&mut stdout, &output_bytes, MAX_OUTPUT_BYTES).map_err(|_| ())
}

fn verify(input: NativeInputV1) -> Option<NativeOutputV1> {
    if input.version != PROTOCOL_VERSION
        || !valid_wire(&input.event_log)
        || !valid_wire(&input.vm_config)
        || !valid_expected_evidence(&input.expected)
    {
        return None;
    }

    let quote = decode_base64(&input.quote)?;
    let collateral = decode_base64(&input.collateral)?;
    let output = unavailable_output(&input, &quote, &collateral);

    #[cfg(target_os = "linux")]
    {
        let _ = offline_upstream_verification_request(&input, &quote);
    }

    Some(output)
}

fn unavailable_output(input: &NativeInputV1, quote: &[u8], collateral: &[u8]) -> NativeOutputV1 {
    NativeOutputV1 {
        version: PROTOCOL_VERSION,
        verdict: "rejected",
        quote_digest: digest(quote),
        collateral_digest: digest(collateral),
        event_log_digest: digest(input.event_log.as_bytes()),
        vm_config_digest: digest(input.vm_config.as_bytes()),
        rtmr: input.expected.rtmr.clone(),
        runtime_identity_digest: input.expected.runtime_identity_digest.clone(),
        workload_artifact_digest: input.expected.workload_artifact_digest.clone(),
        route_identity_digest: input.expected.route_identity_digest.clone(),
        tcb_status: input.expected.tcb_status.clone(),
        kms_root_digests: input.expected.kms_root_digests.clone(),
        channel_pin_digests: input.expected.channel_pin_digests.clone(),
        upstream: input.expected.upstream.clone(),
        failure_code: "dstack_unavailable",
    }
}

#[cfg(target_os = "linux")]
fn offline_upstream_verification_request(
    input: &NativeInputV1,
    quote: &[u8],
) -> VerificationRequest {
    VerificationRequest {
        quote: Some(quote.to_vec()),
        event_log: Some(input.event_log.clone()),
        vm_config: Some(input.vm_config.clone()),
        attestation: None,
        debug: Some(false),
    }
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() {
        return None;
    }
    let decoded = STANDARD.decode(value).ok()?;
    if STANDARD.encode(&decoded) != value {
        return None;
    }
    Some(decoded)
}

fn valid_wire(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_WIRE_BYTES
}

fn valid_expected_evidence(expected: &ExpectedEvidenceV1) -> bool {
    valid_rtmr(&expected.rtmr)
        && valid_digest(&expected.runtime_identity_digest)
        && valid_digest(&expected.workload_artifact_digest)
        && valid_digest(&expected.route_identity_digest)
        && valid_identifier(&expected.tcb_status, MAX_TCB_STATUS_LENGTH)
        && expected.tcb_status == EXPECTED_TCB_STATUS
        && valid_digest_array(&expected.kms_root_digests)
        && valid_digest_array(&expected.channel_pin_digests)
        && expected.tcb_status == expected.upstream.tcb_status
        && valid_upstream_evidence(&expected.upstream)
}

fn valid_upstream_evidence(upstream: &UpstreamEvidenceV1) -> bool {
    valid_tee_variant(&upstream.tee_variant)
        && valid_report_data(&upstream.report_data)
        && upstream.quote_verified
        && upstream.event_log_verified
        && upstream.os_image_hash_verified
        && upstream.acpi_tables_verified
        && upstream.tcb_status == EXPECTED_TCB_STATUS
        && valid_identifier(&upstream.tcb_status, MAX_TCB_STATUS_LENGTH)
        && valid_advisory_ids(&upstream.advisory_ids)
        && valid_digest(&upstream.app_info.app_id_digest)
        && valid_digest(&upstream.app_info.compose_hash_digest)
        && valid_digest(&upstream.app_info.instance_id_digest)
        && valid_digest(&upstream.app_info.device_id_digest)
        && valid_digest(&upstream.app_info.mr_system_digest)
        && valid_digest(&upstream.app_info.mr_aggregated_digest)
        && valid_digest(&upstream.app_info.os_image_hash_digest)
        && valid_digest(&upstream.app_info.key_provider_info_digest)
}

fn valid_tee_variant(value: &str) -> bool {
    matches!(
        value,
        "dstack-amd-sev-snp"
            | "dstack-aws-nitro-tpm"
            | "dstack-gcp-tdx"
            | "dstack-nitro-enclave"
            | "dstack-tdx"
    )
}

fn valid_advisory_ids(values: &[String]) -> bool {
    values.len() <= MAX_ARRAY_ITEMS
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values
            .iter()
            .all(|value| valid_identifier(value, MAX_ADVISORY_ID_LENGTH))
}

fn valid_rtmr(value: &str) -> bool {
    value.len() == RTMR_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_report_data(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_digest(value: &str) -> bool {
    value.len() == DIGEST_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_digest_array(values: &[String]) -> bool {
    values.len() <= MAX_ARRAY_ITEMS
        && values.windows(2).all(|pair| pair[0] < pair[1])
        && values.iter().all(|value| valid_digest(value))
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    if value.is_empty() || value.len() > maximum {
        return false;
    }
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|character| {
        character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '/' | '+' | '-')
    })
}

fn digest(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::offline_upstream_verification_request;
    use crate::protocol::{
        ExpectedEvidenceV1, NativeInputV1, UpstreamAppInfoV1, UpstreamEvidenceV1,
    };

    fn input() -> NativeInputV1 {
        NativeInputV1 {
            version: 1,
            quote: "cXVvdGU=".to_string(),
            collateral: "Y29sbGF0ZXJhbA==".to_string(),
            event_log: "[{\"imr\":3}]".to_string(),
            vm_config: "{\"os_image_hash\":\"fixture-image\"}".to_string(),
            expected: ExpectedEvidenceV1 {
                rtmr: "a".repeat(96),
                runtime_identity_digest: "b".repeat(64),
                workload_artifact_digest: "c".repeat(64),
                route_identity_digest: "d".repeat(64),
                tcb_status: "UpToDate".to_string(),
                kms_root_digests: vec!["e".repeat(64)],
                channel_pin_digests: vec!["f".repeat(64)],
                upstream: UpstreamEvidenceV1 {
                    quote_verified: true,
                    event_log_verified: true,
                    os_image_hash_verified: true,
                    acpi_tables_verified: true,
                    tee_variant: "dstack-tdx".to_string(),
                    report_data: "0".repeat(128),
                    tcb_status: "UpToDate".to_string(),
                    advisory_ids: Vec::new(),
                    app_info: UpstreamAppInfoV1 {
                        app_id_digest: "1".repeat(64),
                        compose_hash_digest: "2".repeat(64),
                        instance_id_digest: "3".repeat(64),
                        device_id_digest: "4".repeat(64),
                        mr_system_digest: "5".repeat(64),
                        mr_aggregated_digest: "6".repeat(64),
                        os_image_hash_digest: "7".repeat(64),
                        key_provider_info_digest: "8".repeat(64),
                    },
                },
            },
        }
    }

    #[test]
    fn exact_upstream_wire_fields_are_mapped_without_an_online_call() {
        let request = offline_upstream_verification_request(&input(), b"quote");

        assert_eq!(request.quote, Some(b"quote".to_vec()));
        assert_eq!(request.event_log.as_deref(), Some("[{\"imr\":3}]"));
        assert_eq!(
            request.vm_config.as_deref(),
            Some("{\"os_image_hash\":\"fixture-image\"}")
        );
        assert_eq!(request.attestation, None);
    }
}
