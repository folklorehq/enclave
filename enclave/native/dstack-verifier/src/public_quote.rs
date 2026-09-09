use serde::{Deserialize, Serialize};

use crate::protocol::parse_json_strict;

const MAX_COMPONENT_BYTES: usize = 1_048_576;
const MAX_EVALUATION_TIME: u64 = 9_007_199_254_740_991;
const INTEL_ROOT: &[u8] = include_bytes!("../trusted/IntelSGXRootCA.der");
const INTEL_ROOT_DIGEST: &str = "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Input {
    version: u8,
    quote_base64: String,
    collateral_base64: String,
    event_log: String,
    vm_config: String,
    evaluation_time_unix_seconds: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Output {
    version: u8,
    verdict: &'static str,
    failure_code: &'static str,
    quote_digest_hex: String,
    collateral_digest_hex: String,
    event_log_digest_hex: String,
    vm_config_digest_hex: String,
    quote_root_digest_hex: String,
    report_data_hex: String,
    tee_variant: &'static str,
    tcb_status: String,
    advisory_ids: Vec<String>,
    mr_td_hex: String,
    rtmr0_hex: String,
    rtmr1_hex: String,
    rtmr2_hex: String,
    rtmr3_hex: String,
    replayed_rtmr3_hex: String,
    app_info: AppInfo,
    key_provider: KeyProvider,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AppInfo {
    app_id_hex: String,
    instance_id_hex: String,
    compose_hash_hex: String,
    key_provider_info_digest_hex: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeyProvider {
    name: String,
    id: String,
}

pub fn verify(bytes: &[u8]) -> Result<Output, &'static str> {
    let input: Input = parse_json_strict(bytes).map_err(|_| "malformed_input")?;
    if input.version != 2
        || input.evaluation_time_unix_seconds == 0
        || input.evaluation_time_unix_seconds > MAX_EVALUATION_TIME
        || !valid_component(&input.event_log)
        || !valid_component(&input.vm_config)
        || !valid_component(&input.quote_base64)
        || !valid_component(&input.collateral_base64)
    {
        return Err("malformed_input");
    }
    verify_offline(input)
}

#[cfg(not(target_os = "linux"))]
fn verify_offline(_input: Input) -> Result<Output, &'static str> {
    Err("unavailable")
}

#[cfg(target_os = "linux")]
fn verify_offline(input: Input) -> Result<Output, &'static str> {
    use dcap_qvl::{verify::QuoteVerifier, QuoteCollateralV3};
    use dstack_attest::attestation::Attestation;

    let quote = crate::decode_base64(&input.quote_base64).ok_or("malformed_input")?;
    let collateral_bytes =
        crate::decode_base64(&input.collateral_base64).ok_or("malformed_input")?;
    let collateral: QuoteCollateralV3 =
        parse_json_strict(&collateral_bytes).map_err(|_| "malformed_input")?;
    // This compiled certificate is the production root shipped in the exact pinned QVL version.
    // No input/environment-supplied roots, online collateral clients, or insecure flags are used.
    if crate::digest(INTEL_ROOT) != INTEL_ROOT_DIGEST {
        return Err("unavailable");
    }
    let verified = QuoteVerifier::new_prod()
        .verify(&quote, &collateral, input.evaluation_time_unix_seconds)
        .map_err(|_| "quote_verification_failed")?;
    if verified.status != "UpToDate" {
        return Err("quote_verification_failed");
    }
    let td = verified.report.as_td10().ok_or("unsupported_tee")?;
    // Enforce duplicate-key rejection before the upstream compatibility decoder parses events.
    let _: serde_json::Value =
        parse_json_strict(input.event_log.as_bytes()).map_err(|_| "malformed_input")?;
    let attestation = Attestation::from_tdx_quote(quote.clone(), input.event_log.as_bytes())
        .map_err(|_| "event_log_verification_failed")?;
    if attestation.runtime_events.len() > 4_096 || attestation.report_data != td.report_data {
        return Err("event_log_verification_failed");
    }
    let replayed = attestation.replay_runtime_events::<ez_hash::Sha384>(None);
    if replayed.as_ref() != td.rt_mr3 {
        return Err("event_log_verification_failed");
    }
    // Identity events are only authoritative before system-ready. Reject ambiguous duplicates.
    let preboot: Vec<_> = attestation
        .runtime_events
        .iter()
        .take_while(|event| event.event != "system-ready")
        .collect();
    if preboot.len() == attestation.runtime_events.len() {
        return Err("event_log_verification_failed");
    }
    for name in ["app-id", "instance-id", "compose-hash", "key-provider"] {
        if preboot.iter().filter(|event| event.event == name).count() != 1 {
            return Err("event_log_verification_failed");
        }
    }
    let app_id = attestation
        .decode_app_id()
        .map_err(|_| "event_log_verification_failed")?;
    let instance_id = attestation
        .decode_instance_id()
        .map_err(|_| "event_log_verification_failed")?;
    let compose_hash = attestation
        .decode_compose_hash()
        .map_err(|_| "event_log_verification_failed")?;
    if app_id.len() != 40 || instance_id.len() != 40 || compose_hash.len() != 64 {
        return Err("event_log_verification_failed");
    }
    let provider_event = preboot
        .iter()
        .find(|event| event.event == "key-provider")
        .ok_or("event_log_verification_failed")?;
    let provider: KeyProvider =
        parse_json_strict(&provider_event.payload).map_err(|_| "event_log_verification_failed")?;
    if provider.name != "kms"
        || provider.id.is_empty()
        || provider.id.len() > 2_048
        || provider.id.len() % 2 != 0
        || !provider
            .id
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err("event_log_verification_failed");
    }
    let mut advisories = verified.advisory_ids;
    advisories.sort();
    advisories.dedup();
    if !crate::valid_advisory_ids(&advisories) {
        return Err("quote_verification_failed");
    }
    Ok(Output {
        version: 2,
        verdict: "accepted",
        failure_code: "none",
        quote_digest_hex: crate::digest(&quote),
        collateral_digest_hex: crate::digest(&collateral_bytes),
        event_log_digest_hex: crate::digest(input.event_log.as_bytes()),
        vm_config_digest_hex: crate::digest(input.vm_config.as_bytes()),
        quote_root_digest_hex: crate::digest(INTEL_ROOT),
        report_data_hex: hex(&td.report_data),
        tee_variant: "dstack-tdx",
        tcb_status: verified.status,
        advisory_ids: advisories,
        mr_td_hex: hex(&td.mr_td),
        rtmr0_hex: hex(&td.rt_mr0),
        rtmr1_hex: hex(&td.rt_mr1),
        rtmr2_hex: hex(&td.rt_mr2),
        rtmr3_hex: hex(&td.rt_mr3),
        replayed_rtmr3_hex: hex(replayed.as_ref()),
        app_info: AppInfo {
            app_id_hex: app_id,
            instance_id_hex: instance_id,
            compose_hash_hex: compose_hash,
            key_provider_info_digest_hex: crate::digest(&provider_event.payload),
        },
        key_provider: provider,
    })
}

fn valid_component(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_COMPONENT_BYTES
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn production_root_has_the_pinned_qvl_identity() {
        assert_eq!(crate::digest(INTEL_ROOT), INTEL_ROOT_DIGEST);
    }
    #[test]
    fn rejects_expected_authority_fields_and_invalid_time() {
        let base = serde_json::json!({"version":2,"quoteBase64":"AA==","collateralBase64":"AA==",
            "eventLog":"[]","vmConfig":"{}","evaluationTimeUnixSeconds":1});
        for (key, value) in [
            ("expected", serde_json::json!({})),
            ("workloadKeysetDigestHex", serde_json::json!("a".repeat(64))),
            ("evaluationTimeUnixSeconds", serde_json::json!(0)),
            (
                "evaluationTimeUnixSeconds",
                serde_json::json!(MAX_EVALUATION_TIME + 1),
            ),
        ] {
            let mut invalid = base.clone();
            invalid[key] = value;
            assert!(matches!(
                verify(&serde_json::to_vec(&invalid).unwrap()),
                Err("malformed_input")
            ));
        }
    }
}
