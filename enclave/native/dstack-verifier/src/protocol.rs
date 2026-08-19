use std::fmt::{Display, Formatter};
use std::io::{Read, Write};

use serde::de::{DeserializeOwned, DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

pub const MAX_INPUT_BYTES: usize = 8_388_608;
pub const MAX_OUTPUT_BYTES: usize = 65_536;
pub const PROTOCOL_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    Io,
    Empty,
    Oversized,
    Trailing,
    Malformed,
}

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("dstack_protocol_error")
    }
}

impl std::error::Error for ProtocolError {}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeInputV1 {
    pub version: u8,
    pub quote: String,
    pub collateral: String,
    #[serde(rename = "eventLog")]
    pub event_log: String,
    #[serde(rename = "vmConfig")]
    pub vm_config: String,
    pub expected: ExpectedEvidenceV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedEvidenceV1 {
    pub rtmr: String,
    #[serde(rename = "runtimeIdentityDigest")]
    pub runtime_identity_digest: String,
    #[serde(rename = "workloadArtifactDigest")]
    pub workload_artifact_digest: String,
    #[serde(rename = "routeIdentityDigest")]
    pub route_identity_digest: String,
    #[serde(rename = "tcbStatus")]
    pub tcb_status: String,
    #[serde(rename = "kmsRootDigests")]
    pub kms_root_digests: Vec<String>,
    #[serde(rename = "channelPinDigests")]
    pub channel_pin_digests: Vec<String>,
    pub upstream: UpstreamEvidenceV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamEvidenceV1 {
    #[serde(rename = "quoteVerified")]
    pub quote_verified: bool,
    #[serde(rename = "eventLogVerified")]
    pub event_log_verified: bool,
    #[serde(rename = "osImageHashVerified")]
    pub os_image_hash_verified: bool,
    #[serde(rename = "acpiTablesVerified")]
    pub acpi_tables_verified: bool,
    #[serde(rename = "teeVariant")]
    pub tee_variant: String,
    #[serde(rename = "reportData")]
    pub report_data: String,
    #[serde(rename = "tcbStatus")]
    pub tcb_status: String,
    #[serde(rename = "advisoryIds")]
    pub advisory_ids: Vec<String>,
    #[serde(rename = "appInfo")]
    pub app_info: UpstreamAppInfoV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamAppInfoV1 {
    #[serde(rename = "appIdDigest")]
    pub app_id_digest: String,
    #[serde(rename = "composeHashDigest")]
    pub compose_hash_digest: String,
    #[serde(rename = "instanceIdDigest")]
    pub instance_id_digest: String,
    #[serde(rename = "deviceIdDigest")]
    pub device_id_digest: String,
    #[serde(rename = "mrSystemDigest")]
    pub mr_system_digest: String,
    #[serde(rename = "mrAggregatedDigest")]
    pub mr_aggregated_digest: String,
    #[serde(rename = "osImageHashDigest")]
    pub os_image_hash_digest: String,
    #[serde(rename = "keyProviderInfoDigest")]
    pub key_provider_info_digest: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOutputV1 {
    pub version: u8,
    pub verdict: &'static str,
    #[serde(rename = "quoteDigest")]
    pub quote_digest: String,
    #[serde(rename = "collateralDigest")]
    pub collateral_digest: String,
    #[serde(rename = "eventLogDigest")]
    pub event_log_digest: String,
    #[serde(rename = "vmConfigDigest")]
    pub vm_config_digest: String,
    pub rtmr: String,
    #[serde(rename = "runtimeIdentityDigest")]
    pub runtime_identity_digest: String,
    #[serde(rename = "workloadArtifactDigest")]
    pub workload_artifact_digest: String,
    #[serde(rename = "routeIdentityDigest")]
    pub route_identity_digest: String,
    #[serde(rename = "tcbStatus")]
    pub tcb_status: String,
    #[serde(rename = "kmsRootDigests")]
    pub kms_root_digests: Vec<String>,
    #[serde(rename = "channelPinDigests")]
    pub channel_pin_digests: Vec<String>,
    pub upstream: UpstreamEvidenceV1,
    #[serde(rename = "failureCode")]
    pub failure_code: &'static str,
}

pub fn read_frame<R: Read>(mut reader: R, maximum: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut prefix = [0u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| ProtocolError::Io)?;
    let declared = u32::from_be_bytes(prefix) as usize;
    if declared == 0 {
        return Err(ProtocolError::Empty);
    }
    if declared > maximum {
        return Err(ProtocolError::Oversized);
    }
    let mut payload = vec![0u8; declared];
    reader
        .read_exact(&mut payload)
        .map_err(|_| ProtocolError::Io)?;
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing).map_err(|_| ProtocolError::Io)? != 0 {
        return Err(ProtocolError::Trailing);
    }
    Ok(payload)
}

pub fn write_frame<W: Write>(
    mut writer: W,
    payload: &[u8],
    maximum: usize,
) -> Result<(), ProtocolError> {
    if payload.is_empty() {
        return Err(ProtocolError::Empty);
    }
    if payload.len() > maximum || payload.len() > u32::MAX as usize {
        return Err(ProtocolError::Oversized);
    }
    let length = (payload.len() as u32).to_be_bytes();
    writer
        .write_all(&length)
        .and_then(|_| writer.write_all(payload))
        .and_then(|_| writer.flush())
        .map_err(|_| ProtocolError::Io)
}

pub fn parse_json_strict<T: DeserializeOwned>(payload: &[u8]) -> Result<T, ProtocolError> {
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    DuplicateKeySeed
        .deserialize(&mut deserializer)
        .map_err(|_| ProtocolError::Malformed)?;
    deserializer.end().map_err(|_| ProtocolError::Malformed)?;
    serde_json::from_slice(payload).map_err(|_| ProtocolError::Malformed)
}

struct DuplicateKeySeed;

impl<'de> DeserializeSeed<'de> for DuplicateKeySeed {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateKeyVisitor)
    }
}

struct DuplicateKeyVisitor;

impl<'de> Visitor<'de> for DuplicateKeyVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_string<E>(self, _: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(A::Error::custom("duplicate object key"));
            }
            map.next_value_seed(DuplicateKeySeed)?;
        }
        Ok(())
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(DuplicateKeySeed)?.is_some() {}
        Ok(())
    }
}
