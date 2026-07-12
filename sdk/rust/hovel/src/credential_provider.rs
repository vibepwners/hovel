//! Optional, secret-aware credential provider execution contracts.

use std::fmt;

use crate::base64;
use crate::credential_delivery::{
    optional_string, required_bytes, required_i64, required_string, required_value,
    CredentialMaterialForm, CredentialProjection, CredentialStampRequest, CredentialStampTarget,
    ResolvedCredentialMetadata,
};
use crate::json::Value;

pub const CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1: &str = "hovel.pki.provider-execution/v1";
pub const CREDENTIAL_RPC_RUNTIME_METHOD: &str = "credential.runtime";
pub const CREDENTIAL_RPC_FILES_METHOD: &str = "credential.files";
pub const CREDENTIAL_RPC_ENCODE_METHOD: &str = "credential.encode";
pub const CREDENTIAL_RPC_STAMP_METHOD: &str = "credential.stamp";

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialBytes(Vec<u8>);

impl CredentialBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("credential bytes must not be empty".to_string());
        }
        Ok(Self(bytes))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn from_value(value: &Value, name: &str) -> Result<Self, String> {
        Self::new(required_bytes(value, name)?)
    }

    fn to_value(&self) -> Value {
        Value::from(base64::encode(&self.0).as_str())
    }
}

impl fmt::Debug for CredentialBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<credential bytes redacted>")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialSecretReference(String);

impl CredentialSecretReference {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err("credential secret reference must not be empty".to_string());
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CredentialSecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<credential secret redacted>")
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialProtectedPath(String);

impl CredentialProtectedPath {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err("credential protected path must not be empty".to_string());
        }
        Ok(Self(value))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for CredentialProtectedPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<credential secret redacted>")
    }
}

#[derive(Clone, Debug, Default)]
pub struct CredentialOperationScope {
    pub operation_id: Option<String>,
    pub run_id: Option<String>,
    pub chain_id: Option<String>,
    pub throw_id: Option<String>,
    pub target: Option<String>,
    pub listener_id: Option<String>,
    pub node_id: Option<String>,
}

impl CredentialOperationScope {
    fn from_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            operation_id: optional_string(value, "operationId")?,
            run_id: optional_string(value, "runId")?,
            chain_id: optional_string(value, "chainId")?,
            throw_id: optional_string(value, "throwId")?,
            target: optional_string(value, "target")?,
            listener_id: optional_string(value, "listenerId")?,
            node_id: optional_string(value, "nodeId")?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CredentialProviderTarget {
    pub module_id: String,
    pub provider_id: String,
    pub provider_version: String,
    pub descriptor_sha256: String,
}

impl CredentialProviderTarget {
    fn from_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            module_id: required_string(value, "moduleId")?,
            provider_id: required_string(value, "providerId")?,
            provider_version: required_string(value, "providerVersion")?,
            descriptor_sha256: required_string(value, "descriptorSha256")?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CredentialScopedReference {
    pub provider_id: String,
    pub reference: CredentialSecretReference,
    pub capabilities: Vec<String>,
}

#[derive(Clone, Debug)]
pub enum CredentialMaterialValue {
    Bytes(CredentialBytes),
    Reference(CredentialScopedReference),
}

#[derive(Clone)]
pub struct ResolvedCredentialMaterial {
    pub projection: CredentialProjection,
    pub encoding: String,
    pub sha256: String,
    form: CredentialMaterialForm,
    value: CredentialMaterialValue,
}

impl fmt::Debug for ResolvedCredentialMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedCredentialMaterial")
            .field("projection", &self.projection)
            .field("form", &self.form)
            .field("encoding", &self.encoding)
            .field("sha256", &self.sha256)
            .field("value", &self.value)
            .finish()
    }
}

impl ResolvedCredentialMaterial {
    pub fn new(
        projection: CredentialProjection,
        form: CredentialMaterialForm,
        encoding: impl Into<String>,
        sha256: impl Into<String>,
        value: CredentialMaterialValue,
    ) -> Result<Self, String> {
        let matches = match (&form, &value) {
            (
                CredentialMaterialForm::Public | CredentialMaterialForm::PrivateBytes,
                CredentialMaterialValue::Bytes(_),
            ) => true,
            (CredentialMaterialForm::PrivateReference, CredentialMaterialValue::Reference(_)) => {
                true
            }
            _ => false,
        };
        if !matches {
            return Err("resolved credential material form does not match its value".to_string());
        }
        Ok(Self {
            projection,
            encoding: encoding.into(),
            sha256: sha256.into(),
            form,
            value,
        })
    }

    pub const fn form(&self) -> CredentialMaterialForm {
        self.form
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        match &self.value {
            CredentialMaterialValue::Bytes(value) => Some(value.as_slice()),
            CredentialMaterialValue::Reference(_) => None,
        }
    }

    pub fn reference(&self) -> Option<&CredentialScopedReference> {
        match &self.value {
            CredentialMaterialValue::Bytes(_) => None,
            CredentialMaterialValue::Reference(value) => Some(value),
        }
    }

    fn from_value(value: &Value) -> Result<Self, String> {
        let form = CredentialMaterialForm::parse(&required_string(value, "form")?)?;
        let data = value
            .get("data")
            .map(|_| CredentialBytes::from_value(value, "data"))
            .transpose()?;
        let reference = value
            .get("reference")
            .map(parse_scoped_reference)
            .transpose()?;
        let material_value =
            match (data, reference) {
                (Some(data), None) if form != CredentialMaterialForm::PrivateReference => {
                    CredentialMaterialValue::Bytes(data)
                }
                (None, Some(reference)) if form == CredentialMaterialForm::PrivateReference => {
                    CredentialMaterialValue::Reference(reference)
                }
                _ => return Err(
                    "resolved credential material requires exactly one data or reference variant"
                        .to_string(),
                ),
            };
        Self::new(
            CredentialProjection::parse(&required_string(value, "projection")?)?,
            form,
            required_string(value, "encoding")?,
            required_string(value, "sha256")?,
            material_value,
        )
    }
}

#[derive(Clone, Debug)]
pub struct CredentialRuntimeRequest {
    pub request_id: String,
    pub provider: CredentialProviderTarget,
    pub assignment_id: String,
    pub slot_name: String,
    pub credential: ResolvedCredentialMetadata,
    pub material: ResolvedCredentialMaterial,
    pub scope: CredentialOperationScope,
}

impl CredentialRuntimeRequest {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        require_schema(value)?;
        Ok(Self {
            request_id: required_string(value, "requestId")?,
            provider: CredentialProviderTarget::from_value(required_value(value, "provider")?)?,
            assignment_id: required_string(value, "assignmentId")?,
            slot_name: required_string(value, "slotName")?,
            credential: ResolvedCredentialMetadata::from_value(required_value(
                value,
                "credential",
            )?)?,
            material: ResolvedCredentialMaterial::from_value(required_value(value, "material")?)?,
            scope: CredentialOperationScope::from_value(required_value(value, "scope")?)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CredentialFile {
    pub projection: CredentialProjection,
    pub form: CredentialMaterialForm,
    pub media_type: String,
    pub path: CredentialProtectedPath,
    pub sha256: String,
    pub size: i64,
}

#[derive(Clone, Debug)]
pub struct CredentialFilesRequest {
    pub request_id: String,
    pub provider: CredentialProviderTarget,
    pub assignment_id: String,
    pub slot_name: String,
    pub credential: ResolvedCredentialMetadata,
    pub files: Vec<CredentialFile>,
    pub scope: CredentialOperationScope,
}

impl CredentialFilesRequest {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        require_schema(value)?;
        let files = required_value(value, "files")?
            .as_array()
            .ok_or_else(|| "credential files must be an array".to_string())?
            .iter()
            .map(parse_credential_file)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            request_id: required_string(value, "requestId")?,
            provider: CredentialProviderTarget::from_value(required_value(value, "provider")?)?,
            assignment_id: required_string(value, "assignmentId")?,
            slot_name: required_string(value, "slotName")?,
            credential: ResolvedCredentialMetadata::from_value(required_value(
                value,
                "credential",
            )?)?,
            files,
            scope: CredentialOperationScope::from_value(required_value(value, "scope")?)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CredentialDeliveryReceipt {
    pub request_id: String,
    pub provider_reference: Option<String>,
    pub receipt_sha256: Option<String>,
}

impl CredentialDeliveryReceipt {
    pub(crate) fn to_value(&self) -> Value {
        let mut members = vec![("requestId".into(), Value::from(self.request_id.as_str()))];
        push_optional(
            &mut members,
            "providerReference",
            self.provider_reference.as_deref(),
        );
        push_optional(
            &mut members,
            "receiptSha256",
            self.receipt_sha256.as_deref(),
        );
        Value::Object(members)
    }
}

#[derive(Clone, Debug)]
pub struct CredentialEncodingRequest {
    pub request_id: String,
    pub provider: CredentialProviderTarget,
    pub provider_id: String,
    pub provider_schema: String,
    pub output_form: CredentialMaterialForm,
    pub maximum_encoded_bytes: i64,
    pub source: ResolvedCredentialMaterial,
    pub scope: CredentialOperationScope,
}

impl CredentialEncodingRequest {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        require_schema(value)?;
        Ok(Self {
            request_id: required_string(value, "requestId")?,
            provider: CredentialProviderTarget::from_value(required_value(value, "provider")?)?,
            provider_id: required_string(value, "providerId")?,
            provider_schema: required_string(value, "providerSchema")?,
            output_form: CredentialMaterialForm::parse(&required_string(value, "outputForm")?)?,
            maximum_encoded_bytes: required_i64(value, "maximumEncodedBytes")?,
            source: ResolvedCredentialMaterial::from_value(required_value(value, "source")?)?,
            scope: CredentialOperationScope::from_value(required_value(value, "scope")?)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CredentialEncodingResult {
    pub request_id: String,
    pub form: CredentialMaterialForm,
    pub encoding: String,
    pub sha256: String,
    pub data: CredentialBytes,
}

impl CredentialEncodingResult {
    pub(crate) fn to_value(&self) -> Value {
        Value::object(vec![
            ("requestId", Value::from(self.request_id.as_str())),
            ("form", Value::from(self.form.as_str())),
            ("encoding", Value::from(self.encoding.as_str())),
            ("sha256", Value::from(self.sha256.as_str())),
            ("data", self.data.to_value()),
        ])
    }
}

#[derive(Clone, Debug)]
pub enum CredentialArtifactContent {
    Data(CredentialBytes),
    Path(CredentialProtectedPath),
}

#[derive(Clone)]
pub struct CredentialArtifactInput {
    pub artifact_id: String,
    pub sha256: String,
    pub encoding: String,
    pub content: CredentialArtifactContent,
}

impl fmt::Debug for CredentialArtifactInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialArtifactInput")
            .field("artifact_id", &self.artifact_id)
            .field("sha256", &self.sha256)
            .field("encoding", &self.encoding)
            .field("content", &self.content)
            .finish()
    }
}

impl CredentialArtifactInput {
    fn from_value(value: &Value) -> Result<Self, String> {
        let data = value
            .get("data")
            .map(|_| CredentialBytes::from_value(value, "data"))
            .transpose()?;
        let path = optional_string(value, "path")?
            .map(CredentialProtectedPath::new)
            .transpose()?;
        let content = match (data, path) {
            (Some(data), None) => CredentialArtifactContent::Data(data),
            (None, Some(path)) => CredentialArtifactContent::Path(path),
            _ => {
                return Err(
                    "credential artifact input requires exactly one data or path variant"
                        .to_string(),
                )
            }
        };
        Ok(Self {
            artifact_id: required_string(value, "id")?,
            sha256: required_string(value, "sha256")?,
            encoding: required_string(value, "encoding")?,
            content,
        })
    }
}

#[derive(Clone)]
pub struct CredentialArtifactOutput {
    pub name: String,
    pub encoding: String,
    pub content: CredentialArtifactContent,
}

impl fmt::Debug for CredentialArtifactOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialArtifactOutput")
            .field("name", &self.name)
            .field("encoding", &self.encoding)
            .field("content", &self.content)
            .finish()
    }
}

impl CredentialArtifactOutput {
    fn to_value(&self) -> Value {
        let mut members = vec![
            ("name".into(), Value::from(self.name.as_str())),
            ("encoding".into(), Value::from(self.encoding.as_str())),
        ];
        match &self.content {
            CredentialArtifactContent::Data(data) => {
                members.push(("data".into(), data.to_value()));
            }
            CredentialArtifactContent::Path(path) => {
                members.push(("path".into(), Value::from(path.expose())));
            }
        }
        Value::Object(members)
    }
}

#[derive(Clone, Debug)]
pub struct CredentialDeploymentOutput {
    pub reference: String,
    pub receipt: CredentialBytes,
}

#[derive(Clone, Debug)]
pub enum CredentialStampOutput {
    Artifact(CredentialArtifactOutput),
    Deployment(CredentialDeploymentOutput),
}

impl CredentialStampOutput {
    fn to_value(&self) -> Value {
        match self {
            Self::Artifact(output) => Value::object(vec![("artifact", output.to_value())]),
            Self::Deployment(output) => Value::object(vec![(
                "deployment",
                Value::object(vec![
                    ("reference", Value::from(output.reference.as_str())),
                    ("receipt", output.receipt.to_value()),
                ]),
            )]),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CredentialStampedMaterialDigest {
    pub projection: CredentialProjection,
    pub reference: String,
    pub sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialStampTargetResolution {
    Unchanged,
    Translated,
}

impl CredentialStampTargetResolution {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Translated => "translated",
        }
    }
}

#[derive(Clone, Debug)]
pub struct CredentialStampExecutionRequest {
    pub stamp_id: String,
    pub provider: CredentialProviderTarget,
    pub request: CredentialStampRequest,
    pub input: CredentialArtifactInput,
    pub material: ResolvedCredentialMaterial,
    pub expected_digests: Vec<CredentialStampedMaterialDigest>,
    pub scope: CredentialOperationScope,
}

impl CredentialStampExecutionRequest {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        require_schema(value)?;
        Ok(Self {
            stamp_id: required_string(value, "stampId")?,
            provider: CredentialProviderTarget::from_value(required_value(value, "provider")?)?,
            request: CredentialStampRequest::from_value(required_value(value, "request")?)?,
            input: CredentialArtifactInput::from_value(required_value(value, "input")?)?,
            material: ResolvedCredentialMaterial::from_value(required_value(
                value,
                "resolvedMaterial",
            )?)?,
            expected_digests: required_value(value, "expectedDigests")?
                .as_array()
                .ok_or_else(|| "expectedDigests must be an array".to_string())?
                .iter()
                .map(parse_stamped_material_digest)
                .collect::<Result<Vec<_>, _>>()?,
            scope: CredentialOperationScope::from_value(required_value(value, "scope")?)?,
        })
    }
}

fn parse_stamped_material_digest(value: &Value) -> Result<CredentialStampedMaterialDigest, String> {
    Ok(CredentialStampedMaterialDigest {
        projection: CredentialProjection::parse(&required_string(value, "projection")?)?,
        reference: required_string(value, "reference")?,
        sha256: required_string(value, "sha256")?,
    })
}

#[derive(Clone, Debug)]
pub struct CredentialStampExecutionResult {
    pub stamp_id: String,
    pub output: CredentialStampOutput,
    pub target_resolution: CredentialStampTargetResolution,
    pub resolved_target: CredentialStampTarget,
    pub bytes_written: String,
    pub material_digests: Vec<CredentialStampedMaterialDigest>,
}

impl CredentialStampExecutionResult {
    pub(crate) fn to_value(&self) -> Value {
        Value::object(vec![
            ("stampId", Value::from(self.stamp_id.as_str())),
            ("output", self.output.to_value()),
            (
                "targetResolution",
                Value::from(self.target_resolution.as_str()),
            ),
            ("resolvedTarget", self.resolved_target.to_value()),
            ("bytesWritten", Value::from(self.bytes_written.as_str())),
            (
                "materialDigests",
                Value::Array(
                    self.material_digests
                        .iter()
                        .map(|digest| {
                            Value::object(vec![
                                ("projection", Value::from(digest.projection.as_str())),
                                ("reference", Value::from(digest.reference.as_str())),
                                ("sha256", Value::from(digest.sha256.as_str())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])
    }
}

fn require_schema(value: &Value) -> Result<(), String> {
    let schema = required_string(value, "schemaVersion")?;
    if schema != CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1 {
        return Err(format!(
            "unsupported credential provider execution schema {schema:?}"
        ));
    }
    Ok(())
}

fn parse_scoped_reference(value: &Value) -> Result<CredentialScopedReference, String> {
    let capabilities = value
        .get("capabilities")
        .map(|items| {
            items
                .as_array()
                .ok_or_else(|| "credential reference capabilities must be an array".to_string())?
                .iter()
                .map(|item| {
                    item.as_str().map(str::to_string).ok_or_else(|| {
                        "credential reference capabilities must contain strings".to_string()
                    })
                })
                .collect()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(CredentialScopedReference {
        provider_id: required_string(value, "providerId")?,
        reference: CredentialSecretReference::new(required_string(value, "reference")?)?,
        capabilities,
    })
}

fn parse_credential_file(value: &Value) -> Result<CredentialFile, String> {
    Ok(CredentialFile {
        projection: CredentialProjection::parse(&required_string(value, "projection")?)?,
        form: CredentialMaterialForm::parse(&required_string(value, "form")?)?,
        media_type: required_string(value, "mediaType")?,
        path: CredentialProtectedPath::new(required_string(value, "path")?)?,
        sha256: required_string(value, "sha256")?,
        size: required_i64(value, "size")?,
    })
}

fn push_optional(members: &mut Vec<(String, Value)>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        members.push((name.into(), Value::from(value)));
    }
}
