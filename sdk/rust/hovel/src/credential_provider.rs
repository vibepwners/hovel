//! Optional, secret-aware credential provider execution contracts.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use crate::base64;
use crate::credential_delivery::{
    optional_string, parse_canonical_u64, required_bytes, required_i64, required_string,
    required_value, validate_canonical_text, validate_projection_form, validate_sha256,
    CredentialMaterialForm, CredentialProjection, CredentialStampRequest, CredentialStampTarget,
    ResolvedCredentialMetadata, MAXIMUM_CREDENTIAL_BINARY_BYTES, MAXIMUM_CREDENTIAL_ENCODING_BYTES,
    MAXIMUM_CREDENTIAL_EXECUTION_FILES, MAXIMUM_CREDENTIAL_ID_BYTES, MAXIMUM_CREDENTIAL_NAME_BYTES,
    MAXIMUM_CREDENTIAL_PATH_BYTES, MAXIMUM_CREDENTIAL_RECEIPT_BYTES,
    MAXIMUM_CREDENTIAL_REFERENCE_CAPABILITIES, MAXIMUM_CREDENTIAL_STAMP_DIGESTS,
};
use crate::json::Value;
use crate::sha256;

pub const CREDENTIAL_PROVIDER_EXECUTION_SCHEMA_V1: &str = "hovel.pki.provider-execution/v1";
pub const CREDENTIAL_ENCODING_RAW: &str = "raw";
pub const CREDENTIAL_RPC_RUNTIME_METHOD: &str = "credential.runtime";
pub const CREDENTIAL_RPC_FILES_METHOD: &str = "credential.files";
pub const CREDENTIAL_RPC_ENCODE_METHOD: &str = "credential.encode";
pub const CREDENTIAL_RPC_STAMP_METHOD: &str = "credential.stamp";

#[derive(Clone, Eq, PartialEq)]
pub struct CredentialBytes(Vec<u8>);

impl CredentialBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if !(1..=MAXIMUM_CREDENTIAL_BINARY_BYTES).contains(&bytes.len()) {
            return Err("credential bytes must be non-empty and bounded".to_string());
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
        validate_canonical_text(
            &value,
            "credential secret reference",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
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
        validate_canonical_text(
            &value,
            "credential protected path",
            MAXIMUM_CREDENTIAL_PATH_BYTES,
        )?;
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
    pub fn validate(&self) -> Result<(), String> {
        for (label, value) in [
            ("operation id", self.operation_id.as_deref()),
            ("run id", self.run_id.as_deref()),
            ("chain id", self.chain_id.as_deref()),
            ("throw id", self.throw_id.as_deref()),
            ("target", self.target.as_deref()),
            ("listener id", self.listener_id.as_deref()),
            ("node id", self.node_id.as_deref()),
        ] {
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                validate_canonical_text(
                    value,
                    &format!("credential operation {label}"),
                    MAXIMUM_CREDENTIAL_ID_BYTES,
                )?;
            }
        }
        Ok(())
    }

    fn from_value(value: &Value) -> Result<Self, String> {
        let scope = Self {
            operation_id: optional_string(value, "operationId")?,
            run_id: optional_string(value, "runId")?,
            chain_id: optional_string(value, "chainId")?,
            throw_id: optional_string(value, "throwId")?,
            target: optional_string(value, "target")?,
            listener_id: optional_string(value, "listenerId")?,
            node_id: optional_string(value, "nodeId")?,
        };
        scope.validate()?;
        Ok(scope)
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
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.module_id,
            "credential provider module id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_canonical_text(
            &self.provider_id,
            "credential provider provider id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_canonical_text(
            &self.provider_version,
            "credential provider provider version",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_sha256(&self.descriptor_sha256, "credential provider descriptor")
    }

    fn from_value(value: &Value) -> Result<Self, String> {
        let target = Self {
            module_id: required_string(value, "moduleId")?,
            provider_id: required_string(value, "providerId")?,
            provider_version: required_string(value, "providerVersion")?,
            descriptor_sha256: required_string(value, "descriptorSha256")?,
        };
        target.validate()?;
        Ok(target)
    }
}

#[derive(Clone, Debug)]
pub struct CredentialScopedReference {
    pub provider_id: String,
    pub reference: CredentialSecretReference,
    pub capabilities: Vec<String>,
}

impl CredentialScopedReference {
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.provider_id,
            "credential reference provider id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_canonical_text(
            self.reference.expose(),
            "credential secret reference",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        if self.capabilities.len() > MAXIMUM_CREDENTIAL_REFERENCE_CAPABILITIES {
            return Err("credential reference capabilities exceed limits".to_string());
        }
        let mut seen = BTreeSet::new();
        for capability in &self.capabilities {
            validate_canonical_text(
                capability,
                "credential reference capability",
                MAXIMUM_CREDENTIAL_ID_BYTES,
            )?;
            if !seen.insert(capability) {
                return Err("credential reference capabilities contain a duplicate".to_string());
            }
        }
        Ok(())
    }
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
        let material = Self {
            projection,
            encoding: encoding.into(),
            sha256: sha256.into(),
            form,
            value,
        };
        material.validate()?;
        Ok(material)
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_projection_form(self.projection, self.form)?;
        validate_canonical_text(
            &self.encoding,
            "credential material encoding",
            MAXIMUM_CREDENTIAL_ENCODING_BYTES,
        )?;
        validate_sha256(&self.sha256, "credential material")?;
        match (&self.form, &self.value) {
            (
                CredentialMaterialForm::Public | CredentialMaterialForm::PrivateBytes,
                CredentialMaterialValue::Bytes(bytes),
            ) => validate_digest(bytes.as_slice(), &self.sha256, "credential material"),
            (
                CredentialMaterialForm::PrivateReference,
                CredentialMaterialValue::Reference(reference),
            ) => reference.validate(),
            _ => Err("resolved credential material form does not match its value".to_string()),
        }
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
    pub fn validate(&self) -> Result<(), String> {
        validate_execution_envelope(&self.request_id)?;
        self.provider.validate()?;
        validate_delivery_inputs(
            &self.assignment_id,
            &self.slot_name,
            &self.credential,
            &self.scope,
        )?;
        self.material.validate()
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        require_schema(value)?;
        let request = Self {
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
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Debug)]
pub struct CredentialFile {
    pub projection: CredentialProjection,
    pub form: CredentialMaterialForm,
    pub encoding: String,
    pub media_type: String,
    pub path: CredentialProtectedPath,
    pub sha256: String,
    pub size: i64,
}

impl CredentialFile {
    pub fn validate(&self) -> Result<(), String> {
        validate_projection_form(self.projection, self.form)?;
        validate_canonical_text(
            &self.encoding,
            "credential file encoding",
            MAXIMUM_CREDENTIAL_ENCODING_BYTES,
        )?;
        validate_canonical_text(
            &self.media_type,
            "credential file media type",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_canonical_text(
            self.path.expose(),
            "credential protected path",
            MAXIMUM_CREDENTIAL_PATH_BYTES,
        )?;
        validate_sha256(&self.sha256, "credential file")?;
        if !(1..=MAXIMUM_CREDENTIAL_BINARY_BYTES as i64).contains(&self.size) {
            return Err("credential file size is invalid".to_string());
        }
        Ok(())
    }
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
    pub fn validate(&self) -> Result<(), String> {
        validate_execution_envelope(&self.request_id)?;
        self.provider.validate()?;
        validate_delivery_inputs(
            &self.assignment_id,
            &self.slot_name,
            &self.credential,
            &self.scope,
        )?;
        if !(1..=MAXIMUM_CREDENTIAL_EXECUTION_FILES).contains(&self.files.len()) {
            return Err("credential files request is empty or exceeds limits".to_string());
        }
        let mut paths = BTreeSet::new();
        for file in &self.files {
            file.validate()?;
            if !paths.insert(file.path.expose()) {
                return Err("credential files request contains a duplicate path".to_string());
            }
        }
        Ok(())
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        require_schema(value)?;
        let files = required_value(value, "files")?
            .as_array()
            .ok_or_else(|| "credential files must be an array".to_string())?
            .iter()
            .map(parse_credential_file)
            .collect::<Result<Vec<_>, _>>()?;
        let request = Self {
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
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Clone, Debug)]
pub struct CredentialDeliveryReceipt {
    pub request_id: String,
    pub provider_reference: Option<String>,
    pub receipt_sha256: Option<String>,
}

impl CredentialDeliveryReceipt {
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.request_id,
            "credential delivery receipt request id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        if let Some(reference) = self.provider_reference.as_deref() {
            validate_canonical_text(
                reference,
                "credential provider reference",
                MAXIMUM_CREDENTIAL_ID_BYTES,
            )?;
        }
        if let Some(digest) = self.receipt_sha256.as_deref() {
            validate_sha256(digest, "credential delivery receipt")?;
        }
        Ok(())
    }

    pub fn validate_for(&self, request_id: &str) -> Result<(), String> {
        self.validate()?;
        if self.request_id != request_id {
            return Err(
                "credential delivery receipt request id does not match its request".to_string(),
            );
        }
        Ok(())
    }

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
    pub fn validate(&self) -> Result<(), String> {
        validate_execution_envelope(&self.request_id)?;
        self.provider.validate()?;
        validate_canonical_text(
            &self.provider_id,
            "credential encoding provider id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        if self.provider_id != self.provider.provider_id {
            return Err(
                "credential encoding provider does not match its invocation target".to_string(),
            );
        }
        validate_canonical_text(
            &self.provider_schema,
            "credential provider schema",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        if !(1..=MAXIMUM_CREDENTIAL_BINARY_BYTES as i64).contains(&self.maximum_encoded_bytes) {
            return Err("credential encoding output bound is invalid".to_string());
        }
        self.source.validate()?;
        self.scope.validate()
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        require_schema(value)?;
        let request = Self {
            request_id: required_string(value, "requestId")?,
            provider: CredentialProviderTarget::from_value(required_value(value, "provider")?)?,
            provider_id: required_string(value, "providerId")?,
            provider_schema: required_string(value, "providerSchema")?,
            output_form: CredentialMaterialForm::parse(&required_string(value, "outputForm")?)?,
            maximum_encoded_bytes: required_i64(value, "maximumEncodedBytes")?,
            source: ResolvedCredentialMaterial::from_value(required_value(value, "source")?)?,
            scope: CredentialOperationScope::from_value(required_value(value, "scope")?)?,
        };
        request.validate()?;
        Ok(request)
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
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.request_id,
            "credential encoding result request id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_canonical_text(
            &self.encoding,
            "credential encoding",
            MAXIMUM_CREDENTIAL_ENCODING_BYTES,
        )?;
        validate_digest(self.data.as_slice(), &self.sha256, "encoded credential")
    }

    pub fn validate_for(&self, request: &CredentialEncodingRequest) -> Result<(), String> {
        request.validate()?;
        self.validate_for_parts(
            &request.request_id,
            request.output_form,
            request.maximum_encoded_bytes,
        )
    }

    pub(crate) fn validate_for_parts(
        &self,
        request_id: &str,
        output_form: CredentialMaterialForm,
        maximum_encoded_bytes: i64,
    ) -> Result<(), String> {
        self.validate()?;
        if self.request_id != request_id
            || self.form != output_form
            || self.data.as_slice().len() > maximum_encoded_bytes as usize
        {
            return Err("credential encoding result does not match its request".to_string());
        }
        Ok(())
    }

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
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.artifact_id,
            "credential stamp input id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_sha256(&self.sha256, "credential stamp input")?;
        validate_canonical_text(
            &self.encoding,
            "credential artifact encoding",
            MAXIMUM_CREDENTIAL_ENCODING_BYTES,
        )?;
        match &self.content {
            CredentialArtifactContent::Data(data) => {
                validate_digest(data.as_slice(), &self.sha256, "credential stamp input")
            }
            CredentialArtifactContent::Path(path) => validate_canonical_text(
                path.expose(),
                "credential protected path",
                MAXIMUM_CREDENTIAL_PATH_BYTES,
            ),
        }
    }

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
        let artifact = Self {
            artifact_id: required_string(value, "id")?,
            sha256: required_string(value, "sha256")?,
            encoding: required_string(value, "encoding")?,
            content,
        };
        artifact.validate()?;
        Ok(artifact)
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
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.name,
            "credential artifact output name",
            MAXIMUM_CREDENTIAL_NAME_BYTES,
        )?;
        validate_canonical_text(
            &self.encoding,
            "credential artifact encoding",
            MAXIMUM_CREDENTIAL_ENCODING_BYTES,
        )?;
        match &self.content {
            CredentialArtifactContent::Data(data) => {
                if data.as_slice().is_empty()
                    || data.as_slice().len() > MAXIMUM_CREDENTIAL_BINARY_BYTES
                {
                    return Err("credential artifact output data is invalid".to_string());
                }
                Ok(())
            }
            CredentialArtifactContent::Path(path) => validate_canonical_text(
                path.expose(),
                "credential protected path",
                MAXIMUM_CREDENTIAL_PATH_BYTES,
            ),
        }
    }

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

impl CredentialDeploymentOutput {
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.reference,
            "credential deployment reference",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        if !(1..=MAXIMUM_CREDENTIAL_RECEIPT_BYTES).contains(&self.receipt.as_slice().len()) {
            return Err("credential deployment receipt is empty or exceeds limits".to_string());
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub enum CredentialStampOutput {
    Artifact(CredentialArtifactOutput),
    Deployment(CredentialDeploymentOutput),
}

impl CredentialStampOutput {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Artifact(output) => output.validate(),
            Self::Deployment(output) => output.validate(),
        }
    }

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

impl CredentialStampedMaterialDigest {
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.reference,
            "credential stamped material reference",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_sha256(&self.sha256, "credential stamped material")
    }
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
    pub fn validate(&self) -> Result<(), String> {
        self.provider.validate()?;
        validate_canonical_text(
            &self.stamp_id,
            "credential stamp id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        self.request.validate()?;
        self.input.validate()?;
        self.material.validate()?;
        let (projection, form) = self.request.material.projection_and_form()?;
        if self.material.projection != projection || self.material.form() != form {
            return Err(
                "resolved credential material does not match the stamp request".to_string(),
            );
        }
        validate_stamped_material_digests(&self.expected_digests)?;
        self.scope.validate()
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        require_schema(value)?;
        let request = Self {
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
        };
        request.validate()?;
        Ok(request)
    }
}

fn parse_stamped_material_digest(value: &Value) -> Result<CredentialStampedMaterialDigest, String> {
    let digest = CredentialStampedMaterialDigest {
        projection: CredentialProjection::parse(&required_string(value, "projection")?)?,
        reference: required_string(value, "reference")?,
        sha256: required_string(value, "sha256")?,
    };
    digest.validate()?;
    Ok(digest)
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
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.stamp_id,
            "credential stamp result id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        self.output.validate()?;
        self.resolved_target.validate()?;
        let bytes_written =
            parse_canonical_u64(&self.bytes_written, "credential stamp result bytes written")?;
        if bytes_written == 0 || bytes_written > MAXIMUM_CREDENTIAL_BINARY_BYTES as u64 {
            return Err("credential stamp result bytes written is invalid".to_string());
        }
        validate_stamped_material_digests(&self.material_digests)
    }

    pub fn validate_for(&self, request: &CredentialStampExecutionRequest) -> Result<(), String> {
        request.validate()?;
        self.validate_for_parts(
            &request.stamp_id,
            &request.request.target,
            request.request.encoded_bytes,
            &request.expected_digests,
        )
    }

    pub(crate) fn validate_for_parts(
        &self,
        stamp_id: &str,
        target: &CredentialStampTarget,
        encoded_bytes: i64,
        expected_digests: &[CredentialStampedMaterialDigest],
    ) -> Result<(), String> {
        self.validate()?;
        if self.stamp_id != stamp_id {
            return Err("credential stamp result id does not match its request".to_string());
        }
        let bytes_written =
            parse_canonical_u64(&self.bytes_written, "credential stamp result bytes written")?;
        if bytes_written != encoded_bytes as u64 {
            return Err(
                "credential stamp result byte count does not match its request".to_string(),
            );
        }
        if self.target_resolution == CredentialStampTargetResolution::Unchanged
            && &self.resolved_target != target
        {
            return Err("unchanged credential stamp target does not match its request".to_string());
        }
        if stamped_material_digest_map(&self.material_digests)
            != stamped_material_digest_map(expected_digests)
        {
            return Err(
                "credential stamp result material digests do not match its request".to_string(),
            );
        }
        Ok(())
    }

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

fn validate_execution_envelope(request_id: &str) -> Result<(), String> {
    validate_canonical_text(
        request_id,
        "credential provider request id",
        MAXIMUM_CREDENTIAL_ID_BYTES,
    )
}

fn validate_delivery_inputs(
    assignment_id: &str,
    slot_name: &str,
    credential: &ResolvedCredentialMetadata,
    scope: &CredentialOperationScope,
) -> Result<(), String> {
    validate_canonical_text(
        assignment_id,
        "credential assignment id",
        MAXIMUM_CREDENTIAL_ID_BYTES,
    )?;
    validate_canonical_text(
        slot_name,
        "credential slot name",
        MAXIMUM_CREDENTIAL_ID_BYTES,
    )?;
    credential.validate()?;
    scope.validate()
}

fn validate_digest(data: &[u8], value: &str, label: &str) -> Result<(), String> {
    validate_sha256(value, label)?;
    if sha256::hex_digest(data) != value {
        return Err(format!("{label} sha256 does not match its bytes"));
    }
    Ok(())
}

fn validate_stamped_material_digests(
    digests: &[CredentialStampedMaterialDigest],
) -> Result<(), String> {
    if !(1..=MAXIMUM_CREDENTIAL_STAMP_DIGESTS).contains(&digests.len()) {
        return Err("credential stamped material digests are empty or exceed limits".to_string());
    }
    let mut seen = BTreeSet::new();
    for digest in digests {
        digest.validate()?;
        let key = format!("{}\0{}", digest.projection.as_str(), digest.reference);
        if !seen.insert(key) {
            return Err("credential stamped material digests contain a duplicate".to_string());
        }
    }
    Ok(())
}

fn stamped_material_digest_map(
    digests: &[CredentialStampedMaterialDigest],
) -> BTreeMap<String, String> {
    digests
        .iter()
        .map(|digest| {
            (
                format!("{}\0{}", digest.projection.as_str(), digest.reference),
                digest.sha256.clone(),
            )
        })
        .collect()
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
    let reference = CredentialScopedReference {
        provider_id: required_string(value, "providerId")?,
        reference: CredentialSecretReference::new(required_string(value, "reference")?)?,
        capabilities,
    };
    reference.validate()?;
    Ok(reference)
}

fn parse_credential_file(value: &Value) -> Result<CredentialFile, String> {
    let file = CredentialFile {
        projection: CredentialProjection::parse(&required_string(value, "projection")?)?,
        form: CredentialMaterialForm::parse(&required_string(value, "form")?)?,
        encoding: required_string(value, "encoding")?,
        media_type: required_string(value, "mediaType")?,
        path: CredentialProtectedPath::new(required_string(value, "path")?)?,
        sha256: required_string(value, "sha256")?,
        size: required_i64(value, "size")?,
    };
    file.validate()?;
    Ok(file)
}

fn push_optional(members: &mut Vec<(String, Value)>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        members.push((name.into(), Value::from(value)));
    }
}
