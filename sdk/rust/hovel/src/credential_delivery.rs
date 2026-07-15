//! Strongly typed provider credential-delivery discovery contracts.

use crate::base64;
use crate::json::Value;

pub const CREDENTIAL_DELIVERY_SCHEMA_V1: &str = "hovel.pki.credential-delivery/v1";
pub(crate) const CREDENTIAL_RPC_DESCRIBE_METHOD: &str = "credential.describe";
pub(crate) const MAXIMUM_CREDENTIAL_BINARY_BYTES: usize = 24 << 20;
pub(crate) const MAXIMUM_CREDENTIAL_EXECUTION_FILES: usize = 64;
pub(crate) const MAXIMUM_CREDENTIAL_REFERENCE_CAPABILITIES: usize = 64;
pub(crate) const MAXIMUM_CREDENTIAL_STAMP_DIGESTS: usize = 128;
pub(crate) const MAXIMUM_CREDENTIAL_STAMP_PRECONDITION_BYTES: usize = 1 << 20;
pub(crate) const MAXIMUM_CREDENTIAL_RECEIPT_BYTES: usize =
    MAXIMUM_CREDENTIAL_STAMP_PRECONDITION_BYTES;
const MAXIMUM_CREDENTIAL_PROVIDER_TARGET_BYTES: usize = 1 << 20;
pub(crate) const MAXIMUM_CREDENTIAL_ID_BYTES: usize = 256;
pub(crate) const MAXIMUM_CREDENTIAL_NAME_BYTES: usize = 512;
pub(crate) const MAXIMUM_CREDENTIAL_PATH_BYTES: usize = 4096;
pub(crate) const MAXIMUM_CREDENTIAL_ENCODING_BYTES: usize = 256;
const MAXIMUM_CREDENTIAL_REFERENCE_LIST: usize = 32;

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub enum $name { $($variant),+ }

        impl $name {
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $value),+ }
            }

            pub fn parse(value: &str) -> Result<Self, String> {
                match value { $($value => Ok(Self::$variant)),+, other => Err(format!(
                    "unsupported {} value {other:?}", stringify!($name)
                )) }
            }
        }
    };
}

string_enum!(CredentialDeliveryCapability {
    None => "none",
    Runtime => "runtime",
    Files => "files",
    StampStandard => "stamp-standard",
    StampAdvanced => "stamp-advanced",
});

string_enum!(CredentialPurpose {
    TlsServer => "tls-server",
    TlsClient => "tls-client",
    MtlsServer => "mtls-server",
    MtlsClient => "mtls-client",
    DualRoleMtls => "dual-role-mtls",
    CodeSigning => "code-signing",
    Custom => "custom",
});

string_enum!(CredentialEndpointRole {
    Server => "server",
    Client => "client",
    Dual => "dual",
    NotApplicable => "not-applicable",
});

string_enum!(CredentialConsumerType {
    MeshProvider => "mesh-provider",
    MeshListener => "mesh-listener",
    ListeningPost => "listening-post",
    MeshNode => "mesh-node",
    Implant => "implant",
    Stager => "stager",
    Payload => "payload",
    C2Service => "c2-service",
    Service => "service",
    External => "external",
});

string_enum!(CredentialProjection {
    Bundle => "bundle",
    CertificateDer => "certificate-der",
    PrivateKeyPkcs8 => "private-key-pkcs8",
    PublicKeySpki => "public-key-spki",
    SignerReference => "signer-reference",
    ChainDer => "chain-der",
    TrustDer => "trust-der",
    CrlDer => "crl-der",
    ProviderEncoding => "provider-encoding",
    LiteralReference => "literal-reference",
});

string_enum!(CredentialMaterialForm {
    Public => "public",
    PrivateReference => "private-reference",
    PrivateBytes => "private-bytes",
});

string_enum!(CredentialPrivateMaterialPolicy {
    Forbidden => "forbidden",
    Allowed => "allowed",
    Required => "required",
});

string_enum!(CredentialStampRemainderPolicy {
    Preserve => "preserve",
    ZeroFill => "zero-fill",
    RequireExact => "require-exact",
});

string_enum!(CredentialStampTargetKind {
    NamedSlot => "named-slot",
    FileOffset => "file-offset",
    VirtualAddress => "virtual-address",
    Symbol => "symbol",
    Marker => "marker",
    BytePattern => "byte-pattern",
    ProviderDefined => "provider-defined",
});

string_enum!(CredentialStampAddressSpace {
    File => "file",
    ElfVirtualAddress => "elf-virtual-address",
    PeRva => "pe-rva",
    MachOVmAddress => "macho-vm-address",
});

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialStampPrecondition {
    None,
    Bytes(Vec<u8>),
    Sha256 { sha256: String, length: String },
}

impl CredentialStampPrecondition {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::None => Ok(()),
            Self::Bytes(bytes)
                if (1..=MAXIMUM_CREDENTIAL_STAMP_PRECONDITION_BYTES).contains(&bytes.len()) =>
            {
                Ok(())
            }
            Self::Bytes(_) => Err("credential byte stamp precondition is invalid".to_string()),
            Self::Sha256 { sha256, length } => {
                validate_sha256(sha256, "credential stamp precondition")?;
                let length = parse_canonical_u64(length, "credential stamp precondition length")?;
                if length == 0 || length > MAXIMUM_CREDENTIAL_BINARY_BYTES as u64 {
                    return Err("credential stamp precondition hash length is invalid".to_string());
                }
                Ok(())
            }
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            Self::None => Value::object(vec![("kind", Value::from("none"))]),
            Self::Bytes(bytes) => Value::object(vec![
                ("kind", Value::from("bytes")),
                ("bytes", Value::from(base64::encode(bytes).as_str())),
            ]),
            Self::Sha256 { sha256, length } => Value::object(vec![
                ("kind", Value::from("sha256")),
                ("sha256", Value::from(sha256.as_str())),
                ("length", Value::from(length.as_str())),
            ]),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialStampTarget {
    NamedSlot {
        name: String,
    },
    FileOffset {
        offset: String,
        maximum_length: String,
        alignment: String,
        remainder_policy: CredentialStampRemainderPolicy,
        precondition: CredentialStampPrecondition,
    },
    VirtualAddress {
        address: String,
        address_space: CredentialStampAddressSpace,
        image_base: Option<String>,
        maximum_length: String,
        alignment: String,
        remainder_policy: CredentialStampRemainderPolicy,
        precondition: CredentialStampPrecondition,
    },
    Symbol {
        name: String,
        section: Option<String>,
        maximum_length: String,
        remainder_policy: CredentialStampRemainderPolicy,
        precondition: CredentialStampPrecondition,
    },
    Marker {
        marker: Vec<u8>,
        occurrence: u32,
        maximum_length: String,
        remainder_policy: CredentialStampRemainderPolicy,
        precondition: CredentialStampPrecondition,
    },
    BytePattern {
        pattern: Vec<u8>,
        mask: Vec<u8>,
        occurrence: u32,
        maximum_length: String,
        remainder_policy: CredentialStampRemainderPolicy,
        precondition: CredentialStampPrecondition,
    },
    ProviderDefined {
        provider_id: String,
        schema_version: String,
        value: Value,
    },
}

impl CredentialStampTarget {
    pub fn validate(&self) -> Result<(), String> {
        validate_credential_stamp_target(self)
    }

    pub fn to_value(&self) -> Value {
        match self {
            Self::NamedSlot { name } => tagged_target(
                CredentialStampTargetKind::NamedSlot,
                "namedSlot",
                Value::object(vec![("name", Value::from(name.as_str()))]),
            ),
            Self::FileOffset {
                offset,
                maximum_length,
                alignment,
                remainder_policy,
                precondition,
            } => tagged_target(
                CredentialStampTargetKind::FileOffset,
                "fileOffset",
                Value::object(vec![
                    ("offset", Value::from(offset.as_str())),
                    ("maximumLength", Value::from(maximum_length.as_str())),
                    ("alignment", Value::from(alignment.as_str())),
                    ("remainderPolicy", Value::from(remainder_policy.as_str())),
                    ("precondition", precondition.to_value()),
                ]),
            ),
            Self::VirtualAddress {
                address,
                address_space,
                image_base,
                maximum_length,
                alignment,
                remainder_policy,
                precondition,
            } => {
                let mut target = vec![
                    ("address".into(), Value::from(address.as_str())),
                    ("addressSpace".into(), Value::from(address_space.as_str())),
                    ("maximumLength".into(), Value::from(maximum_length.as_str())),
                    ("alignment".into(), Value::from(alignment.as_str())),
                    (
                        "remainderPolicy".into(),
                        Value::from(remainder_policy.as_str()),
                    ),
                    ("precondition".into(), precondition.to_value()),
                ];
                if let Some(image_base) = image_base {
                    target.push(("imageBase".into(), Value::from(image_base.as_str())));
                }
                tagged_target(
                    CredentialStampTargetKind::VirtualAddress,
                    "virtualAddress",
                    Value::Object(target),
                )
            }
            Self::Symbol {
                name,
                section,
                maximum_length,
                remainder_policy,
                precondition,
            } => {
                let mut target = vec![
                    ("name".into(), Value::from(name.as_str())),
                    ("maximumLength".into(), Value::from(maximum_length.as_str())),
                    (
                        "remainderPolicy".into(),
                        Value::from(remainder_policy.as_str()),
                    ),
                    ("precondition".into(), precondition.to_value()),
                ];
                if let Some(section) = section {
                    target.push(("section".into(), Value::from(section.as_str())));
                }
                tagged_target(
                    CredentialStampTargetKind::Symbol,
                    "symbol",
                    Value::Object(target),
                )
            }
            Self::Marker {
                marker,
                occurrence,
                maximum_length,
                remainder_policy,
                precondition,
            } => tagged_target(
                CredentialStampTargetKind::Marker,
                "marker",
                Value::object(vec![
                    ("marker", Value::from(base64::encode(marker).as_str())),
                    ("occurrence", Value::from(i64::from(*occurrence))),
                    ("maximumLength", Value::from(maximum_length.as_str())),
                    ("remainderPolicy", Value::from(remainder_policy.as_str())),
                    ("precondition", precondition.to_value()),
                ]),
            ),
            Self::BytePattern {
                pattern,
                mask,
                occurrence,
                maximum_length,
                remainder_policy,
                precondition,
            } => tagged_target(
                CredentialStampTargetKind::BytePattern,
                "bytePattern",
                Value::object(vec![
                    ("pattern", Value::from(base64::encode(pattern).as_str())),
                    ("mask", Value::from(base64::encode(mask).as_str())),
                    ("occurrence", Value::from(i64::from(*occurrence))),
                    ("maximumLength", Value::from(maximum_length.as_str())),
                    ("remainderPolicy", Value::from(remainder_policy.as_str())),
                    ("precondition", precondition.to_value()),
                ]),
            ),
            Self::ProviderDefined {
                provider_id,
                schema_version,
                value,
            } => tagged_target(
                CredentialStampTargetKind::ProviderDefined,
                "providerDefined",
                Value::object(vec![
                    ("providerId", Value::from(provider_id.as_str())),
                    ("schemaVersion", Value::from(schema_version.as_str())),
                    ("value", value.clone()),
                ]),
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialMaterialReference {
    pub projection: CredentialProjection,
    pub form: CredentialMaterialForm,
    pub bundle_id: Option<String>,
    pub generation_id: Option<String>,
    pub generation_ids: Vec<String>,
    pub trust_set_generation_id: Option<String>,
    pub crl_generation_ids: Vec<String>,
}

impl CredentialMaterialReference {
    pub fn validate(&self) -> Result<(), String> {
        validate_credential_material_reference(self)
    }

    pub fn to_value(&self) -> Value {
        let mut members = vec![
            ("projection".into(), Value::from(self.projection.as_str())),
            ("form".into(), Value::from(self.form.as_str())),
        ];
        push_optional_string(&mut members, "bundleId", self.bundle_id.as_deref());
        push_optional_string(&mut members, "generationId", self.generation_id.as_deref());
        push_array(
            &mut members,
            "generationIds",
            self.generation_ids
                .iter()
                .map(|value| Value::from(value.as_str())),
        );
        push_optional_string(
            &mut members,
            "trustSetGenerationId",
            self.trust_set_generation_id.as_deref(),
        );
        push_array(
            &mut members,
            "crlGenerationIds",
            self.crl_generation_ids
                .iter()
                .map(|value| Value::from(value.as_str())),
        );
        Value::Object(members)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CredentialStampMaterial {
    Credential(CredentialMaterialReference),
    ProviderEncoding {
        provider_id: String,
        schema_version: String,
        form: CredentialMaterialForm,
        source: CredentialMaterialReference,
    },
    LiteralReference {
        reference: String,
        sha256: String,
        form: CredentialMaterialForm,
    },
}

impl CredentialStampMaterial {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Credential(reference) => reference.validate(),
            Self::ProviderEncoding {
                provider_id,
                schema_version,
                source,
                ..
            } => {
                validate_canonical_text(
                    provider_id,
                    "credential provider-encoding provider id",
                    MAXIMUM_CREDENTIAL_ID_BYTES,
                )?;
                validate_canonical_text(
                    schema_version,
                    "credential provider-encoding schema version",
                    MAXIMUM_CREDENTIAL_ID_BYTES,
                )?;
                source.validate()
            }
            Self::LiteralReference {
                reference, sha256, ..
            } => {
                validate_canonical_text(
                    reference,
                    "credential literal material reference",
                    MAXIMUM_CREDENTIAL_ID_BYTES,
                )?;
                validate_sha256(sha256, "credential literal material")
            }
        }
    }

    pub(crate) fn projection_and_form(
        &self,
    ) -> Result<(CredentialProjection, CredentialMaterialForm), String> {
        self.validate()?;
        Ok(match self {
            Self::Credential(reference) => (reference.projection, reference.form),
            Self::ProviderEncoding { form, .. } => (CredentialProjection::ProviderEncoding, *form),
            Self::LiteralReference { form, .. } => (CredentialProjection::LiteralReference, *form),
        })
    }

    pub fn to_value(&self) -> Value {
        match self {
            Self::Credential(reference) => Value::object(vec![
                ("projection", Value::from(reference.projection.as_str())),
                ("credential", reference.to_value()),
            ]),
            Self::ProviderEncoding {
                provider_id,
                schema_version,
                form,
                source,
            } => Value::object(vec![
                (
                    "projection",
                    Value::from(CredentialProjection::ProviderEncoding.as_str()),
                ),
                (
                    "providerEncoding",
                    Value::object(vec![
                        ("providerId", Value::from(provider_id.as_str())),
                        ("schemaVersion", Value::from(schema_version.as_str())),
                        ("form", Value::from(form.as_str())),
                        ("source", source.to_value()),
                    ]),
                ),
            ]),
            Self::LiteralReference {
                reference,
                sha256,
                form,
            } => Value::object(vec![
                (
                    "projection",
                    Value::from(CredentialProjection::LiteralReference.as_str()),
                ),
                (
                    "literalReference",
                    Value::object(vec![
                        ("reference", Value::from(reference.as_str())),
                        ("sha256", Value::from(sha256.as_str())),
                        ("form", Value::from(form.as_str())),
                    ]),
                ),
            ]),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ResolvedCredentialMetadata {
    pub bundle_version: String,
    pub purpose: CredentialPurpose,
    pub consumer_type: CredentialConsumerType,
    pub profile_id: String,
    pub compatibility_target_id: String,
}

impl ResolvedCredentialMetadata {
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.bundle_version,
            "resolved credential bundle version",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_canonical_text(
            &self.profile_id,
            "resolved credential profile id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_canonical_text(
            &self.compatibility_target_id,
            "resolved credential compatibility target id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )
    }

    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("bundleVersion", Value::from(self.bundle_version.as_str())),
            ("purpose", Value::from(self.purpose.as_str())),
            ("consumerType", Value::from(self.consumer_type.as_str())),
            ("profileId", Value::from(self.profile_id.as_str())),
            (
                "compatibilityTargetId",
                Value::from(self.compatibility_target_id.as_str()),
            ),
        ])
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CredentialStampRequest {
    pub assignment_id: String,
    pub capability: CredentialDeliveryCapability,
    pub slot_name: String,
    pub target: CredentialStampTarget,
    pub material: CredentialStampMaterial,
    pub encoded_bytes: i64,
    pub credential: ResolvedCredentialMetadata,
}

impl CredentialStampRequest {
    pub fn validate(&self) -> Result<(), String> {
        validate_canonical_text(
            &self.assignment_id,
            "credential stamp assignment id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        validate_canonical_text(
            &self.slot_name,
            "credential stamp slot name",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        )?;
        self.target.validate()?;
        self.material.validate()?;
        if !(1..=MAXIMUM_CREDENTIAL_BINARY_BYTES as i64).contains(&self.encoded_bytes) {
            return Err("credential stamp encoded byte count is invalid".to_string());
        }
        self.credential.validate()
    }

    pub fn to_value(&self) -> Value {
        Value::object(vec![
            ("assignmentId", Value::from(self.assignment_id.as_str())),
            ("capability", Value::from(self.capability.as_str())),
            ("slotName", Value::from(self.slot_name.as_str())),
            ("target", self.target.to_value()),
            ("material", self.material.to_value()),
            ("encodedBytes", Value::from(self.encoded_bytes)),
            ("credential", self.credential.to_value()),
        ])
    }

    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        let request = Self {
            assignment_id: required_string(value, "assignmentId")?,
            capability: CredentialDeliveryCapability::parse(&required_string(
                value,
                "capability",
            )?)?,
            slot_name: required_string(value, "slotName")?,
            target: CredentialStampTarget::from_value(required_value(value, "target")?)?,
            material: CredentialStampMaterial::from_value(required_value(value, "material")?)?,
            encoded_bytes: required_i64(value, "encodedBytes")?,
            credential: ResolvedCredentialMetadata::from_value(required_value(
                value,
                "credential",
            )?)?,
        };
        request.validate()?;
        Ok(request)
    }
}

impl CredentialStampPrecondition {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        let kind = required_string(value, "kind")?;
        let allowed = match kind.as_str() {
            "none" => &[][..],
            "bytes" => &["bytes"][..],
            "sha256" => &["sha256", "length"][..],
            other => {
                return Err(format!(
                    "unsupported credential stamp precondition {other:?}"
                ))
            }
        };
        reject_inactive_fields(
            value,
            allowed,
            &["bytes", "sha256", "length"],
            "credential stamp precondition",
        )?;
        let precondition = match kind.as_str() {
            "none" => Self::None,
            "bytes" => Self::Bytes(required_bytes(value, "bytes")?),
            "sha256" => Self::Sha256 {
                sha256: required_string(value, "sha256")?,
                length: required_string(value, "length")?,
            },
            _ => unreachable!("precondition kind was checked above"),
        };
        precondition.validate()?;
        Ok(precondition)
    }
}

impl CredentialStampTarget {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        let kind = CredentialStampTargetKind::parse(&required_string(value, "kind")?)?;
        let active = match kind {
            CredentialStampTargetKind::NamedSlot => "namedSlot",
            CredentialStampTargetKind::FileOffset => "fileOffset",
            CredentialStampTargetKind::VirtualAddress => "virtualAddress",
            CredentialStampTargetKind::Symbol => "symbol",
            CredentialStampTargetKind::Marker => "marker",
            CredentialStampTargetKind::BytePattern => "bytePattern",
            CredentialStampTargetKind::ProviderDefined => "providerDefined",
        };
        reject_inactive_fields(
            value,
            &[active],
            &[
                "namedSlot",
                "fileOffset",
                "virtualAddress",
                "symbol",
                "marker",
                "bytePattern",
                "providerDefined",
            ],
            "credential stamp target",
        )?;
        let target = match kind {
            CredentialStampTargetKind::NamedSlot => {
                let target = required_value(value, "namedSlot")?;
                Self::NamedSlot {
                    name: required_string(target, "name")?,
                }
            }
            CredentialStampTargetKind::FileOffset => {
                let target = required_value(value, "fileOffset")?;
                Self::FileOffset {
                    offset: required_string(target, "offset")?,
                    maximum_length: required_string(target, "maximumLength")?,
                    alignment: required_string(target, "alignment")?,
                    remainder_policy: CredentialStampRemainderPolicy::parse(&required_string(
                        target,
                        "remainderPolicy",
                    )?)?,
                    precondition: CredentialStampPrecondition::from_value(required_value(
                        target,
                        "precondition",
                    )?)?,
                }
            }
            CredentialStampTargetKind::VirtualAddress => {
                let target = required_value(value, "virtualAddress")?;
                Self::VirtualAddress {
                    address: required_string(target, "address")?,
                    address_space: CredentialStampAddressSpace::parse(&required_string(
                        target,
                        "addressSpace",
                    )?)?,
                    image_base: optional_string(target, "imageBase")?,
                    maximum_length: required_string(target, "maximumLength")?,
                    alignment: required_string(target, "alignment")?,
                    remainder_policy: CredentialStampRemainderPolicy::parse(&required_string(
                        target,
                        "remainderPolicy",
                    )?)?,
                    precondition: CredentialStampPrecondition::from_value(required_value(
                        target,
                        "precondition",
                    )?)?,
                }
            }
            CredentialStampTargetKind::Symbol => {
                let target = required_value(value, "symbol")?;
                Self::Symbol {
                    name: required_string(target, "name")?,
                    section: optional_string(target, "section")?,
                    maximum_length: required_string(target, "maximumLength")?,
                    remainder_policy: CredentialStampRemainderPolicy::parse(&required_string(
                        target,
                        "remainderPolicy",
                    )?)?,
                    precondition: CredentialStampPrecondition::from_value(required_value(
                        target,
                        "precondition",
                    )?)?,
                }
            }
            CredentialStampTargetKind::Marker => {
                let target = required_value(value, "marker")?;
                Self::Marker {
                    marker: required_bytes(target, "marker")?,
                    occurrence: required_u32(target, "occurrence")?,
                    maximum_length: required_string(target, "maximumLength")?,
                    remainder_policy: CredentialStampRemainderPolicy::parse(&required_string(
                        target,
                        "remainderPolicy",
                    )?)?,
                    precondition: CredentialStampPrecondition::from_value(required_value(
                        target,
                        "precondition",
                    )?)?,
                }
            }
            CredentialStampTargetKind::BytePattern => {
                let target = required_value(value, "bytePattern")?;
                Self::BytePattern {
                    pattern: required_bytes(target, "pattern")?,
                    mask: required_bytes(target, "mask")?,
                    occurrence: required_u32(target, "occurrence")?,
                    maximum_length: required_string(target, "maximumLength")?,
                    remainder_policy: CredentialStampRemainderPolicy::parse(&required_string(
                        target,
                        "remainderPolicy",
                    )?)?,
                    precondition: CredentialStampPrecondition::from_value(required_value(
                        target,
                        "precondition",
                    )?)?,
                }
            }
            CredentialStampTargetKind::ProviderDefined => {
                let target = required_value(value, "providerDefined")?;
                Self::ProviderDefined {
                    provider_id: required_string(target, "providerId")?,
                    schema_version: required_string(target, "schemaVersion")?,
                    value: required_value(target, "value")?.clone(),
                }
            }
        };
        target.validate()?;
        Ok(target)
    }
}

impl CredentialMaterialReference {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        let projection = CredentialProjection::parse(&required_string(value, "projection")?)?;
        let active = match projection {
            CredentialProjection::Bundle => "bundleId",
            CredentialProjection::CertificateDer
            | CredentialProjection::PrivateKeyPkcs8
            | CredentialProjection::PublicKeySpki
            | CredentialProjection::SignerReference => "generationId",
            CredentialProjection::ChainDer => "generationIds",
            CredentialProjection::TrustDer => "trustSetGenerationId",
            CredentialProjection::CrlDer => "crlGenerationIds",
            CredentialProjection::ProviderEncoding | CredentialProjection::LiteralReference => {
                return Err(
                    "credential material reference cannot contain provider or literal material"
                        .to_string(),
                )
            }
        };
        reject_inactive_fields(
            value,
            &[active],
            &[
                "bundleId",
                "generationId",
                "generationIds",
                "trustSetGenerationId",
                "crlGenerationIds",
            ],
            "credential material reference",
        )?;
        let reference = Self {
            projection,
            form: CredentialMaterialForm::parse(&required_string(value, "form")?)?,
            bundle_id: optional_string(value, "bundleId")?,
            generation_id: optional_string(value, "generationId")?,
            generation_ids: optional_string_array(value, "generationIds")?,
            trust_set_generation_id: optional_string(value, "trustSetGenerationId")?,
            crl_generation_ids: optional_string_array(value, "crlGenerationIds")?,
        };
        reference.validate()?;
        Ok(reference)
    }
}

impl CredentialStampMaterial {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        let projection = CredentialProjection::parse(&required_string(value, "projection")?)?;
        let active = match projection {
            CredentialProjection::ProviderEncoding => "providerEncoding",
            CredentialProjection::LiteralReference => "literalReference",
            _ => "credential",
        };
        reject_inactive_fields(
            value,
            &[active],
            &["credential", "providerEncoding", "literalReference"],
            "credential stamp material",
        )?;
        let material = match projection {
            CredentialProjection::ProviderEncoding => {
                let material = required_value(value, "providerEncoding")?;
                Self::ProviderEncoding {
                    provider_id: required_string(material, "providerId")?,
                    schema_version: required_string(material, "schemaVersion")?,
                    form: CredentialMaterialForm::parse(&required_string(material, "form")?)?,
                    source: CredentialMaterialReference::from_value(required_value(
                        material, "source",
                    )?)?,
                }
            }
            CredentialProjection::LiteralReference => {
                let material = required_value(value, "literalReference")?;
                Self::LiteralReference {
                    reference: required_string(material, "reference")?,
                    sha256: required_string(material, "sha256")?,
                    form: CredentialMaterialForm::parse(&required_string(material, "form")?)?,
                }
            }
            _ => {
                let reference =
                    CredentialMaterialReference::from_value(required_value(value, "credential")?)?;
                if reference.projection != projection {
                    return Err(
                        "credential material projection does not match its reference".into(),
                    );
                }
                Self::Credential(reference)
            }
        };
        material.validate()?;
        Ok(material)
    }
}

impl ResolvedCredentialMetadata {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        let metadata = Self {
            bundle_version: required_string(value, "bundleVersion")?,
            purpose: CredentialPurpose::parse(&required_string(value, "purpose")?)?,
            consumer_type: CredentialConsumerType::parse(&required_string(value, "consumerType")?)?,
            profile_id: required_string(value, "profileId")?,
            compatibility_target_id: required_string(value, "compatibilityTargetId")?,
        };
        metadata.validate()?;
        Ok(metadata)
    }
}

#[derive(Clone, Debug)]
pub struct CredentialSlot {
    pub name: String,
    pub purpose: CredentialPurpose,
    pub endpoint_role: CredentialEndpointRole,
    pub consumer_type: CredentialConsumerType,
    pub accepted_bundle_versions: Vec<String>,
    pub accepted_profiles: Vec<String>,
    pub accepted_compatibility_targets: Vec<String>,
    pub accepted_projections: Vec<CredentialProjection>,
    pub accepted_material_forms: Vec<CredentialMaterialForm>,
    pub maximum_encoded_bytes: i64,
    pub remainder_policy: CredentialStampRemainderPolicy,
    pub private_material: CredentialPrivateMaterialPolicy,
}

impl CredentialSlot {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("name".into(), Value::from(self.name.as_str())),
            ("purpose".into(), Value::from(self.purpose.as_str())),
            (
                "endpointRole".into(),
                Value::from(self.endpoint_role.as_str()),
            ),
            (
                "consumerType".into(),
                Value::from(self.consumer_type.as_str()),
            ),
            (
                "acceptedBundleVersions".into(),
                strings(&self.accepted_bundle_versions),
            ),
            ("acceptedProfiles".into(), strings(&self.accepted_profiles)),
            (
                "acceptedCompatibilityTargets".into(),
                strings(&self.accepted_compatibility_targets),
            ),
            (
                "acceptedProjections".into(),
                enum_values(&self.accepted_projections, |value| value.as_str()),
            ),
            (
                "acceptedMaterialForms".into(),
                enum_values(&self.accepted_material_forms, |value| value.as_str()),
            ),
            (
                "maximumEncodedBytes".into(),
                Value::from(self.maximum_encoded_bytes),
            ),
            (
                "remainderPolicy".into(),
                Value::from(self.remainder_policy.as_str()),
            ),
            (
                "privateMaterial".into(),
                Value::from(self.private_material.as_str()),
            ),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct CredentialProviderTargetSchema {
    pub provider_id: String,
    pub schema_version: String,
    pub json_schema: Value,
}

impl CredentialProviderTargetSchema {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("providerId".into(), Value::from(self.provider_id.as_str())),
            (
                "schemaVersion".into(),
                Value::from(self.schema_version.as_str()),
            ),
            ("jsonSchema".into(), self.json_schema.clone()),
        ])
    }
}

#[derive(Clone, Debug)]
pub struct CredentialProviderEncodingSchema {
    pub provider_id: String,
    pub schema_version: String,
    pub accepted_source_projections: Vec<CredentialProjection>,
    pub accepted_source_forms: Vec<CredentialMaterialForm>,
    pub output_forms: Vec<CredentialMaterialForm>,
}

impl CredentialProviderEncodingSchema {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("providerId".into(), Value::from(self.provider_id.as_str())),
            (
                "schemaVersion".into(),
                Value::from(self.schema_version.as_str()),
            ),
            (
                "acceptedSourceProjections".into(),
                enum_values(&self.accepted_source_projections, |value| value.as_str()),
            ),
            (
                "acceptedSourceForms".into(),
                enum_values(&self.accepted_source_forms, |value| value.as_str()),
            ),
            (
                "outputForms".into(),
                enum_values(&self.output_forms, |value| value.as_str()),
            ),
        ])
    }
}

#[derive(Clone, Debug, Default)]
pub struct CredentialDeliveryDescriptor {
    pub capabilities: Vec<CredentialDeliveryCapability>,
    pub slots: Vec<CredentialSlot>,
    pub stamp_target_kinds: Vec<CredentialStampTargetKind>,
    pub address_spaces: Vec<CredentialStampAddressSpace>,
    pub provider_target_schemas: Vec<CredentialProviderTargetSchema>,
    pub provider_encoding_schemas: Vec<CredentialProviderEncodingSchema>,
}

impl CredentialDeliveryDescriptor {
    pub(crate) fn to_value(&self) -> Value {
        let mut members = vec![
            (
                "schemaVersion".into(),
                Value::from(CREDENTIAL_DELIVERY_SCHEMA_V1),
            ),
            (
                "deliveryCapabilities".into(),
                enum_values(&self.capabilities, |value| value.as_str()),
            ),
        ];
        push_array(
            &mut members,
            "credentialSlots",
            self.slots.iter().map(CredentialSlot::to_value),
        );
        push_array(
            &mut members,
            "stampTargetKinds",
            self.stamp_target_kinds
                .iter()
                .map(|value| Value::from(value.as_str())),
        );
        push_array(
            &mut members,
            "addressSpaces",
            self.address_spaces
                .iter()
                .map(|value| Value::from(value.as_str())),
        );
        push_array(
            &mut members,
            "providerTargetSchemas",
            self.provider_target_schemas
                .iter()
                .map(CredentialProviderTargetSchema::to_value),
        );
        push_array(
            &mut members,
            "providerEncodingSchemas",
            self.provider_encoding_schemas
                .iter()
                .map(CredentialProviderEncodingSchema::to_value),
        );
        Value::Object(members)
    }
}

fn validate_credential_stamp_target(target: &CredentialStampTarget) -> Result<(), String> {
    match target {
        CredentialStampTarget::NamedSlot { name } => validate_canonical_text(
            name,
            "credential stamp slot name",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        ),
        CredentialStampTarget::FileOffset {
            offset,
            maximum_length,
            alignment,
            remainder_policy,
            precondition,
        } => validate_credential_position_target(
            offset,
            None,
            maximum_length,
            alignment,
            *remainder_policy,
            precondition,
            CredentialStampAddressSpace::File,
        ),
        CredentialStampTarget::VirtualAddress {
            address,
            address_space,
            image_base,
            maximum_length,
            alignment,
            remainder_policy,
            precondition,
        } => {
            if *address_space == CredentialStampAddressSpace::File {
                return Err(
                    "credential virtual-address target cannot use file address space".to_string(),
                );
            }
            validate_credential_position_target(
                address,
                image_base.as_deref(),
                maximum_length,
                alignment,
                *remainder_policy,
                precondition,
                *address_space,
            )
        }
        CredentialStampTarget::Symbol {
            name,
            section,
            maximum_length,
            remainder_policy,
            precondition,
        } => {
            validate_canonical_text(
                name,
                "credential stamp symbol name",
                MAXIMUM_CREDENTIAL_NAME_BYTES,
            )?;
            if let Some(section) = section {
                validate_canonical_text(
                    section,
                    "credential stamp symbol section",
                    MAXIMUM_CREDENTIAL_NAME_BYTES,
                )?;
            }
            validate_credential_bounded_target(maximum_length, *remainder_policy, precondition)?;
            Ok(())
        }
        CredentialStampTarget::Marker {
            marker,
            maximum_length,
            remainder_policy,
            precondition,
            ..
        } => {
            if !(1..=MAXIMUM_CREDENTIAL_STAMP_PRECONDITION_BYTES).contains(&marker.len()) {
                return Err("credential marker stamp target is invalid".to_string());
            }
            validate_credential_bounded_target(maximum_length, *remainder_policy, precondition)?;
            Ok(())
        }
        CredentialStampTarget::BytePattern {
            pattern,
            mask,
            maximum_length,
            remainder_policy,
            precondition,
            ..
        } => {
            if pattern.is_empty()
                || pattern.len() != mask.len()
                || pattern.len() > MAXIMUM_CREDENTIAL_STAMP_PRECONDITION_BYTES
                || mask.iter().all(|byte| *byte == 0)
            {
                return Err("credential byte-pattern stamp target is invalid".to_string());
            }
            validate_credential_bounded_target(maximum_length, *remainder_policy, precondition)?;
            Ok(())
        }
        CredentialStampTarget::ProviderDefined {
            provider_id,
            schema_version,
            value,
        } => {
            validate_canonical_text(
                provider_id,
                "credential provider-defined target provider id",
                MAXIMUM_CREDENTIAL_ID_BYTES,
            )?;
            validate_canonical_text(
                schema_version,
                "credential provider-defined target schema version",
                MAXIMUM_CREDENTIAL_ID_BYTES,
            )?;
            if matches!(value, Value::Null)
                || value.to_string().len() > MAXIMUM_CREDENTIAL_PROVIDER_TARGET_BYTES
            {
                return Err("credential provider-defined target value is invalid".to_string());
            }
            Ok(())
        }
    }
}

fn validate_credential_position_target(
    position: &str,
    image_base: Option<&str>,
    maximum_length: &str,
    alignment: &str,
    remainder_policy: CredentialStampRemainderPolicy,
    precondition: &CredentialStampPrecondition,
    address_space: CredentialStampAddressSpace,
) -> Result<(), String> {
    let position = parse_canonical_u64(position, "credential stamp target position")?;
    let image_base = image_base
        .map(|value| parse_canonical_u64(value, "credential stamp target image base"))
        .transpose()?;
    let alignment = parse_canonical_u64(alignment, "credential stamp target alignment")?;
    if alignment == 0 || !alignment.is_power_of_two() {
        return Err("credential stamp target alignment must be a nonzero power of two".to_string());
    }
    if position % alignment != 0 {
        return Err("credential stamp target position does not satisfy its alignment".to_string());
    }
    let maximum =
        validate_credential_bounded_target(maximum_length, remainder_policy, precondition)?;
    position.checked_add(maximum).ok_or_else(|| {
        "credential stamp target position and maximum length overflow uint64".to_string()
    })?;
    if let Some(image_base) = image_base {
        match address_space {
            CredentialStampAddressSpace::PeRva => {
                image_base
                    .checked_add(position)
                    .and_then(|value| value.checked_add(maximum))
                    .ok_or_else(|| {
                        "credential stamp image base, address, and length overflow uint64"
                            .to_string()
                    })?;
            }
            CredentialStampAddressSpace::ElfVirtualAddress
            | CredentialStampAddressSpace::MachOVmAddress
                if position < image_base =>
            {
                return Err("credential virtual address precedes its image base".to_string());
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_credential_bounded_target(
    maximum_length: &str,
    _remainder_policy: CredentialStampRemainderPolicy,
    precondition: &CredentialStampPrecondition,
) -> Result<u64, String> {
    let maximum = parse_canonical_u64(maximum_length, "credential stamp target maximum length")?;
    if maximum == 0 || maximum > MAXIMUM_CREDENTIAL_BINARY_BYTES as u64 {
        return Err("credential stamp target maximum length is invalid".to_string());
    }
    precondition.validate()?;
    match precondition {
        CredentialStampPrecondition::Bytes(bytes) if bytes.len() as u64 > maximum => {
            return Err("credential stamp precondition exceeds target maximum length".to_string());
        }
        CredentialStampPrecondition::Sha256 { length, .. }
            if parse_canonical_u64(length, "credential stamp precondition length")? > maximum =>
        {
            return Err(
                "credential stamp hash precondition exceeds target maximum length".to_string(),
            );
        }
        _ => {}
    }
    Ok(maximum)
}

fn validate_credential_material_reference(
    reference: &CredentialMaterialReference,
) -> Result<(), String> {
    validate_projection_form(reference.projection, reference.form)?;
    let variant_count = usize::from(
        reference
            .bundle_id
            .as_deref()
            .is_some_and(|value| !value.is_empty()),
    ) + usize::from(
        reference
            .generation_id
            .as_deref()
            .is_some_and(|value| !value.is_empty()),
    ) + usize::from(!reference.generation_ids.is_empty())
        + usize::from(
            reference
                .trust_set_generation_id
                .as_deref()
                .is_some_and(|value| !value.is_empty()),
        )
        + usize::from(!reference.crl_generation_ids.is_empty());
    if variant_count != 1 {
        return Err("credential material must contain exactly one tagged reference".to_string());
    }
    match reference.projection {
        CredentialProjection::Bundle => validate_canonical_text(
            reference.bundle_id.as_deref().unwrap_or_default(),
            "credential bundle id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        ),
        CredentialProjection::CertificateDer
        | CredentialProjection::PrivateKeyPkcs8
        | CredentialProjection::PublicKeySpki
        | CredentialProjection::SignerReference => validate_canonical_text(
            reference.generation_id.as_deref().unwrap_or_default(),
            "credential generation id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        ),
        CredentialProjection::ChainDer => {
            validate_reference_list(&reference.generation_ids, "credential chain generation ids")
        }
        CredentialProjection::TrustDer => validate_canonical_text(
            reference
                .trust_set_generation_id
                .as_deref()
                .unwrap_or_default(),
            "credential trust-set generation id",
            MAXIMUM_CREDENTIAL_ID_BYTES,
        ),
        CredentialProjection::CrlDer => validate_reference_list(
            &reference.crl_generation_ids,
            "credential CRL generation ids",
        ),
        CredentialProjection::ProviderEncoding | CredentialProjection::LiteralReference => Err(
            "credential material reference cannot contain provider or literal material".to_string(),
        ),
    }
}

pub(crate) fn validate_projection_form(
    projection: CredentialProjection,
    form: CredentialMaterialForm,
) -> Result<(), String> {
    match projection {
        CredentialProjection::CertificateDer
        | CredentialProjection::PublicKeySpki
        | CredentialProjection::ChainDer
        | CredentialProjection::TrustDer
        | CredentialProjection::CrlDer
            if form != CredentialMaterialForm::Public =>
        {
            Err("public credential projection requires public material".to_string())
        }
        CredentialProjection::PrivateKeyPkcs8 if form != CredentialMaterialForm::PrivateBytes => {
            Err("private-key projection requires private bytes".to_string())
        }
        CredentialProjection::SignerReference
            if form != CredentialMaterialForm::PrivateReference =>
        {
            Err("signer projection requires a private reference".to_string())
        }
        _ => Ok(()),
    }
}

pub(crate) fn validate_canonical_text(
    value: &str,
    label: &str,
    maximum_bytes: usize,
) -> Result<(), String> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.len() > maximum_bytes
        || value.chars().any(char::is_control)
    {
        return Err(format!("{label} is invalid or noncanonical"));
    }
    Ok(())
}

pub(crate) fn validate_sha256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || value.bytes().any(|byte| !byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(format!("{label} sha256 is invalid or noncanonical"));
    }
    Ok(())
}

pub(crate) fn parse_canonical_u64(value: &str, label: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{label} is not a canonical uint64"))?;
    if parsed.to_string() != value {
        return Err(format!("{label} is not a canonical uint64"));
    }
    Ok(parsed)
}

fn validate_reference_list(values: &[String], label: &str) -> Result<(), String> {
    if !(1..=MAXIMUM_CREDENTIAL_REFERENCE_LIST).contains(&values.len()) {
        return Err(format!("{label} is empty or exceeds limits"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        validate_canonical_text(value, label, MAXIMUM_CREDENTIAL_ID_BYTES)?;
        if !seen.insert(value) {
            return Err(format!("{label} contains a duplicate"));
        }
    }
    Ok(())
}

fn reject_inactive_fields(
    value: &Value,
    allowed: &[&str],
    variants: &[&str],
    label: &str,
) -> Result<(), String> {
    for variant in variants {
        if value.get(variant).is_some() && !allowed.contains(variant) {
            return Err(format!(
                "{label} contains inactive variant field {variant:?}"
            ));
        }
    }
    Ok(())
}

fn strings(values: &[String]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::from(value.as_str()))
            .collect(),
    )
}

fn enum_values<T>(values: &[T], as_str: impl Fn(&T) -> &'static str) -> Value {
    Value::Array(
        values
            .iter()
            .map(|value| Value::from(as_str(value)))
            .collect(),
    )
}

fn push_array(members: &mut Vec<(String, Value)>, name: &str, values: impl Iterator<Item = Value>) {
    let values: Vec<Value> = values.collect();
    if !values.is_empty() {
        members.push((name.into(), Value::Array(values)));
    }
}

fn tagged_target(kind: CredentialStampTargetKind, field: &str, target: Value) -> Value {
    Value::object(vec![("kind", Value::from(kind.as_str())), (field, target)])
}

fn push_optional_string(members: &mut Vec<(String, Value)>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        members.push((name.into(), Value::from(value)));
    }
}

pub(crate) fn required_value<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value
        .get(name)
        .ok_or_else(|| format!("credential contract field {name:?} is required"))
}

pub(crate) fn required_string(value: &Value, name: &str) -> Result<String, String> {
    required_value(value, name)?
        .as_str()
        .filter(|field| !field.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("credential contract field {name:?} must be a non-empty string"))
}

pub(crate) fn optional_string(value: &Value, name: &str) -> Result<Option<String>, String> {
    match value.get(name) {
        None => Ok(None),
        Some(field) => field
            .as_str()
            .map(|field| Some(field.to_string()))
            .ok_or_else(|| format!("credential contract field {name:?} must be a string")),
    }
}

pub(crate) fn required_i64(value: &Value, name: &str) -> Result<i64, String> {
    let number = required_value(value, name)?
        .as_f64()
        .ok_or_else(|| format!("credential contract field {name:?} must be an integer"))?;
    if !number.is_finite() || number.fract() != 0.0 || number < 0.0 || number > i64::MAX as f64 {
        return Err(format!(
            "credential contract field {name:?} must be a non-negative integer"
        ));
    }
    let number = number as i64;
    if matches!(name, "encodedBytes" | "maximumEncodedBytes" | "size")
        && !(1..=MAXIMUM_CREDENTIAL_BINARY_BYTES as i64).contains(&number)
    {
        return Err(format!(
            "credential contract field {name:?} must be between 1 and {MAXIMUM_CREDENTIAL_BINARY_BYTES} bytes"
        ));
    }
    Ok(number)
}

fn required_u32(value: &Value, name: &str) -> Result<u32, String> {
    let number = required_i64(value, name)?;
    u32::try_from(number).map_err(|_| format!("credential contract field {name:?} exceeds uint32"))
}

pub(crate) fn required_bytes(value: &Value, name: &str) -> Result<Vec<u8>, String> {
    let encoded = required_string(value, name)?;
    let decoded = base64::decode(&encoded)?;
    if decoded.is_empty() || decoded.len() > MAXIMUM_CREDENTIAL_BINARY_BYTES {
        return Err(format!(
            "credential contract field {name:?} must be non-empty and bounded"
        ));
    }
    Ok(decoded)
}

fn optional_string_array(value: &Value, name: &str) -> Result<Vec<String>, String> {
    let Some(field) = value.get(name) else {
        return Ok(Vec::new());
    };
    let values = field
        .as_array()
        .ok_or_else(|| format!("credential contract field {name:?} must be an array"))?;
    values
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("credential contract field {name:?} must contain strings"))
        })
        .collect()
}
