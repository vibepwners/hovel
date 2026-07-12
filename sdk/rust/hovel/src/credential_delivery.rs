//! Strongly typed provider credential-delivery discovery contracts.

use crate::base64;
use crate::json::Value;

pub const CREDENTIAL_DELIVERY_SCHEMA_V1: &str = "hovel.pki.credential-delivery/v1";
pub(crate) const CREDENTIAL_RPC_DESCRIBE_METHOD: &str = "credential.describe";

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

#[derive(Clone, Debug)]
pub enum CredentialStampPrecondition {
    None,
    Bytes(Vec<u8>),
    Sha256 { sha256: String, length: String },
}

impl CredentialStampPrecondition {
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct ResolvedCredentialMetadata {
    pub bundle_version: String,
    pub purpose: CredentialPurpose,
    pub consumer_type: CredentialConsumerType,
    pub profile_id: String,
    pub compatibility_target_id: String,
}

impl ResolvedCredentialMetadata {
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

#[derive(Clone, Debug)]
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
        Ok(Self {
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
        })
    }
}

impl CredentialStampPrecondition {
    fn from_value(value: &Value) -> Result<Self, String> {
        match required_string(value, "kind")?.as_str() {
            "none" => Ok(Self::None),
            "bytes" => Ok(Self::Bytes(required_bytes(value, "bytes")?)),
            "sha256" => Ok(Self::Sha256 {
                sha256: required_string(value, "sha256")?,
                length: required_string(value, "length")?,
            }),
            other => Err(format!(
                "unsupported credential stamp precondition {other:?}"
            )),
        }
    }
}

impl CredentialStampTarget {
    fn from_value(value: &Value) -> Result<Self, String> {
        match CredentialStampTargetKind::parse(&required_string(value, "kind")?)? {
            CredentialStampTargetKind::NamedSlot => {
                let target = required_value(value, "namedSlot")?;
                Ok(Self::NamedSlot {
                    name: required_string(target, "name")?,
                })
            }
            CredentialStampTargetKind::FileOffset => {
                let target = required_value(value, "fileOffset")?;
                Ok(Self::FileOffset {
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
                })
            }
            CredentialStampTargetKind::VirtualAddress => {
                let target = required_value(value, "virtualAddress")?;
                Ok(Self::VirtualAddress {
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
                })
            }
            CredentialStampTargetKind::Symbol => {
                let target = required_value(value, "symbol")?;
                Ok(Self::Symbol {
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
                })
            }
            CredentialStampTargetKind::Marker => {
                let target = required_value(value, "marker")?;
                Ok(Self::Marker {
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
                })
            }
            CredentialStampTargetKind::BytePattern => {
                let target = required_value(value, "bytePattern")?;
                Ok(Self::BytePattern {
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
                })
            }
            CredentialStampTargetKind::ProviderDefined => {
                let target = required_value(value, "providerDefined")?;
                Ok(Self::ProviderDefined {
                    provider_id: required_string(target, "providerId")?,
                    schema_version: required_string(target, "schemaVersion")?,
                    value: required_value(target, "value")?.clone(),
                })
            }
        }
    }
}

impl CredentialMaterialReference {
    fn from_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            projection: CredentialProjection::parse(&required_string(value, "projection")?)?,
            form: CredentialMaterialForm::parse(&required_string(value, "form")?)?,
            bundle_id: optional_string(value, "bundleId")?,
            generation_id: optional_string(value, "generationId")?,
            generation_ids: optional_string_array(value, "generationIds")?,
            trust_set_generation_id: optional_string(value, "trustSetGenerationId")?,
            crl_generation_ids: optional_string_array(value, "crlGenerationIds")?,
        })
    }
}

impl CredentialStampMaterial {
    fn from_value(value: &Value) -> Result<Self, String> {
        let projection = CredentialProjection::parse(&required_string(value, "projection")?)?;
        match projection {
            CredentialProjection::ProviderEncoding => {
                let material = required_value(value, "providerEncoding")?;
                Ok(Self::ProviderEncoding {
                    provider_id: required_string(material, "providerId")?,
                    schema_version: required_string(material, "schemaVersion")?,
                    form: CredentialMaterialForm::parse(&required_string(material, "form")?)?,
                    source: CredentialMaterialReference::from_value(required_value(
                        material, "source",
                    )?)?,
                })
            }
            CredentialProjection::LiteralReference => {
                let material = required_value(value, "literalReference")?;
                Ok(Self::LiteralReference {
                    reference: required_string(material, "reference")?,
                    sha256: required_string(material, "sha256")?,
                    form: CredentialMaterialForm::parse(&required_string(material, "form")?)?,
                })
            }
            _ => {
                let reference =
                    CredentialMaterialReference::from_value(required_value(value, "credential")?)?;
                if reference.projection != projection {
                    return Err(
                        "credential material projection does not match its reference".into(),
                    );
                }
                Ok(Self::Credential(reference))
            }
        }
    }
}

impl ResolvedCredentialMetadata {
    pub(crate) fn from_value(value: &Value) -> Result<Self, String> {
        Ok(Self {
            bundle_version: required_string(value, "bundleVersion")?,
            purpose: CredentialPurpose::parse(&required_string(value, "purpose")?)?,
            consumer_type: CredentialConsumerType::parse(&required_string(value, "consumerType")?)?,
            profile_id: required_string(value, "profileId")?,
            compatibility_target_id: required_string(value, "compatibilityTargetId")?,
        })
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
    Ok(number as i64)
}

fn required_u32(value: &Value, name: &str) -> Result<u32, String> {
    let number = required_i64(value, name)?;
    u32::try_from(number).map_err(|_| format!("credential contract field {name:?} exceeds uint32"))
}

pub(crate) fn required_bytes(value: &Value, name: &str) -> Result<Vec<u8>, String> {
    let encoded = required_string(value, name)?;
    let decoded = base64::decode(&encoded)?;
    if decoded.is_empty() {
        return Err(format!(
            "credential contract field {name:?} must not be empty"
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
