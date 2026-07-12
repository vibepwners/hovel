#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

os.environ.setdefault("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")


REGISTER_RE = re.compile(
    r"register(?:Privileged)?(?:NoStore)?Unary\[[^\n]+\]\(mux,\s*"
    r"(?P<method>\"[^\"]+\"|[A-Za-z_]\w*)\s*,"
)
STRING_CONST_RE = re.compile(
    r'^\s*(?P<name>[A-Za-z_]\w*)\s*=\s*"(?P<value>[^"]+)"',
    re.MULTILINE,
)
SERVICE_PREFIX = "/hovel.daemon.v1.DaemonService/"
MAX_SEQUENCE_NUMBER = 2**63 - 1
CONTRACT_ARGS = tuple(sys.argv[1:])


@pytest.fixture(scope="class")
def daemon_rpc_contract(request: pytest.FixtureRequest) -> None:
    if len(CONTRACT_ARGS) != 3:
        pytest.fail(
            "usage: daemon_rpc_openapi_test.py OPENAPI_JSON DAEMONRPC_GO DOC_HTML"
        )

    contract_class = request.cls
    assert contract_class is not None
    openapi_path, daemonrpc_path, doc_path = map(Path, CONTRACT_ARGS)
    with openapi_path.open("r", encoding="utf-8") as handle:
        contract_class.openapi = json.load(handle)
    contract_class.daemonrpc_source = daemonrpc_path.read_text(encoding="utf-8")
    contract_class.doc_html = doc_path.read_text(encoding="utf-8")


@pytest.mark.usefixtures("daemon_rpc_contract")
class TestDaemonRPCOpenAPI:

    def registered_methods(self) -> list[str]:
        string_constants = {
            match.group("name"): match.group("value")
            for match in STRING_CONST_RE.finditer(self.daemonrpc_source)
        }
        methods = []
        for match in REGISTER_RE.finditer(self.daemonrpc_source):
            token = match.group("method")
            if token.startswith('"'):
                methods.append(json.loads(token))
                continue
            if token not in string_constants:
                raise AssertionError(f"unresolved RPC method constant: {token}")
            methods.append(string_constants[token])
        return methods

    def test_openapi_paths_match_registered_daemon_rpc_methods(self) -> None:
        registered = self.registered_methods()
        assert len(registered) > 10

        paths = self.openapi.get("paths", {})
        documented = sorted(path.removeprefix(SERVICE_PREFIX) for path in paths)
        assert documented == sorted(registered)

        for method in registered:
            path = SERVICE_PREFIX + method
            operation = paths[path]["post"]
            assert operation["operationId"] == method
            request_body = self.resolve_ref(operation["requestBody"])
            assert "application/json" in request_body["content"]
            assert "200" in operation["responses"]
            success = self.resolve_ref(operation["responses"]["200"])
            assert "application/json" in success["content"]

    def test_contract_declares_stability_and_standard_shape(self) -> None:
        assert self.openapi["openapi"] == "3.1.0"
        assert self.openapi["info"]["title"] == "Hovel Daemon RPC"
        assert self.openapi["x-hovel-stability"] == "stable"
        assert self.openapi["x-hovel-service"] == "hovel.daemon.v1.DaemonService"

    def test_every_local_reference_resolves(self) -> None:
        pending: list[object] = [self.openapi]
        while pending:
            node = pending.pop()
            if isinstance(node, dict):
                ref = node.get("$ref")
                if ref is not None:
                    self.resolve_ref(node)
                pending.extend(node.values())
            elif isinstance(node, list):
                pending.extend(node)

    def test_human_docs_link_contract_and_name_every_method(self) -> None:
        assert "reference/daemon-rpc.openapi.json" in self.doc_html
        for method in self.registered_methods():
            assert method in self.doc_html

    def test_mesh_listener_contract_is_stable_and_does_not_echo_config(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        listener = schemas["MeshListener"]
        assert "id" in listener["required"]
        assert "config" not in listener["properties"]

        start_request = schemas["MeshListenerStartInnerRequest"]
        assert "listenerId" in start_request["required"]
        assert start_request["properties"]["config"]["writeOnly"]

        for response_name in (
            "MeshListenerStartResponse",
            "MeshListenerStopResponse",
        ):
            response = schemas[response_name]
            assert response["properties"]["listener"] == {
                "$ref": "#/components/schemas/MeshListener"
            }
            assert "operationId" in response["required"]

        operation = schemas["MeshOperation"]["properties"]
        assert "listenerId" in operation
        assert operation["action"]["enum"] == ["start", "stop"]

    def test_mesh_contract_is_closed_where_core_owns_the_shape(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        for schema_name in (
            "AgentContext",
            "AgentEntity",
            "AgentHint",
            "MeshDescribeRequest",
            "MeshDescribeInnerRequest",
            "MeshTopologyRequest",
            "MeshTopologyInnerRequest",
            "MeshBeaconListRequest",
            "MeshBeaconInnerRequest",
            "MeshTaskRunRequest",
            "MeshStreamOpenRequest",
            "MeshOperationListRequest",
            "MeshOperationListResponse",
            "MeshOperation",
            "MeshDescriptor",
            "MeshTopology",
            "MeshNode",
            "MeshLink",
            "MeshRoute",
            "MeshTaskSpec",
            "MeshTrigger",
            "MeshBeacon",
            "MeshBeaconListResponse",
            "MeshTaskRequest",
            "MeshTaskResult",
            "MeshEvent",
            "MeshStreamRequest",
            "MeshBridgeOpenRequest",
            "MeshBridgeOpenResponse",
            "MeshBridgeCloseRequest",
            "MeshBridgeCloseResponse",
            "MeshListener",
            "MeshListenerSpec",
            "MeshListenerListInnerRequest",
            "MeshListenerStartInnerRequest",
            "MeshListenerStopInnerRequest",
            "MeshListenerListRequest",
            "MeshListenerStartRequest",
            "MeshListenerStopRequest",
        ):
            assert not schemas[schema_name]["additionalProperties"]

        assert schemas["MeshOperation"]["properties"]["kind"]["enum"] == [
            "task",
            "stream",
            "bridge",
            "listener",
        ]
        assert schemas["MeshOperation"]["properties"]["state"]["enum"] == [
            "started",
            "active",
            "succeeded",
            "failed",
            "closed",
        ]
        assert "id" in schemas["MeshNode"]["required"]
        assert set(schemas["MeshLink"]["required"]) == {"id", "source", "target"}
        assert "nodes" in schemas["MeshRoute"]["required"]
        assert "kind" in schemas["MeshTaskRequest"]["required"]
        assert schemas["MeshDescriptor"]["properties"]["credentialDelivery"] == {
            "$ref": "#/components/schemas/PKICredentialDeliveryDescriptor"
        }
        assert schemas["MeshTaskResult"]["properties"]["agentHints"][
            "items"
        ] == {"$ref": "#/components/schemas/AgentHint"}

    def test_mesh_bridge_capability_is_required_and_never_cacheable(self) -> None:
        bridge = self.openapi["components"]["schemas"]["MeshBridgeOpenResponse"]
        assert "capability" in bridge["required"]
        assert bridge["properties"]["capability"]["pattern"] == (
            "^[A-Za-z0-9_-]{43}$"
        )

        success_ref = self.openapi["paths"][
            SERVICE_PREFIX + "OpenMeshBridge"
        ]["post"]["responses"]["200"]
        assert success_ref == {
            "$ref": "#/components/responses/MeshBridgeOpenResponse"
        }
        success = self.resolve_ref(success_ref)
        assert success["headers"]["Cache-Control"]["schema"] == {
            "const": "no-store"
        }

    def test_mesh_credential_selection_is_typed_secret_free_and_approved(
        self,
    ) -> None:
        schemas = self.openapi["components"]["schemas"]
        for schema_name in (
            "MeshListenerStartRequest",
            "MeshTaskRunRequest",
            "MeshStreamOpenRequest",
            "MeshBridgeOpenRequest",
        ):
            schema = schemas[schema_name]
            assert schema["dependentRequired"] == {
                "credentials": ["credentialContext"],
                "credentialContext": ["credentials"],
            }
            assert schema["properties"]["credentials"] == {
                "$ref": "#/components/schemas/MeshCredentialSelections"
            }
            assert schema["properties"]["credentialContext"] == {
                "$ref": "#/components/schemas/MeshCredentialRequestContext"
            }

        selection = schemas["MeshCredentialSelection"]
        assert not selection["additionalProperties"]
        assert set(selection["required"]) == {
            "requestId",
            "assignmentId",
            "slotName",
            "capability",
            "material",
        }
        assert selection["properties"]["capability"]["const"] == "runtime"
        serialized = json.dumps(
            {
                "selections": schemas["MeshCredentialSelections"],
                "selection": selection,
                "material": schemas["MeshCredentialMaterialSelection"],
            }
        )
        for secret_field in (
            '"data"',
            '"path"',
            '"reference"',
            '"provider"',
            '"receipt"',
        ):
            assert secret_field not in serialized

        valid = {
            "moduleId": "mesh-provider@1.2.3",
            "request": {"listenerId": "listener-edge"},
            "credentials": [
                {
                    "requestId": "credential-request-1",
                    "assignmentId": "assignment-edge",
                    "slotName": "tls-server",
                    "capability": "runtime",
                    "material": {
                        "projection": "certificate-der",
                        "form": "public",
                    },
                }
            ],
            "credentialContext": {
                "actorId": "operator-1",
                "operationId": "operation-1",
                "correlationId": "request-1",
                "approveCredentialUse": True,
            },
        }
        self.validate_component("MeshListenerStartRequest", valid)
        for candidate in (
            {key: value for key, value in valid.items() if key != "credentialContext"},
            {key: value for key, value in valid.items() if key != "credentials"},
            {**valid, "credentials": []},
            {
                **valid,
                "credentialContext": {
                    **valid["credentialContext"],
                    "approveCredentialUse": False,
                },
            },
            {
                **valid,
                "credentials": [
                    {**valid["credentials"][0], "data": "secret"}
                ],
            },
            {
                **valid,
                "credentials": [
                    {
                        **valid["credentials"][0],
                        "material": {"projection": "bundle", "form": "public"},
                    }
                ],
            },
        ):
            with pytest.raises(ValidationError):
                self.validate_component("MeshListenerStartRequest", candidate)

    def test_mesh_operation_separates_provider_status_from_lifecycle_state(
        self,
    ) -> None:
        schemas = self.openapi["components"]["schemas"]
        operation = schemas["MeshOperation"]
        properties = operation["properties"]
        assert properties["state"]["enum"] == [
            "started",
            "active",
            "succeeded",
            "failed",
            "closed",
        ]
        assert "providerStatus" not in operation["required"]
        provider_status = properties["providerStatus"]
        assert provider_status["type"] == "string"
        assert provider_status["minLength"] == 1
        assert provider_status["maxLength"] == 256
        assert "Provider-defined" in provider_status["description"]
        assert (
            schemas["MeshOperationListRequest"]["properties"]["providerStatus"]
            == provider_status
        )

    def test_pki_assignment_mutations_are_retry_safe_and_generation_pinned(
        self,
    ) -> None:
        schemas = self.openapi["components"]["schemas"]
        mutation_requests = (
            "PKIBindAssignmentInnerRequest",
            "PKIStageAssignmentInnerRequest",
            "PKIActivateAssignmentInnerRequest",
            "PKIUnbindAssignmentInnerRequest",
            "PKICreateTrustSetInnerRequest",
            "PKIStageTrustSetInnerRequest",
            "PKIActivateTrustSetInnerRequest",
        )
        for schema_name in mutation_requests:
            schema = schemas[schema_name]
            assert not schema["additionalProperties"]
            assert schema["properties"]["idempotencyKey"] == {
                "type": "string",
                "maxLength": 256,
            }

        for schema_name in (
            "PKIStageAssignmentInnerRequest",
            "PKIActivateAssignmentInnerRequest",
            "PKIUnbindAssignmentInnerRequest",
            "PKIStageTrustSetInnerRequest",
            "PKIActivateTrustSetInnerRequest",
        ):
            assert "expectedRevision" in schemas[schema_name]["required"]
            assert schemas[schema_name]["properties"]["expectedRevision"] == {
                "type": "integer",
                "format": "int64",
                "minimum": 1,
                "maximum": MAX_SEQUENCE_NUMBER,
            }

        assignment = schemas["PKIAssignment"]["properties"]
        assert "activeTrustGenerationId" in assignment
        assert "stagedTrustGenerationId" in assignment
        crls = schemas["PKIStageTrustSetInnerRequest"]["properties"][
            "crlGenerationIds"
        ]
        assert "fresh" in crls["description"]
        assert "issuer" in crls["description"]
        assert "scoped to the authenticated actor" in self.doc_html

        for schema_name in (
            "PKIRenewCertificateInnerRequest",
            "PKIRotateCertificateInnerRequest",
        ):
            schema = schemas[schema_name]
            assert not schema["additionalProperties"]
            assert "sourceGenerationId" in schema["required"]
            assert "idempotencyKey" in schema["properties"]
        lifecycle = schemas["PKICertificateLifecycleResult"]
        assert "keyReused" in lifecycle["required"]
        assert lifecycle["properties"]["kind"]["enum"] == [
            "certificate-renewal",
            "certificate-rotation",
        ]

        reason = schemas["PKIRevocationReason"]
        assert reason["enum"] == [
            "unspecified",
            "key-compromise",
            "ca-compromise",
            "affiliation-changed",
            "superseded",
            "cessation-of-operation",
            "certificate-hold",
            "privilege-withdrawn",
            "aa-compromise",
        ]
        revoke = schemas["PKIRevokeCertificateInnerRequest"]
        assert not revoke["additionalProperties"]
        assert set(revoke["required"]) == {"generationId", "reason"}
        assert revoke["properties"]["reason"] == {
            "$ref": "#/components/schemas/PKIRevocationReason"
        }
        revocation = schemas["PKIRevocation"]
        assert not revocation["additionalProperties"]
        assert revocation["properties"]["previousState"]["enum"] == [
            "active",
            "superseded",
            "expired",
        ]
        result = schemas["PKICertificateRevocationResult"]
        assert set(result["required"]) == {
            "revocation",
            "generation",
            "affectedAssignments",
        }
        assert result["properties"]["affectedAssignments"]["items"] == {
            "$ref": "#/components/schemas/PKIAssignment"
        }

    def test_pki_credential_execution_contract_is_typed_and_secret_free(
        self,
    ) -> None:
        schemas = self.openapi["components"]["schemas"]
        for schema_name in (
            "PKICredentialExecutionRequest",
            "PKICredentialExecutionListResponse",
            "PKICredentialExecution",
            "PKICredentialExecutionPlan",
            "PKICredentialProviderTarget",
            "PKICredentialOperationScope",
            "PKIResolvedCredentialMetadata",
            "PKICredentialExecutionMaterial",
            "PKICredentialExecutionResult",
            "PKICredentialExecutionOutput",
        ):
            assert not schemas[schema_name]["additionalProperties"]

        execution = schemas["PKICredentialExecution"]
        assert execution["properties"]["status"]["enum"] == [
            "pending",
            "succeeded",
            "failed",
        ]
        assert len(execution["oneOf"]) == 3
        plan = schemas["PKICredentialExecutionPlan"]
        assert plan["properties"]["kind"]["enum"] == [
            "runtime",
            "files",
            "provider-encoding",
        ]
        material_properties = schemas["PKICredentialExecutionMaterial"][
            "properties"
        ]
        for secret_field in ("data", "path", "reference"):
            assert secret_field not in material_properties
        result_properties = schemas["PKICredentialExecutionResult"]["properties"]
        assert "providerReferenceSha256" in result_properties
        assert "providerReference" not in result_properties
        assert "receipt" not in result_properties
        assert "never credential bytes" in self.doc_html

    def test_pki_credential_stamp_contract_is_closed_and_discriminated(
        self,
    ) -> None:
        schemas = self.openapi["components"]["schemas"]
        for schema_name in (
            "PKICredentialStamp",
            "PKICredentialStampPlan",
            "PKICredentialDeliveryDescriptor",
            "PKICredentialSlot",
            "PKICredentialStampContractRequest",
            "PKICredentialStampPrecondition",
            "PKICredentialStampMaterial",
            "PKICredentialMaterialReference",
            "PKICredentialProviderEncodingMaterial",
            "PKICredentialLiteralMaterialReference",
            "PKIStampArtifactReference",
            "PKIStampedMaterialDigest",
            "PKICredentialStampResult",
            "PKIStampDestination",
            "PKIStampDeploymentReference",
        ):
            assert not schemas[schema_name]["additionalProperties"]

        stamp = schemas["PKICredentialStamp"]
        assert len(stamp["oneOf"]) == 4
        assert stamp["properties"]["plan"] == {
            "$ref": "#/components/schemas/PKICredentialStampPlan"
        }
        assert stamp["properties"]["result"] == {
            "$ref": "#/components/schemas/PKICredentialStampResult"
        }

        target = schemas["PKICredentialStampTarget"]
        assert target["discriminator"] == {"propertyName": "kind"}
        assert len(target["oneOf"]) == 7
        assert schemas["PKICredentialStampTargetKind"]["enum"] == [
            "named-slot",
            "file-offset",
            "virtual-address",
            "symbol",
            "marker",
            "byte-pattern",
            "provider-defined",
        ]
        assert len(schemas["PKICredentialStampMaterial"]["oneOf"]) == 3
        assert len(schemas["PKIStampDestination"]["oneOf"]) == 2

        serialized = json.dumps(
            {
                name: schemas[name]
                for name in (
                    "PKICredentialStampPlan",
                    "PKICredentialStampResult",
                    "PKIStampedMaterialDigest",
                    "PKIStampDestination",
                )
            }
        )
        for secret_field in (
            '"data"',
            '"path"',
            '"privateKey"',
            '"providerReference"',
            '"receipt"',
        ):
            assert secret_field not in serialized

    def test_pki_credential_descriptor_schema_rejects_domain_invalid_shapes(
        self,
    ) -> None:
        slot = {
            "name": "control-plane-mtls",
            "purpose": "mtls-server",
            "endpointRole": "server",
            "consumerType": "mesh-listener",
            "acceptedBundleVersions": ["hovel.pki.bundle/v1"],
            "acceptedProfiles": ["mtls-server"],
            "acceptedCompatibilityTargets": ["portable-x509"],
            "acceptedProjections": ["bundle"],
            "acceptedMaterialForms": ["private-bytes"],
            "maximumEncodedBytes": 16384,
            "remainderPolicy": "preserve",
            "privateMaterial": "allowed",
        }
        valid = {
            "schemaVersion": "hovel.pki.credential-delivery/v1",
            "credentialSlots": [slot],
            "deliveryCapabilities": ["stamp-standard"],
            "stampTargetKinds": ["named-slot"],
        }
        self.validate_component("PKICredentialDeliveryDescriptor", valid)
        self.validate_component(
            "PKICredentialDeliveryDescriptor",
            {
                "schemaVersion": "hovel.pki.credential-delivery/v1",
                "deliveryCapabilities": ["none"],
            },
        )

        invalid = (
            {**valid, "deliveryCapabilities": ["none", "stamp-standard"]},
            {**valid, "deliveryCapabilities": ["none"]},
            {
                "schemaVersion": "hovel.pki.credential-delivery/v1",
                "deliveryCapabilities": ["runtime"],
            },
            {**valid, "stampTargetKinds": []},
            {**valid, "deliveryCapabilities": ["runtime"]},
            {
                **valid,
                "deliveryCapabilities": ["stamp-standard"],
                "stampTargetKinds": ["file-offset"],
                "addressSpaces": ["file"],
            },
            {
                **valid,
                "deliveryCapabilities": ["stamp-advanced"],
                "stampTargetKinds": ["file-offset"],
            },
            {
                **valid,
                "deliveryCapabilities": ["stamp-advanced"],
                "stampTargetKinds": ["named-slot"],
                "addressSpaces": ["file"],
            },
            {
                **valid,
                "deliveryCapabilities": ["stamp-advanced"],
                "stampTargetKinds": ["provider-defined"],
            },
            {
                **valid,
                "deliveryCapabilities": ["stamp-advanced"],
                "stampTargetKinds": ["named-slot"],
                "providerTargetSchemas": [
                    {
                        "providerId": "custom",
                        "schemaVersion": "custom/v1",
                        "jsonSchema": {"type": "object"},
                    }
                ],
            },
        )
        for candidate in invalid:
            with pytest.raises(ValidationError):
                self.validate_component(
                    "PKICredentialDeliveryDescriptor", candidate
                )

    def test_pki_stamp_material_schema_binds_projection_to_variant(self) -> None:
        valid = {
            "projection": "certificate-der",
            "credential": {
                "projection": "certificate-der",
                "form": "public",
                "generationId": "generation-1",
            },
        }
        self.validate_component("PKICredentialStampMaterial", valid)

        invalid = (
            {**valid, "projection": "provider-encoding"},
            {
                "projection": "certificate-der",
                "providerEncoding": {
                    "providerId": "custom",
                    "schemaVersion": "custom/v1",
                    "form": "private-bytes",
                    "source": valid["credential"],
                },
            },
            {
                "projection": "literal-reference",
                "credential": valid["credential"],
            },
        )
        for candidate in invalid:
            with pytest.raises(ValidationError):
                self.validate_component("PKICredentialStampMaterial", candidate)

    def test_pki_canonical_uint64_schema_enforces_the_full_range(self) -> None:
        for value in ("0", "1", "18446744073709551614", "18446744073709551615"):
            self.validate_component("PKICanonicalUint64", value)

        for value in (
            "",
            "00",
            "01",
            "-1",
            "18446744073709551616",
            "99999999999999999999",
        ):
            with pytest.raises(ValidationError):
                self.validate_component("PKICanonicalUint64", value)

    def test_pki_crl_contract_is_strict_auditable_and_recoverable(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        for schema_name in (
            "PKIPublishCRLInnerRequest",
            "PKICRLPublishRequest",
            "PKICRLRequest",
            "PKICRLPublicationRequest",
            "PKICRLListRequest",
            "PKIReconcileCRLInnerRequest",
            "PKIReconcileCRLsInnerRequest",
            "PKICRLReconcileRequest",
            "PKICRLsReconcileRequest",
            "PKICRLSignedCheckpoint",
            "PKICRLPublicationIntent",
            "PKICRLGeneration",
            "PKICRLPublicationResult",
            "PKICRLListResponse",
            "PKICRLPublicationListResponse",
        ):
            assert not schemas[schema_name]["additionalProperties"]

        concrete_algorithms = schemas["PKIConcreteSignatureAlgorithm"]["enum"]
        assert "" not in concrete_algorithms
        assert "auto" not in concrete_algorithms
        assert "ml-dsa-65" in concrete_algorithms

        backend = schemas["PKIBackendDescriptor"]
        assert "signatureAlgorithms" in backend["required"]
        assert backend["properties"]["signatureAlgorithms"]["items"] == {
            "$ref": "#/components/schemas/PKIConcreteSignatureAlgorithm"
        }

        publish = schemas["PKIPublishCRLInnerRequest"]
        assert publish["required"] == ["authorityId"]
        assert "signatureAlgorithm" in publish["properties"]
        assert publish["properties"]["validitySeconds"]["oneOf"] == [
            {"type": "integer", "const": 0},
            {"type": "integer", "minimum": 300, "maximum": 604800},
        ]

        intent = schemas["PKICRLPublicationIntent"]
        for field in (
            "requestSha256",
            "issuerGenerationId",
            "number",
            "revocationIds",
            "signatureAlgorithm",
            "phase",
            "ownerToken",
            "revision",
            "leaseExpiresAt",
        ):
            assert field in intent["required"]
        assert intent["properties"]["revocationIds"]["maxItems"] == 100000
        assert intent["properties"]["revocationIds"]["uniqueItems"]
        assert intent["oneOf"] == [
            {
                "properties": {"status": {"enum": ["pending"]}},
                "not": {
                    "anyOf": [
                        {"required": ["resultCrlGenerationId"]},
                        {"required": ["failure"]},
                    ]
                },
            },
            {
                "required": ["resultCrlGenerationId"],
                "properties": {
                    "status": {"enum": ["completed"]},
                    "phase": {"enum": ["signed"]},
                },
                "not": {"required": ["failure"]},
            },
            {
                "required": ["failure"],
                "properties": {"status": {"enum": ["failed"]}},
                "not": {"required": ["resultCrlGenerationId"]},
            },
        ]
        assert schemas["PKICRLPublicationPhase"]["enum"] == [
            "planned",
            "signing",
            "signed",
        ]
        assert intent["allOf"][0]["oneOf"][2] == {
            "required": ["signedCheckpoint"],
            "properties": {"phase": {"enum": ["signed"]}},
        }
        checkpoint = schemas["PKICRLSignedCheckpoint"]
        assert not checkpoint["additionalProperties"]
        assert checkpoint["properties"]["crlDer"]["contentEncoding"] == "base64"
        assert checkpoint["properties"]["providerOperationRef"]["maxLength"] == 1024

        generation = schemas["PKICRLGeneration"]
        assert generation["properties"]["signatureAlgorithm"] == {
            "$ref": "#/components/schemas/PKIConcreteSignatureAlgorithm"
        }
        assert (
            generation["properties"]["fingerprintSha256"]["pattern"]
            == "^[0-9a-f]{64}$"
        )
        assert generation["properties"]["crlDer"]["contentEncoding"] == "base64"

        context = schemas["PKIRequestContext"]["properties"]
        assert "approveCrlPublicationReconciliation" in context
        assert not context["approveCrlPublicationReconciliation"]["default"]
        assert schemas["PKIReconcileCRLInnerRequest"]["properties"][
            "staleAfterSeconds"
        ] == {"type": "integer", "minimum": 60, "maximum": 86400}
        assert schemas["PKIReconcileCRLInnerRequest"]["required"] == [
            "publicationId",
            "staleAfterSeconds",
        ]
        assert schemas["PKIReconcileCRLsInnerRequest"]["properties"]["limit"] == {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
        }

    def test_pki_certificate_and_bundle_contracts_are_strongly_typed(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        template_ref = "#/components/schemas/PKICertificateTemplate"
        template = schemas["PKICertificateTemplate"]
        assert not template["additionalProperties"]
        assert set(template["properties"]) == {
            "serialNumber",
            "subject",
            "notBefore",
            "notAfter",
            "key",
            "signatureAlgorithm",
            "subjectAlternativeNames",
            "basicConstraints",
            "keyUsage",
            "extendedKeyUsages",
            "unknownExtendedKeyUsages",
            "subjectKeyIdentifier",
            "authorityKeyIdentifier",
            "nameConstraints",
            "policyOids",
            "ocspServers",
            "issuingCertificateUrls",
            "crlDistributionPoints",
            "customExtensions",
        }
        assert set(template["required"]) == {
            "serialNumber",
            "subject",
            "notBefore",
            "notAfter",
            "key",
            "signatureAlgorithm",
            "subjectAlternativeNames",
            "basicConstraints",
            "keyUsage",
            "subjectKeyIdentifier",
            "authorityKeyIdentifier",
            "nameConstraints",
        }

        for schema_name in (
            "PKIAttribute",
            "PKIDistinguishedName",
            "PKISubjectAlternativeNames",
            "PKINameConstraints",
            "PKIKeySpec",
            "PKIBasicConstraints",
            "PKIKeyIdentifier",
            "PKICustomExtension",
        ):
            assert not schemas[schema_name]["additionalProperties"]

        for schema_name in (
            "PKIIssueCertificateInnerRequest",
            "PKICreateAuthorityInnerRequest",
            "PKIRenewCertificateInnerRequest",
            "PKIRotateCertificateInnerRequest",
            "PKICertificateGeneration",
        ):
            assert (
                schemas[schema_name]["properties"]["template"]["$ref"]
                == template_ref
            )

        profile = schemas["PKIProfile"]["properties"]
        assert profile["key"]["$ref"] == "#/components/schemas/PKIKeySpec"
        assert (
            profile["basicConstraints"]["$ref"]
            == "#/components/schemas/PKIBasicConstraints"
        )

        bundle = schemas["PKIBundle"]
        assert not bundle["additionalProperties"]
        for field, target in {
            "certificate": "PKICertificateBinary",
            "publicKey": "PKIPublicKeyBinary",
            "privateKey": "PKIPrivateKeyBinary",
            "privateKeyRef": "PKIKeyReference",
            "fingerprints": "PKIFingerprints",
        }.items():
            assert (
                bundle["properties"][field]["$ref"]
                == f"#/components/schemas/{target}"
            )
        for field, target in {
            "chain": "PKICertificateMember",
            "trustAnchors": "PKICertificateMember",
            "certificateRevocationLists": "PKICRLMember",
        }.items():
            assert (
                bundle["properties"][field]["items"]["$ref"]
                == f"#/components/schemas/{target}"
            )

    def test_pki_rollover_contract_is_strict_and_generation_pinned(self) -> None:
        schemas = self.openapi["components"]["schemas"]
        rollover = schemas["PKIAuthorityRollover"]
        assert not rollover["additionalProperties"]
        assert {
            "previousAuthorityGenerationId",
            "replacementAuthorityGenerationId",
            "overlapTrustGenerationId",
            "consumerTracking",
            "requiredAssignmentIds",
            "phase",
        }.issubset(rollover["required"])
        assert rollover["properties"]["consumerTracking"]["enum"] == [
            "all-tracked",
            "explicit",
            "none",
        ]
        assert rollover["properties"]["requiredAssignmentIds"]["maxItems"] == 4096
        assert rollover["properties"]["requiredAssignmentIds"]["uniqueItems"]

        operation = schemas["PKIOperation"]
        assert not operation["additionalProperties"]
        assert operation["properties"]["kind"] == {"const": "authority-rollover"}
        assert "authorityRollover" in operation["required"]
        assert len(operation["oneOf"]) == 4

        acknowledgement = schemas["PKIConsumerAcknowledgement"]
        assert not acknowledgement["additionalProperties"]
        assert acknowledgement["properties"]["kind"] == {
            "const": "trust-set-generation"
        }

        rpc_error = schemas["RPCError"]
        assert not rpc_error["additionalProperties"]
        assert rpc_error["properties"]["version"] == {"const": "v1"}
        assert "rollover-precondition" in rpc_error["properties"]["code"]["enum"]
        for code in (
            "idempotency-conflict",
            "mutation-exists",
            "issuance-in-progress",
            "crl-publication-in-progress",
            "private-key-export-denied",
            "authority-signing-locked",
            "permission-denied",
        ):
            assert code in rpc_error["properties"]["code"]["enum"]
        assert "permission-denied" in rpc_error["oneOf"][1]["properties"]["code"][
            "enum"
        ]
        self.validate_component(
            "RPCError",
            {
                "version": "v1",
                "code": "permission-denied",
                "message": "privileged RPC access was denied",
            },
        )
        assert "resource-reserved" in rpc_error["properties"]["rolloverReason"]["enum"]
        assert rpc_error["properties"]["rolloverDetail"] == {"type": "string"}
        assert rpc_error["oneOf"][0] == {
            "required": ["rolloverReason"],
            "properties": {"code": {"const": "rollover-precondition"}},
        }

        noncompleted_phases = [
            "awaiting-overlap-acknowledgements",
            "awaiting-leaf-rotation",
            "awaiting-final-acknowledgements",
        ]
        for branch in (operation["oneOf"][0], operation["oneOf"][2]):
            phase = branch["properties"]["authorityRollover"]["allOf"][1][
                "properties"
            ]["phase"]
            assert phase["enum"] == noncompleted_phases
        canceled_phase = operation["oneOf"][3]["properties"][
            "authorityRollover"
        ]["allOf"][1]["properties"]["phase"]
        assert canceled_phase == {"const": "awaiting-overlap-acknowledgements"}

        for method in (
            "BindPKIAssignment",
            "StagePKIAssignment",
            "ActivatePKIAssignment",
            "UnbindPKIAssignment",
            "StagePKITrustSet",
            "ActivatePKITrustSet",
        ):
            responses = self.openapi["paths"][SERVICE_PREFIX + method]["post"][
                "responses"
            ]
            assert responses["404"] == {"$ref": "#/components/responses/RPCError"}
            assert responses["409"] == {"$ref": "#/components/responses/RPCError"}

        start = schemas["PKIStartAuthorityRolloverInnerRequest"]
        assert not start["additionalProperties"]
        assert len(start["oneOf"]) == 2
        assert start["properties"]["consumerTracking"]["enum"] == [
            "all-tracked",
            "explicit",
            "none",
        ]

        for schema_name in (
            "PKIActivateAuthorityRolloverInnerRequest",
            "PKIBeginAuthorityRolloverFinalTrustInnerRequest",
            "PKICompleteAuthorityRolloverInnerRequest",
        ):
            schema = schemas[schema_name]
            assert not schema["additionalProperties"]
            assert "expectedRevision" in schema["required"]
            assert "expectedTrustSetRevision" in schema["required"]
            assert (
                schema["properties"]["expectedTrustSetRevision"]["maximum"]
                == MAX_SEQUENCE_NUMBER
            )

        for phrase in (
            "Root authorities",
            "subordinate authorities",
            "previousAuthorityGenerationId",
            "replacementAuthorityGenerationId",
            "all-tracked",
            "explicit",
            "none",
        ):
            assert phrase in self.doc_html

    def resolve_ref(self, node: object) -> object:
        if not isinstance(node, dict) or "$ref" not in node:
            return node
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise AssertionError(f"unsupported OpenAPI ref: {ref!r}")
        current: object = self.openapi
        for part in ref.removeprefix("#/").split("/"):
            if not isinstance(current, dict):
                raise AssertionError(
                    f"cannot resolve OpenAPI ref through {part!r}: {ref}"
                )
            current = current[part]
        return current

    def validate_component(self, name: str, instance: object) -> None:
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": f"#/components/schemas/{name}",
            "components": self.openapi["components"],
        }
        Draft202012Validator(schema).validate(instance)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-p", "no:cacheprovider"]))
