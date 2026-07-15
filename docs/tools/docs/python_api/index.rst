Hovel Python SDK API
====================

This reference is generated with Sphinx autodoc from the importable
``hovel_sdk`` package. The module-author guide explains lifecycle rules and
operator-facing behavior; this page is the callable API surface.

Module Lifecycle
----------------

.. autoclass:: hovel_sdk.HovelModule
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.Context
   :members:
   :undoc-members:
   :show-inheritance:

.. autofunction:: hovel_sdk.serve

Configuration
-------------

.. autoclass:: hovel_sdk.Requirement
   :members:
   :undoc-members:
   :show-inheritance:

Results
-------

.. autoclass:: hovel_sdk.Result
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.Finding
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.Artifact
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.InstalledPayload
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.PayloadProviderRecord
   :members:
   :undoc-members:
   :show-inheritance:

Sessions
--------

.. autoclass:: hovel_sdk.SessionRef
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.LineShellSession
   :members:
   :undoc-members:
   :show-inheritance:

Mesh
----

``HovelModule`` supplies optional Mesh hooks; providers override only the
operations advertised by their descriptor.

.. autoclass:: hovel_sdk.MeshDescriptor
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshDescribeRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshTopology
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshTopologyRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshNode
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshLink
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshRoute
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshBeacon
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshBeaconRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshListener
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshListenerSpec
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshListenerListRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshListenerStartRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshListenerStopRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshTaskSpec
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshTaskRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshTaskResult
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshStreamRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshEvent
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshTrigger
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshBridgeEndpoint
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.MeshBridgeNetwork
   :members:
   :undoc-members:

.. autofunction:: hovel_sdk.connect_mesh_bridge

Credential Delivery Model
-------------------------

The discovery model describes strict credential slots and optional runtime,
files, encoding, and stamping capabilities. ``HovelModule`` provides the
``describe_credential_delivery`` hook; Python has no separate
``CredentialDescriber`` protocol.

.. autoclass:: hovel_sdk.CredentialDeliveryDescriptor
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialDeliveryCapability
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialSlot
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialPurpose
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialEndpointRole
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialConsumerType
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialProjection
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialMaterialForm
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialPrivateMaterialPolicy
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialProviderTargetSchema
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialProviderEncodingSchema
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialStampTargetKind
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialStampAddressSpace
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialStampRemainderPolicy
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialStampPreconditionKind
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialStampPrecondition
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialNamedSlotTarget
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialFileOffsetTarget
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialVirtualAddressTarget
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialSymbolTarget
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialMarkerTarget
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialBytePatternTarget
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialProviderDefinedTarget
   :members:
   :undoc-members:

.. autodata:: hovel_sdk.CredentialStampTarget

.. autoclass:: hovel_sdk.CredentialMaterialReference
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialReferencedStampMaterial
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialProviderEncodingStampMaterial
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialLiteralStampMaterial
   :members:
   :undoc-members:

.. autodata:: hovel_sdk.CredentialStampMaterial

.. autoclass:: hovel_sdk.ResolvedCredentialMetadata
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialStampRequest
   :members:
   :undoc-members:

Credential Provider Execution Model
-----------------------------------

These values cross the secret-bearing provider invocation boundary. Their
representations are redacted, but explicit value access still reveals secrets.
Do not log secret bytes, protected paths, or secret references, and do not put
them in Hovel's public execution ledger. A provider may copy material into its
own protected runtime or installation only when the advertised capability and
lifecycle require that retention; return only a non-secret receipt or digest.

.. autoclass:: hovel_sdk.CredentialOperationScope
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialProviderTarget
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialBytes
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialProtectedPath
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialSecretReference
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialScopedReference
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.ResolvedCredentialMaterial
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialRuntimeRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialFile
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialFilesRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialDeliveryReceipt
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialEncodingRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialEncodingResult
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialArtifactInput
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialArtifactOutput
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialDeploymentOutput
   :members:
   :undoc-members:

.. autodata:: hovel_sdk.CredentialStampOutput

.. autoclass:: hovel_sdk.CredentialStampedMaterialDigest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialStampTargetResolution
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialStampExecutionRequest
   :members:
   :undoc-members:

.. autoclass:: hovel_sdk.CredentialStampExecutionResult
   :members:
   :undoc-members:

Testing
-------

.. autoclass:: hovel_sdk.ModuleRPC
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: hovel_sdk.RPCError
   :members:
   :undoc-members:
   :show-inheritance:

.. autofunction:: hovel_sdk.drive_module

Logging
-------

.. autofunction:: hovel_sdk.setup_logging
