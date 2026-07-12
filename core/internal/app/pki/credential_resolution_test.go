package pki_test

import (
	"bytes"
	"strings"
	"testing"

	pkimemory "github.com/vibepwners/hovel/internal/adapters/pki/memory"
	apppki "github.com/vibepwners/hovel/internal/app/pki"
	domainpki "github.com/vibepwners/hovel/internal/domain/pki"
)

func TestServiceResolvesAndClearsRuntimeCredentialSelections(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	assignment, _ := bindActiveStampTestAssignment(
		t,
		service,
		"runtime-resolution",
		"assignment-runtime-resolution",
		"mesh-provider/listener-edge",
	)
	descriptor := runtimeCredentialDescriptor(t)
	provider := runtimeCredentialProvider(t, descriptor)
	consumer, err := domainpki.NewMeshListenerConsumer("mesh-provider", "listener-edge")
	if err != nil {
		t.Fatal(err)
	}
	selections := domainpki.CredentialSelections{
		{
			RequestID:    "runtime-public",
			AssignmentID: assignment.ID,
			SlotName:     "certificate",
			Capability:   domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionCertificateDER,
				Form:       domainpki.CredentialMaterialPublic,
			},
		},
		{
			RequestID:    "runtime-private",
			AssignmentID: assignment.ID,
			SlotName:     "private-key",
			Capability:   domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionPrivateKeyPKCS8,
				Form:       domainpki.CredentialMaterialPrivateBytes,
			},
		},
	}
	deliveries, cleanup, err := service.ResolveCredentialOperation(
		t.Context(),
		provider,
		descriptor,
		selections,
		domainpki.CredentialOperationScope{OperationID: "mesh-operation-1", ListenerID: "listener-edge"},
		[]domainpki.CredentialConsumerBinding{consumer},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(deliveries) != len(selections) {
		t.Fatalf("deliveries = %d, want %d", len(deliveries), len(selections))
	}
	publicData := deliveries[0].Runtime.Material.Data
	privateData := deliveries[1].Runtime.Material.Data
	if len(publicData) == 0 || len(privateData) == 0 {
		t.Fatal("resolved runtime delivery omitted credential material")
	}
	cleanup()
	if !bytes.Equal(publicData, make([]byte, len(publicData))) ||
		!bytes.Equal(privateData, make([]byte, len(privateData))) {
		t.Fatal("credential cleanup did not clear ephemeral material")
	}
	provider.DescriptorSHA256 = strings.Repeat("0", 64)
	if _, cleanup, err := service.ResolveCredentialOperation(
		t.Context(),
		provider,
		descriptor,
		selections,
		domainpki.CredentialOperationScope{OperationID: "mesh-operation-1"},
		[]domainpki.CredentialConsumerBinding{consumer},
	); err == nil {
		cleanup()
		t.Fatal("ResolveCredentialOperation() accepted a mismatched descriptor digest")
	}
}

func TestServiceRejectsCredentialAssignmentOutsideOperation(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	assignment, _ := bindActiveStampTestAssignment(
		t,
		service,
		"runtime-consumer",
		"assignment-runtime-consumer",
		"mesh-provider/listener-other",
	)
	descriptor := runtimeCredentialDescriptor(t)
	provider := runtimeCredentialProvider(t, descriptor)
	consumer, err := domainpki.NewMeshListenerConsumer("mesh-provider", "listener-edge")
	if err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := service.ResolveCredentialOperation(
		t.Context(),
		provider,
		descriptor,
		domainpki.CredentialSelections{{
			RequestID:    "runtime-wrong-consumer",
			AssignmentID: assignment.ID,
			SlotName:     "certificate",
			Capability:   domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionCertificateDER,
				Form:       domainpki.CredentialMaterialPublic,
			},
		}},
		domainpki.CredentialOperationScope{ListenerID: "listener-edge"},
		[]domainpki.CredentialConsumerBinding{consumer},
	)
	cleanup()
	if err == nil {
		t.Fatal("ResolveCredentialOperation() accepted an assignment bound to another consumer")
	}
}

func TestServiceRejectsUnimplementedRuntimeCredentialProjection(t *testing.T) {
	t.Parallel()

	store := pkimemory.NewStore()
	service := newTestService(t, store)
	assignment, _ := bindActiveStampTestAssignment(
		t,
		service,
		"runtime-projection",
		"assignment-runtime-projection",
		"mesh-provider/listener-edge",
	)
	descriptor := runtimeCredentialDescriptor(t)
	descriptor.Slots[0].AcceptedProjections = append(
		descriptor.Slots[0].AcceptedProjections,
		domainpki.CredentialProjectionBundle,
	)
	provider := runtimeCredentialProvider(t, descriptor)
	consumer, err := domainpki.NewMeshListenerConsumer("mesh-provider", "listener-edge")
	if err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := service.ResolveCredentialOperation(
		t.Context(),
		provider,
		descriptor,
		domainpki.CredentialSelections{{
			RequestID:    "runtime-bundle",
			AssignmentID: assignment.ID,
			SlotName:     "certificate",
			Capability:   domainpki.DeliveryCapabilityRuntime,
			Material: domainpki.CredentialMaterialSelection{
				Projection: domainpki.CredentialProjectionBundle,
				Form:       domainpki.CredentialMaterialPublic,
			},
		}},
		domainpki.CredentialOperationScope{ListenerID: "listener-edge"},
		[]domainpki.CredentialConsumerBinding{consumer},
	)
	cleanup()
	if err == nil {
		t.Fatal("ResolveCredentialOperation() accepted an unimplemented projection")
	}
}

func runtimeCredentialDescriptor(t *testing.T) domainpki.CredentialDeliveryDescriptor {
	t.Helper()
	const maximumRuntimeCredentialBytes = 64 * 1024
	common := domainpki.CredentialSlot{
		Purpose:                domainpki.PurposeTLSServer,
		EndpointRole:           domainpki.CredentialEndpointServer,
		ConsumerType:           domainpki.ConsumerMeshListener,
		AcceptedBundleVersions: []string{domainpki.BundleSchemaV1},
		AcceptedProfiles:       []domainpki.ProfileID{domainpki.ProfileTLSServer},
		AcceptedCompatibilityTargets: []domainpki.CompatibilityTargetID{
			domainpki.CompatibilityPortableX509,
		},
		MaximumEncodedBytes: maximumRuntimeCredentialBytes,
		RemainderPolicy:     domainpki.StampRemainderPreserve,
	}
	certificate := common.Clone()
	certificate.Name = "certificate"
	certificate.AcceptedProjections = []domainpki.CredentialProjection{
		domainpki.CredentialProjectionCertificateDER,
	}
	certificate.AcceptedMaterialForms = []domainpki.CredentialMaterialForm{
		domainpki.CredentialMaterialPublic,
	}
	certificate.PrivateMaterial = domainpki.PrivateMaterialForbidden
	privateKey := common.Clone()
	privateKey.Name = "private-key"
	privateKey.AcceptedProjections = []domainpki.CredentialProjection{
		domainpki.CredentialProjectionPrivateKeyPKCS8,
	}
	privateKey.AcceptedMaterialForms = []domainpki.CredentialMaterialForm{
		domainpki.CredentialMaterialPrivateBytes,
	}
	privateKey.PrivateMaterial = domainpki.PrivateMaterialRequired
	descriptor, err := domainpki.NewCredentialDeliveryDescriptor(
		domainpki.CredentialDeliveryDescriptorArgs{
			SchemaVersion: domainpki.CredentialDeliverySchemaV1,
			Slots:         []domainpki.CredentialSlot{certificate, privateKey},
			Capabilities:  []domainpki.DeliveryCapability{domainpki.DeliveryCapabilityRuntime},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func runtimeCredentialProvider(
	t *testing.T,
	descriptor domainpki.CredentialDeliveryDescriptor,
) domainpki.CredentialProviderTarget {
	t.Helper()
	digest, err := descriptor.DigestSHA256()
	if err != nil {
		t.Fatal(err)
	}
	return domainpki.CredentialProviderTarget{
		ModuleID:         "mesh-provider",
		ProviderID:       "mesh-provider",
		ProviderVersion:  "1.0.0",
		DescriptorSHA256: digest,
	}
}

var _ apppki.CredentialUseAuthorizer = fixedAuditContext{}
