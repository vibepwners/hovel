package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/vibepwners/hovel/sdk/go/hovel"
)

const (
	payloadTLSCredentialSlot = "payload-tls-server"
	payloadPKIMagic          = "SQPKI001"
	payloadPKIVersion        = 1
	payloadPKIFlagPresent    = 0xa5c35a3c
	payloadPKIVersionOffset  = 8
	payloadPKIFlagsOffset    = 12
	payloadPKIPayloadLength  = 16
	payloadPKIBundleLength   = 20
	payloadPKICertLength     = 24
	payloadPKIKeyLength      = 28
	payloadPKIChainCount     = 32
	payloadPKITrustCount     = 36
	payloadPKICRLCount       = 40
	payloadPKISHA256Offset   = 44
	payloadPKIPayloadSHA256  = 76
	payloadPKIBundleOffset   = 108
	payloadPKIBundleCapacity = 1 << 20
	payloadPKIMaxBundleJSON  = payloadPKIBundleCapacity / 2
)

func payloadTLSCredentialSlotDescriptor() hovel.CredentialSlot {
	return hovel.CredentialSlot{
		Name:                         payloadTLSCredentialSlot,
		Purpose:                      hovel.CredentialPurposeTLSServer,
		EndpointRole:                 hovel.CredentialEndpointServer,
		ConsumerType:                 hovel.CredentialConsumerPayload,
		AcceptedBundleVersions:       []string{hovel.CredentialBundleSchemaV1},
		AcceptedProfiles:             []string{"tls-server"},
		AcceptedCompatibilityTargets: []string{"portable-x509"},
		AcceptedProjections:          []hovel.CredentialProjection{hovel.CredentialProjectionBundle},
		AcceptedMaterialForms:        []hovel.CredentialMaterialForm{hovel.CredentialMaterialPrivateBytes},
		MaximumEncodedBytes:          payloadPKIMaxBundleJSON,
		RemainderPolicy:              hovel.CredentialStampRemainderZeroFill,
		PrivateMaterial:              hovel.CredentialPrivateMaterialRequired,
	}
}

func (Provider) StampCredential(
	req hovel.CredentialStampExecutionRequest,
) (hovel.CredentialStampExecutionResult, error) {
	if err := req.Validate(); err != nil {
		return hovel.CredentialStampExecutionResult{}, err
	}
	if req.Provider.ModuleID != payloadName+"@"+version ||
		req.Provider.ProviderID != payloadName || req.Provider.ProviderVersion != version {
		return hovel.CredentialStampExecutionResult{}, errors.New(
			"squatter: credential stamp targets a different provider",
		)
	}
	if req.Request.Capability != hovel.CredentialDeliveryStampStandard ||
		req.Request.SlotName != payloadTLSCredentialSlot ||
		req.Request.Target.Kind != hovel.CredentialStampTargetNamedSlot ||
		req.Request.Target.NamedSlot == nil ||
		req.Request.Target.NamedSlot.Name != payloadTLSCredentialSlot {
		return hovel.CredentialStampExecutionResult{}, errors.New(
			"squatter: credential stamp does not match the payload TLS slot",
		)
	}
	if req.Request.Credential.Purpose != hovel.CredentialPurposeTLSServer ||
		req.Request.Credential.ConsumerType != hovel.CredentialConsumerPayload ||
		req.Request.Credential.ProfileID != "tls-server" ||
		req.Request.Credential.CompatibilityTargetID != "portable-x509" {
		return hovel.CredentialStampExecutionResult{}, errors.New(
			"squatter: credential stamp metadata does not match the payload TLS slot",
		)
	}

	material, ok := req.Material.Bytes()
	if !ok {
		return hovel.CredentialStampExecutionResult{}, errors.New(
			"squatter: payload TLS stamp requires private bundle bytes",
		)
	}
	defer clear(material)
	if uint64(len(material)) != req.Request.EncodedBytes || len(material) > payloadPKIMaxBundleJSON {
		return hovel.CredentialStampExecutionResult{}, errors.New(
			"squatter: payload TLS bundle length does not match the stamp plan",
		)
	}
	bundle, err := hovel.DecodeCredentialBundleJSON(material)
	if err != nil {
		return hovel.CredentialStampExecutionResult{}, fmt.Errorf(
			"squatter: validate stamped TLS bundle: %w",
			err,
		)
	}
	defer bundle.Clear()
	if bundle.AssignmentID != req.Request.AssignmentID ||
		bundle.Purpose != req.Request.Credential.Purpose ||
		bundle.CompatibilityTargetID != req.Request.Credential.CompatibilityTargetID ||
		req.Request.Credential.BundleVersion != bundle.SchemaVersion {
		return hovel.CredentialStampExecutionResult{}, errors.New(
			"squatter: stamped TLS bundle metadata does not match its plan",
		)
	}
	if err := validatePayloadTLSNamedGroups(bundle); err != nil {
		return hovel.CredentialStampExecutionResult{}, err
	}
	if _, err := bundle.TLSServerConfigAt(time.Now().UTC()); err != nil {
		return hovel.CredentialStampExecutionResult{}, fmt.Errorf(
			"squatter: configure stamped TLS credential: %w",
			err,
		)
	}

	input, ok := req.Input.Content.Data()
	if !ok {
		return hovel.CredentialStampExecutionResult{}, errors.New(
			"squatter: payload TLS stamping requires an in-memory PE artifact",
		)
	}
	configOffset, err := payloadConfigOffset(input)
	if err != nil {
		return hovel.CredentialStampExecutionResult{}, err
	}
	if binary.LittleEndian.Uint32(input[configOffset+payloadConfigKindOffset:]) != payloadConfigKindTCPBind {
		return hovel.CredentialStampExecutionResult{}, errors.New(
			"squatter: payload TLS stamping currently requires a configured TCP-bind artifact",
		)
	}
	offset, err := payloadPKIConfigOffset(input)
	if err != nil {
		return hovel.CredentialStampExecutionResult{}, err
	}
	stamped := append([]byte(nil), input...)
	defer clear(stamped)
	region := stamped[offset : offset+payloadPKIBundleOffset+payloadPKIBundleCapacity]
	payload, err := encodePayloadPKIManifest(material, bundle)
	if err != nil {
		return hovel.CredentialStampExecutionResult{}, err
	}
	defer clear(payload)
	binary.LittleEndian.PutUint32(region[payloadPKIVersionOffset:], payloadPKIVersion)
	binary.LittleEndian.PutUint32(region[payloadPKIFlagsOffset:], payloadPKIFlagPresent)
	binary.LittleEndian.PutUint32(region[payloadPKIPayloadLength:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(region[payloadPKIBundleLength:], uint32(len(material)))
	binary.LittleEndian.PutUint32(region[payloadPKICertLength:], uint32(len(bundle.Certificate.Data)))
	binary.LittleEndian.PutUint32(region[payloadPKIKeyLength:], uint32(len(bundle.PrivateKey.Data)))
	binary.LittleEndian.PutUint32(region[payloadPKIChainCount:], uint32(len(bundle.Chain)))
	binary.LittleEndian.PutUint32(region[payloadPKITrustCount:], uint32(len(bundle.TrustAnchors)))
	binary.LittleEndian.PutUint32(region[payloadPKICRLCount:], uint32(len(bundle.CertificateRevocationLists)))
	digest := sha256.Sum256(material)
	copy(region[payloadPKISHA256Offset:payloadPKIPayloadSHA256], digest[:])
	payloadDigest := sha256.Sum256(payload)
	copy(region[payloadPKIPayloadSHA256:payloadPKIBundleOffset], payloadDigest[:])
	clear(region[payloadPKIBundleOffset:])
	copy(region[payloadPKIBundleOffset:], payload)

	content, err := hovel.NewCredentialArtifactData(stamped)
	if err != nil {
		return hovel.CredentialStampExecutionResult{}, err
	}
	output, err := hovel.NewCredentialStampArtifactOutput(hovel.CredentialArtifactOutput{
		Name:     "squatter-stamped.exe",
		Encoding: req.Input.Encoding,
		Content:  content,
	})
	if err != nil {
		return hovel.CredentialStampExecutionResult{}, err
	}
	return hovel.CredentialStampExecutionResult{
		StampID:          req.StampID,
		Output:           output,
		TargetResolution: hovel.CredentialStampTargetUnchanged,
		ResolvedTarget:   req.Request.Target,
		BytesWritten:     hovel.CredentialCanonicalUint64(strconv.FormatUint(req.Request.EncodedBytes, 10)),
		MaterialDigests:  append([]hovel.CredentialStampedMaterialDigest(nil), req.ExpectedDigests...),
	}, nil
}

func validatePayloadTLSNamedGroups(bundle hovel.CredentialBundle) error {
	expected := []string{"x25519", "secp256r1", "secp384r1", "secp521r1"}
	if bundle.KeyEstablishmentPolicy != hovel.CredentialKeyEstablishmentClassicalCompatible ||
		!slices.Equal(bundle.TLSNamedGroups, expected) {
		return fmt.Errorf(
			"squatter: payload TLS stamp requires named groups %q in preference order",
			expected,
		)
	}
	return nil
}

func encodePayloadPKIManifest(material []byte, bundle hovel.CredentialBundle) ([]byte, error) {
	if bundle.PrivateKey == nil {
		return nil, errors.New("squatter: payload TLS bundle does not contain a private key")
	}
	payload := make([]byte, 0, len(material)+len(bundle.Certificate.Data)+len(bundle.PrivateKey.Data))
	payload = append(payload, material...)
	payload = append(payload, bundle.Certificate.Data...)
	payload = append(payload, bundle.PrivateKey.Data...)
	appendMembers := func(members []hovel.CredentialBundleCertificate) {
		for _, member := range members {
			payload = binary.LittleEndian.AppendUint32(payload, uint32(len(member.Data)))
			payload = append(payload, member.Data...)
		}
	}
	appendMembers(bundle.Chain)
	appendMembers(bundle.TrustAnchors)
	for _, member := range bundle.CertificateRevocationLists {
		payload = binary.LittleEndian.AppendUint32(payload, uint32(len(member.Data)))
		payload = append(payload, member.Data...)
	}
	if len(payload) > payloadPKIBundleCapacity {
		clear(payload)
		return nil, errors.New("squatter: encoded payload TLS manifest exceeds its PE slot")
	}
	return payload, nil
}

func payloadPKIConfigOffset(body []byte) (int, error) {
	marker := []byte(payloadPKIMagic)
	for cursor := 0; cursor < len(body); {
		found := bytes.Index(body[cursor:], marker)
		if found < 0 {
			break
		}
		offset := cursor + found
		end := offset + payloadPKIBundleOffset + payloadPKIBundleCapacity
		if end <= len(body) && binary.LittleEndian.Uint32(body[offset+payloadPKIVersionOffset:]) == payloadPKIVersion {
			return offset, nil
		}
		cursor = offset + 1
	}
	return -1, fmt.Errorf("squatter payload PKI marker %q not found", payloadPKIMagic)
}

func stampedPayloadBundle(body []byte) ([]byte, string, error) {
	offset, err := payloadPKIConfigOffset(body)
	if err != nil {
		return nil, "", err
	}
	state := binary.LittleEndian.Uint32(body[offset+payloadPKIFlagsOffset:])
	if state == 0 {
		return nil, "", errors.New("squatter payload does not contain a stamped PKI bundle")
	}
	if state != payloadPKIFlagPresent {
		return nil, "", errors.New("squatter payload stamped PKI state is invalid")
	}
	length := int(binary.LittleEndian.Uint32(body[offset+payloadPKIBundleLength:]))
	if length < 1 || length > payloadPKIBundleCapacity {
		return nil, "", errors.New("squatter payload stamped PKI bundle length is invalid")
	}
	bundle := append([]byte(nil), body[offset+payloadPKIBundleOffset:offset+payloadPKIBundleOffset+length]...)
	digest := sha256.Sum256(bundle)
	want := body[offset+payloadPKISHA256Offset : offset+payloadPKIPayloadSHA256]
	if !bytes.Equal(digest[:], want) {
		clear(bundle)
		return nil, "", errors.New("squatter payload stamped PKI bundle digest is invalid")
	}
	return bundle, hex.EncodeToString(digest[:]), nil
}
