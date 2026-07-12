package pki

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

const (
	CredentialStampSchemaV1      = "hovel.pki.credential-stamp/v1"
	MaximumCredentialStampLinks  = 64
	MaximumStampedMaterialHashes = 128
	MaximumCredentialStampJSON   = MaximumCredentialDescriptorJSON +
		(2 * MaximumStampContractJSON)
)

type CredentialStampStatus string

const (
	CredentialStampPending    CredentialStampStatus = "pending"
	CredentialStampSucceeded  CredentialStampStatus = "succeeded"
	CredentialStampFailed     CredentialStampStatus = "failed"
	CredentialStampSuperseded CredentialStampStatus = "superseded"
)

func (s CredentialStampStatus) Validate() error {
	switch s {
	case CredentialStampPending, CredentialStampSucceeded,
		CredentialStampFailed, CredentialStampSuperseded:
		return nil
	default:
		return fmt.Errorf("pki: unsupported credential stamp status %q", s)
	}
}

type CredentialStampLinkKind string

const (
	CredentialStampLinkPayloadStamp CredentialStampLinkKind = "payload-stamp"
	CredentialStampLinkModule       CredentialStampLinkKind = "module"
	CredentialStampLinkOperation    CredentialStampLinkKind = "operation"
	CredentialStampLinkChain        CredentialStampLinkKind = "chain"
	CredentialStampLinkThrow        CredentialStampLinkKind = "throw"
	CredentialStampLinkRun          CredentialStampLinkKind = "run"
	CredentialStampLinkTarget       CredentialStampLinkKind = "target"
	CredentialStampLinkListener     CredentialStampLinkKind = "listener"
	CredentialStampLinkNode         CredentialStampLinkKind = "node"
)

func (k CredentialStampLinkKind) Validate() error {
	switch k {
	case CredentialStampLinkPayloadStamp, CredentialStampLinkModule,
		CredentialStampLinkOperation, CredentialStampLinkChain,
		CredentialStampLinkThrow, CredentialStampLinkRun,
		CredentialStampLinkTarget, CredentialStampLinkListener,
		CredentialStampLinkNode:
		return nil
	default:
		return fmt.Errorf("pki: unsupported credential stamp link kind %q", k)
	}
}

type CredentialStampLink struct {
	Kind      CredentialStampLinkKind `json:"kind"`
	Reference StampReferenceID        `json:"reference"`
}

type credentialStampLinkWire CredentialStampLink

func (l *CredentialStampLink) UnmarshalJSON(data []byte) error {
	if l == nil {
		return errors.New("pki: credential stamp link destination is nil")
	}
	var wire credentialStampLinkWire
	if err := strictDecodeJSONObject(
		data, MaximumStampContractJSON, &wire, "credential stamp link",
	); err != nil {
		return err
	}
	link := CredentialStampLink(wire)
	if err := link.Validate(); err != nil {
		return err
	}
	*l = link
	return nil
}

func (l CredentialStampLink) Validate() error {
	if err := l.Kind.Validate(); err != nil {
		return err
	}
	return l.Reference.Validate()
}

type StampArtifactKind string

const (
	StampArtifactWorkspace StampArtifactKind = "workspace-artifact"
	StampArtifactProvider  StampArtifactKind = "provider-build-input"
)

func (k StampArtifactKind) Validate() error {
	switch k {
	case StampArtifactWorkspace, StampArtifactProvider:
		return nil
	default:
		return fmt.Errorf("pki: unsupported stamp artifact kind %q", k)
	}
}

type StampArtifactReference struct {
	Kind   StampArtifactKind `json:"kind"`
	ID     StampReferenceID  `json:"id"`
	SHA256 string            `json:"sha256"`
}

type stampArtifactReferenceWire StampArtifactReference

func (r *StampArtifactReference) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: stamp artifact reference destination is nil")
	}
	var wire stampArtifactReferenceWire
	if err := strictDecodeJSONObject(
		data, MaximumStampContractJSON, &wire, "stamp artifact reference",
	); err != nil {
		return err
	}
	reference := StampArtifactReference(wire)
	if err := reference.Validate(); err != nil {
		return err
	}
	*r = reference
	return nil
}

func (r StampArtifactReference) Validate() error {
	if err := r.Kind.Validate(); err != nil {
		return err
	}
	if err := r.ID.Validate(); err != nil {
		return err
	}
	return validateCanonicalSHA256(r.SHA256, "stamp artifact")
}

type StampDeploymentReference struct {
	Reference     StampReferenceID `json:"reference"`
	ReceiptSHA256 string           `json:"receiptSha256"`
}

type stampDeploymentReferenceWire StampDeploymentReference

func (r *StampDeploymentReference) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: stamp deployment reference destination is nil")
	}
	var wire stampDeploymentReferenceWire
	if err := strictDecodeJSONObject(
		data, MaximumStampContractJSON, &wire, "stamp deployment reference",
	); err != nil {
		return err
	}
	reference := StampDeploymentReference(wire)
	if err := reference.Validate(); err != nil {
		return err
	}
	*r = reference
	return nil
}

func (r StampDeploymentReference) Validate() error {
	if err := r.Reference.Validate(); err != nil {
		return err
	}
	return validateCanonicalSHA256(r.ReceiptSHA256, "stamp deployment receipt")
}

type StampDestination struct {
	Artifact   *StampArtifactReference   `json:"artifact,omitempty"`
	Deployment *StampDeploymentReference `json:"deployment,omitempty"`
}

type stampDestinationWire StampDestination

func (d *StampDestination) UnmarshalJSON(data []byte) error {
	if d == nil {
		return errors.New("pki: stamp destination is nil")
	}
	var wire stampDestinationWire
	if err := strictDecodeJSONObject(
		data, MaximumStampContractJSON, &wire, "stamp destination",
	); err != nil {
		return err
	}
	destination := StampDestination(wire)
	active := ""
	switch {
	case destination.Artifact != nil && destination.Deployment == nil:
		active = "artifact"
	case destination.Artifact == nil && destination.Deployment != nil:
		active = "deployment"
	default:
		return errors.New("pki: stamp destination requires exactly one tagged variant")
	}
	if err := rejectInactiveVariantJSONFields(
		data, active, []string{"artifact", "deployment"}, "stamp destination",
	); err != nil {
		return err
	}
	if err := destination.Validate(); err != nil {
		return err
	}
	*d = destination.Clone()
	return nil
}

func (d StampDestination) Clone() StampDestination {
	result := d
	if d.Artifact != nil {
		value := *d.Artifact
		result.Artifact = &value
	}
	if d.Deployment != nil {
		value := *d.Deployment
		result.Deployment = &value
	}
	return result
}

func (d StampDestination) Validate() error {
	if (d.Artifact == nil) == (d.Deployment == nil) {
		return errors.New("pki: stamp destination requires exactly one tagged variant")
	}
	if d.Artifact != nil {
		return d.Artifact.Validate()
	}
	return d.Deployment.Validate()
}

type StampedMaterialDigest struct {
	Projection CredentialProjection `json:"projection"`
	Reference  StampReferenceID     `json:"reference"`
	SHA256     string               `json:"sha256"`
}

type stampedMaterialDigestWire StampedMaterialDigest

func (d *StampedMaterialDigest) UnmarshalJSON(data []byte) error {
	if d == nil {
		return errors.New("pki: stamped material digest destination is nil")
	}
	var wire stampedMaterialDigestWire
	if err := strictDecodeJSONObject(
		data, MaximumStampContractJSON, &wire, "stamped material digest",
	); err != nil {
		return err
	}
	digest := StampedMaterialDigest(wire)
	if err := digest.Validate(); err != nil {
		return err
	}
	*d = digest
	return nil
}

func (d StampedMaterialDigest) Validate() error {
	if err := d.Projection.Validate(); err != nil {
		return err
	}
	if err := d.Reference.Validate(); err != nil {
		return err
	}
	return validateCanonicalSHA256(d.SHA256, "stamped material")
}

type CredentialStampPlan struct {
	Descriptor       CredentialDeliveryDescriptor `json:"descriptor"`
	DescriptorSHA256 string                       `json:"descriptorSha256"`
	Request          CredentialStampRequest       `json:"request"`
	Input            StampArtifactReference       `json:"input"`
	ExpectedDigests  []StampedMaterialDigest      `json:"expectedDigests"`
}

type credentialStampPlanWire CredentialStampPlan

func (p *CredentialStampPlan) UnmarshalJSON(data []byte) error {
	if p == nil {
		return errors.New("pki: credential stamp plan destination is nil")
	}
	var wire credentialStampPlanWire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialStampJSON, &wire, "credential stamp plan",
	); err != nil {
		return err
	}
	plan := CredentialStampPlan(wire)
	if err := plan.Validate(); err != nil {
		return err
	}
	*p = plan.Clone()
	return nil
}

func NewCredentialStampPlan(
	descriptor CredentialDeliveryDescriptor,
	request CredentialStampRequest,
	input StampArtifactReference,
	expectedDigests []StampedMaterialDigest,
) (CredentialStampPlan, error) {
	digest, err := descriptor.DigestSHA256()
	if err != nil {
		return CredentialStampPlan{}, err
	}
	plan := CredentialStampPlan{
		Descriptor: descriptor.Clone(), DescriptorSHA256: digest,
		Request: request.Clone(), Input: input,
		ExpectedDigests: append([]StampedMaterialDigest(nil), expectedDigests...),
	}
	if err := plan.Validate(); err != nil {
		return CredentialStampPlan{}, err
	}
	return plan.Clone(), nil
}

func (p CredentialStampPlan) Clone() CredentialStampPlan {
	result := p
	result.Descriptor = p.Descriptor.Clone()
	result.Request = p.Request.Clone()
	result.ExpectedDigests = append([]StampedMaterialDigest(nil), p.ExpectedDigests...)
	return result
}

func (p CredentialStampPlan) Validate() error {
	if err := p.Descriptor.ValidateStampRequest(p.Request); err != nil {
		return err
	}
	if err := p.Input.Validate(); err != nil {
		return err
	}
	digest, err := p.Descriptor.DigestSHA256()
	if err != nil {
		return err
	}
	if p.DescriptorSHA256 != digest {
		return errors.New("pki: credential stamp descriptor digest does not match its snapshot")
	}
	if len(p.ExpectedDigests) == 0 || len(p.ExpectedDigests) > MaximumStampedMaterialHashes {
		return errors.New("pki: credential stamp expected digests are empty or exceed limits")
	}
	seen := make(map[string]string, len(p.ExpectedDigests))
	for _, digest := range p.ExpectedDigests {
		if err := digest.Validate(); err != nil {
			return err
		}
		key := stampedMaterialKey(digest.Projection, digest.Reference)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("pki: credential stamp expected digests contain a duplicate")
		}
		seen[key] = digest.SHA256
	}
	requiredReferences := requiredMaterialDigestReferences(p.Request.Material)
	if len(p.ExpectedDigests) != len(requiredReferences) {
		return errors.New("pki: credential stamp expected digests do not exactly match its material")
	}
	for _, required := range requiredReferences {
		if _, exists := seen[stampedMaterialKey(required.Projection, required.Reference)]; !exists {
			return fmt.Errorf("pki: credential stamp plan omits material reference %q", required.Reference)
		}
	}
	return nil
}

type StampTargetResolution string

const (
	StampTargetResolutionUnchanged  StampTargetResolution = "unchanged"
	StampTargetResolutionTranslated StampTargetResolution = "translated"
)

func (r StampTargetResolution) Validate() error {
	switch r {
	case StampTargetResolutionUnchanged, StampTargetResolutionTranslated:
		return nil
	default:
		return fmt.Errorf("pki: unsupported stamp target resolution %q", r)
	}
}

type CredentialStampResult struct {
	TargetResolution StampTargetResolution   `json:"targetResolution"`
	ResolvedTarget   StampTarget             `json:"resolvedTarget"`
	BytesWritten     CanonicalUint64         `json:"bytesWritten"`
	MaterialDigests  []StampedMaterialDigest `json:"materialDigests"`
	Destination      StampDestination        `json:"destination"`
}

type credentialStampResultWire CredentialStampResult

func (r *CredentialStampResult) UnmarshalJSON(data []byte) error {
	if r == nil {
		return errors.New("pki: credential stamp result destination is nil")
	}
	var wire credentialStampResultWire
	if err := strictDecodeJSONObject(
		data, MaximumStampContractJSON, &wire, "credential stamp result",
	); err != nil {
		return err
	}
	result := CredentialStampResult(wire)
	*r = result.Clone()
	return nil
}

func (r CredentialStampResult) Clone() CredentialStampResult {
	result := r
	result.ResolvedTarget = r.ResolvedTarget.Clone()
	result.MaterialDigests = append([]StampedMaterialDigest(nil), r.MaterialDigests...)
	result.Destination = r.Destination.Clone()
	return result
}

func (r CredentialStampResult) Validate(plan CredentialStampPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := r.TargetResolution.Validate(); err != nil {
		return err
	}
	if err := r.ResolvedTarget.Validate(); err != nil {
		return err
	}
	bytesWritten, err := r.BytesWritten.Uint64()
	if err != nil || bytesWritten == 0 || bytesWritten > MaximumBundleBinaryBytes {
		return errors.New("pki: credential stamp byte count is invalid")
	}
	if bytesWritten != plan.Request.EncodedBytes {
		return errors.New("pki: credential stamp byte count does not match its plan")
	}
	if err := validateTargetResolution(
		plan.Request.Target, r.ResolvedTarget, r.TargetResolution,
	); err != nil {
		return err
	}
	maximum, policy, bounded, err := stampTargetCapacity(r.ResolvedTarget)
	if err != nil {
		return err
	}
	if bounded && (bytesWritten > maximum ||
		(policy == StampRemainderRequireExact && bytesWritten != maximum)) {
		return errors.New("pki: credential stamp byte count does not satisfy its resolved target")
	}
	if len(r.MaterialDigests) == 0 || len(r.MaterialDigests) > MaximumStampedMaterialHashes {
		return errors.New("pki: credential stamp material digests are empty or exceed limits")
	}
	seen := make(map[string]string, len(r.MaterialDigests))
	for _, digest := range r.MaterialDigests {
		if err := digest.Validate(); err != nil {
			return err
		}
		key := string(digest.Projection) + "\x00" + string(digest.Reference)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("pki: credential stamp material digests contain a duplicate")
		}
		seen[key] = digest.SHA256
	}
	if len(seen) != len(plan.ExpectedDigests) {
		return errors.New("pki: credential stamp result digest set does not match its plan")
	}
	for _, expected := range plan.ExpectedDigests {
		actual, exists := seen[stampedMaterialKey(expected.Projection, expected.Reference)]
		if !exists {
			return fmt.Errorf("pki: credential stamp result omits planned digest %q", expected.Reference)
		}
		if actual != expected.SHA256 {
			return fmt.Errorf("pki: credential stamp result digest %q does not match its plan", expected.Reference)
		}
	}
	return r.Destination.Validate()
}

type CredentialStampArgs struct {
	SchemaVersion   string
	ID              StampID
	ProviderID      DeliveryProviderID
	ProviderVersion string
	Plan            CredentialStampPlan
	Links           []CredentialStampLink
	CreatedAt       time.Time
}

type CredentialStamp struct {
	SchemaVersion   string                 `json:"schemaVersion"`
	ID              StampID                `json:"id"`
	ProviderID      DeliveryProviderID     `json:"providerId"`
	ProviderVersion string                 `json:"providerVersion"`
	Plan            CredentialStampPlan    `json:"plan"`
	Links           []CredentialStampLink  `json:"links,omitempty"`
	Status          CredentialStampStatus  `json:"status"`
	Result          *CredentialStampResult `json:"result,omitempty"`
	Failure         string                 `json:"failure,omitempty"`
	SupersededBy    StampID                `json:"supersededBy,omitempty"`
	Revision        uint64                 `json:"revision"`
	CreatedAt       time.Time              `json:"createdAt"`
	UpdatedAt       time.Time              `json:"updatedAt"`
}

type credentialStampWire CredentialStamp

func (s *CredentialStamp) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("pki: credential stamp destination is nil")
	}
	var wire credentialStampWire
	if err := strictDecodeJSONObject(
		data, MaximumCredentialStampJSON, &wire, "credential stamp",
	); err != nil {
		return err
	}
	stamp := CredentialStamp(wire)
	allowed := []string(nil)
	switch stamp.Status {
	case CredentialStampPending:
	case CredentialStampSucceeded:
		allowed = []string{"result"}
	case CredentialStampFailed:
		allowed = []string{"failure"}
	case CredentialStampSuperseded:
		allowed = []string{"result", "supersededBy"}
	default:
		return fmt.Errorf("pki: unsupported credential stamp status %q", stamp.Status)
	}
	if err := rejectDisallowedVariantJSONFields(
		data, allowed, []string{"result", "failure", "supersededBy"},
		"credential stamp",
	); err != nil {
		return err
	}
	if err := stamp.Validate(); err != nil {
		return err
	}
	*s = stamp.Clone()
	return nil
}

func NewCredentialStamp(args CredentialStampArgs) (CredentialStamp, error) {
	stamp := CredentialStamp{
		SchemaVersion: args.SchemaVersion, ID: args.ID,
		ProviderID: args.ProviderID, ProviderVersion: args.ProviderVersion,
		Plan: args.Plan.Clone(), Links: append([]CredentialStampLink(nil), args.Links...),
		Status: CredentialStampPending, Revision: 1,
		CreatedAt: args.CreatedAt.UTC(), UpdatedAt: args.CreatedAt.UTC(),
	}
	if err := stamp.Validate(); err != nil {
		return CredentialStamp{}, err
	}
	return stamp.Clone(), nil
}

func (s CredentialStamp) Clone() CredentialStamp {
	result := s
	result.Plan = s.Plan.Clone()
	result.Links = append([]CredentialStampLink(nil), s.Links...)
	if s.Result != nil {
		value := s.Result.Clone()
		result.Result = &value
	}
	return result
}

func (s CredentialStamp) Validate() error {
	if s.SchemaVersion != CredentialStampSchemaV1 {
		return fmt.Errorf("pki: unsupported credential stamp schema %q", s.SchemaVersion)
	}
	if err := s.ID.Validate(); err != nil {
		return err
	}
	if err := s.ProviderID.Validate(); err != nil {
		return err
	}
	if err := validateProviderSchemaVersion(s.ProviderVersion, "delivery provider"); err != nil {
		return err
	}
	if err := s.Plan.Validate(); err != nil {
		return err
	}
	if err := validateCredentialStampLinks(s.Links); err != nil {
		return err
	}
	if err := s.Status.Validate(); err != nil {
		return err
	}
	if err := validateSequenceNumber(s.Revision, "credential stamp revision"); err != nil {
		return err
	}
	if !validCredentialBookkeepingTimestamp(s.CreatedAt) ||
		!validCredentialBookkeepingTimestamp(s.UpdatedAt) ||
		s.UpdatedAt.Before(s.CreatedAt) {
		return errors.New("pki: credential stamp timestamps are invalid or noncanonical")
	}
	switch s.Status {
	case CredentialStampPending:
		if s.Result != nil || s.Failure != "" || s.SupersededBy != "" {
			return errors.New("pki: pending credential stamp contains terminal state")
		}
	case CredentialStampSucceeded:
		if s.Result == nil || s.Failure != "" || s.SupersededBy != "" {
			return errors.New("pki: succeeded credential stamp state is invalid")
		}
		if err := s.Result.Validate(s.Plan); err != nil {
			return err
		}
	case CredentialStampFailed:
		failure, err := validateName(s.Failure, "credential stamp failure")
		if err != nil || failure != s.Failure || s.Result != nil || s.SupersededBy != "" {
			return errors.New("pki: failed credential stamp state is invalid")
		}
	case CredentialStampSuperseded:
		if s.Result == nil || s.Failure != "" || s.SupersededBy.Validate() != nil ||
			s.SupersededBy == s.ID {
			return errors.New("pki: superseded credential stamp state is invalid")
		}
		if err := s.Result.Validate(s.Plan); err != nil {
			return err
		}
	}
	return nil
}

func validCredentialBookkeepingTimestamp(value time.Time) bool {
	const maximumJSONYear = 9999
	return !value.IsZero() && value.Location() == time.UTC &&
		value.Year() >= 0 && value.Year() <= maximumJSONYear
}

func CompleteCredentialStamp(
	stamp CredentialStamp,
	result CredentialStampResult,
	updatedAt time.Time,
) (CredentialStamp, error) {
	if err := stamp.Validate(); err != nil {
		return CredentialStamp{}, err
	}
	if stamp.Status != CredentialStampPending {
		return CredentialStamp{}, errors.New("pki: only a pending credential stamp can succeed")
	}
	next, err := nextCredentialStampRevision(stamp, updatedAt)
	if err != nil {
		return CredentialStamp{}, err
	}
	validatedResult := result.Clone()
	if err := validatedResult.Validate(stamp.Plan); err != nil {
		return CredentialStamp{}, err
	}
	next.Status = CredentialStampSucceeded
	next.Result = &validatedResult
	if err := next.Validate(); err != nil {
		return CredentialStamp{}, err
	}
	return next.Clone(), nil
}

func FailCredentialStamp(
	stamp CredentialStamp,
	failure string,
	updatedAt time.Time,
) (CredentialStamp, error) {
	if err := stamp.Validate(); err != nil {
		return CredentialStamp{}, err
	}
	if stamp.Status != CredentialStampPending {
		return CredentialStamp{}, errors.New("pki: only a pending credential stamp can fail")
	}
	next, err := nextCredentialStampRevision(stamp, updatedAt)
	if err != nil {
		return CredentialStamp{}, err
	}
	next.Status = CredentialStampFailed
	next.Failure = strings.TrimSpace(failure)
	if err := next.Validate(); err != nil {
		return CredentialStamp{}, err
	}
	return next.Clone(), nil
}

func SupersedeCredentialStamp(
	stamp CredentialStamp,
	supersededBy StampID,
	updatedAt time.Time,
) (CredentialStamp, error) {
	if err := stamp.Validate(); err != nil {
		return CredentialStamp{}, err
	}
	if stamp.Status != CredentialStampSucceeded {
		return CredentialStamp{}, errors.New("pki: only a succeeded credential stamp can be superseded")
	}
	next, err := nextCredentialStampRevision(stamp, updatedAt)
	if err != nil {
		return CredentialStamp{}, err
	}
	next.Status = CredentialStampSuperseded
	next.SupersededBy = supersededBy
	if err := next.Validate(); err != nil {
		return CredentialStamp{}, err
	}
	return next.Clone(), nil
}

func ValidateCredentialStampTransition(previous, next CredentialStamp) error {
	if err := previous.Validate(); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	var expected CredentialStamp
	var err error
	switch next.Status {
	case CredentialStampSucceeded:
		if next.Result == nil {
			return errors.New("pki: credential stamp success transition is missing a result")
		}
		expected, err = CompleteCredentialStamp(previous, *next.Result, next.UpdatedAt)
	case CredentialStampFailed:
		expected, err = FailCredentialStamp(previous, next.Failure, next.UpdatedAt)
	case CredentialStampSuperseded:
		expected, err = SupersedeCredentialStamp(previous, next.SupersededBy, next.UpdatedAt)
	default:
		return errors.New("pki: credential stamp transition does not enter a terminal state")
	}
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, next) {
		return errors.New("pki: credential stamp transition changes immutable or derived state")
	}
	return nil
}

func ValidateCredentialStampReplacement(
	previous CredentialStamp,
	replacement CredentialStamp,
	superseded CredentialStamp,
) error {
	if err := previous.Validate(); err != nil {
		return err
	}
	if err := replacement.Validate(); err != nil {
		return err
	}
	if err := superseded.Validate(); err != nil {
		return err
	}
	if err := ValidateCredentialStampTransition(previous, superseded); err != nil {
		return err
	}
	if superseded.Status != CredentialStampSuperseded ||
		superseded.SupersededBy != replacement.ID ||
		replacement.UpdatedAt.After(superseded.UpdatedAt) {
		return errors.New("pki: credential stamp replacement chronology is invalid")
	}
	if replacement.Status != CredentialStampSucceeded || replacement.ID == previous.ID {
		return errors.New("pki: credential stamp replacement must be a distinct succeeded stamp")
	}
	left := previous.Plan.Request
	right := replacement.Plan.Request
	if left.AssignmentID != right.AssignmentID || previous.ProviderID != replacement.ProviderID ||
		left.Capability != right.Capability || left.SlotName != right.SlotName ||
		!reflect.DeepEqual(left.Target, right.Target) ||
		left.Credential.Purpose != right.Credential.Purpose ||
		left.Credential.ConsumerType != right.Credential.ConsumerType ||
		replacement.CreatedAt.Before(previous.CreatedAt) {
		return errors.New("pki: credential stamp replacement does not share compatible lineage")
	}
	if left.Target.Kind != StampTargetNamedSlot &&
		(previous.Result.TargetResolution != replacement.Result.TargetResolution ||
			!reflect.DeepEqual(previous.Result.ResolvedTarget, replacement.Result.ResolvedTarget)) {
		return errors.New("pki: credential stamp replacement resolves a different target")
	}
	return nil
}

func ValidateCredentialStampAssignment(
	assignment Assignment,
	request CredentialStampRequest,
) error {
	if err := assignment.Validate(); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	if assignment.ID != request.AssignmentID ||
		assignment.Purpose != request.Credential.Purpose ||
		assignment.ConsumerType != request.Credential.ConsumerType ||
		assignment.ProfileID != request.Credential.ProfileID {
		return errors.New("pki: credential stamp request does not match its assignment")
	}
	if err := validateCredentialAssignmentUsable(assignment, "credential stamp"); err != nil {
		return err
	}
	return validateCredentialStampMaterialLineage(assignment, request.Material)
}

func validateCredentialStampMaterialLineage(
	assignment Assignment,
	material StampMaterial,
) error {
	var reference CredentialMaterialReference
	switch material.Projection {
	case CredentialProjectionProviderEncoding:
		reference = material.ProviderEncoding.Source
	case CredentialProjectionBundle, CredentialProjectionCertificateDER,
		CredentialProjectionPrivateKeyPKCS8, CredentialProjectionPublicKeySPKI,
		CredentialProjectionSignerReference, CredentialProjectionChainDER,
		CredentialProjectionTrustDER, CredentialProjectionCRLDER:
		reference = *material.Credential
	case CredentialProjectionLiteralReference:
		return errors.New("pki: literal stamp material has no credential assignment lineage")
	default:
		return fmt.Errorf("pki: unsupported credential stamp material projection %q", material.Projection)
	}

	switch reference.Projection {
	case CredentialProjectionCertificateDER, CredentialProjectionPrivateKeyPKCS8,
		CredentialProjectionPublicKeySPKI, CredentialProjectionSignerReference:
		if reference.GenerationID != assignment.ActiveGenerationID &&
			reference.GenerationID != assignment.StagedGenerationID {
			return errors.New("pki: credential stamp certificate generation is outside its assignment lineage")
		}
		return nil
	case CredentialProjectionTrustDER:
		if reference.TrustSetGenerationID != assignment.ActiveTrustGenerationID &&
			reference.TrustSetGenerationID != assignment.StagedTrustGenerationID {
			return errors.New("pki: credential stamp trust generation is outside its assignment lineage")
		}
		return nil
	case CredentialProjectionBundle:
		return errors.New("pki: bundle stamp material does not expose verifiable assignment lineage")
	case CredentialProjectionChainDER:
		return errors.New("pki: chain stamp material does not expose its leaf assignment generation")
	case CredentialProjectionCRLDER:
		return errors.New("pki: crl stamp material does not expose its trust generation lineage")
	case CredentialProjectionProviderEncoding, CredentialProjectionLiteralReference:
		return errors.New("pki: nested stamp material reference has an invalid projection")
	default:
		return fmt.Errorf("pki: unsupported credential stamp material reference projection %q", reference.Projection)
	}
}

func nextCredentialStampRevision(stamp CredentialStamp, updatedAt time.Time) (CredentialStamp, error) {
	if stamp.Revision == MaximumSequenceNumber {
		return CredentialStamp{}, errors.New("pki: credential stamp revision is exhausted")
	}
	updatedAt = updatedAt.UTC()
	if updatedAt.Before(stamp.UpdatedAt) {
		return CredentialStamp{}, errors.New("pki: credential stamp update precedes the current state")
	}
	next := stamp.Clone()
	next.Revision++
	next.UpdatedAt = updatedAt
	return next, nil
}

func validateCredentialStampLinks(links []CredentialStampLink) error {
	if len(links) > MaximumCredentialStampLinks {
		return errors.New("pki: credential stamp links exceed limits")
	}
	seen := make(map[string]struct{}, len(links))
	for _, link := range links {
		if err := link.Validate(); err != nil {
			return err
		}
		key := string(link.Kind) + "\x00" + string(link.Reference)
		if _, duplicate := seen[key]; duplicate {
			return errors.New("pki: credential stamp links contain a duplicate")
		}
		seen[key] = struct{}{}
	}
	return nil
}

type stampedMaterialReference struct {
	Projection CredentialProjection
	Reference  StampReferenceID
}

func requiredMaterialDigestReferences(material StampMaterial) []stampedMaterialReference {
	if material.Projection == CredentialProjectionLiteralReference {
		return []stampedMaterialReference{{
			Projection: CredentialProjectionLiteralReference,
			Reference:  material.LiteralReference.Reference,
		}}
	}
	reference := material.Credential
	if material.Projection == CredentialProjectionProviderEncoding {
		reference = &material.ProviderEncoding.Source
	}
	if reference == nil {
		return nil
	}
	projection := reference.Projection
	switch projection {
	case CredentialProjectionBundle:
		return []stampedMaterialReference{{Projection: projection, Reference: StampReferenceID(reference.BundleID)}}
	case CredentialProjectionCertificateDER, CredentialProjectionPrivateKeyPKCS8,
		CredentialProjectionPublicKeySPKI, CredentialProjectionSignerReference:
		return []stampedMaterialReference{{Projection: projection, Reference: StampReferenceID(reference.GenerationID)}}
	case CredentialProjectionChainDER:
		result := make([]stampedMaterialReference, len(reference.GenerationIDs))
		for i, id := range reference.GenerationIDs {
			result[i] = stampedMaterialReference{Projection: projection, Reference: StampReferenceID(id)}
		}
		return result
	case CredentialProjectionTrustDER:
		return []stampedMaterialReference{{Projection: projection, Reference: StampReferenceID(reference.TrustSetGenerationID)}}
	case CredentialProjectionCRLDER:
		result := make([]stampedMaterialReference, len(reference.CRLGenerationIDs))
		for i, id := range reference.CRLGenerationIDs {
			result[i] = stampedMaterialReference{Projection: projection, Reference: StampReferenceID(id)}
		}
		return result
	}
	return nil
}

func stampedMaterialKey(projection CredentialProjection, reference StampReferenceID) string {
	return string(projection) + "\x00" + string(reference)
}

func validateTargetResolution(
	requested StampTarget,
	resolved StampTarget,
	resolution StampTargetResolution,
) error {
	switch resolution {
	case StampTargetResolutionUnchanged:
		if !reflect.DeepEqual(requested, resolved) {
			return errors.New("pki: unchanged stamp target resolution differs from its request")
		}
	case StampTargetResolutionTranslated:
		if requested.Kind == StampTargetFileOffset {
			return errors.New("pki: file-offset stamp target cannot be translated")
		}
		if resolved.Kind != StampTargetFileOffset &&
			resolved.Kind != StampTargetVirtualAddress &&
			resolved.Kind != StampTargetProviderDefined {
			return errors.New("pki: translated stamp target has no concrete resolved location")
		}
	}
	return nil
}

func validateCanonicalSHA256(value, label string) error {
	normalized, err := normalizeSHA256Fingerprint(value, label)
	if err != nil || normalized != value {
		return fmt.Errorf("pki: %s sha256 is invalid or noncanonical", label)
	}
	return nil
}
